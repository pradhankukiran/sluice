//! Async reader for the `EVENTS` BPF ring buffer.
//!
//! Aya's `RingBuf` is a non-blocking interface: `.next()` returns the next
//! buffered record or `None` if empty. To wait for new records without
//! busy-spinning we wrap the ring buffer's file descriptor in
//! [`tokio::io::unix::AsyncFd`].

use std::mem::size_of;
use std::ptr::read_unaligned;

use anyhow::{anyhow, Context, Result};
use aya::maps::ring_buf::RingBuf;
use aya::maps::MapData;
use aya::Ebpf;
use sluice_common::event::ConnectEvent;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

const MAP_NAME: &str = "EVENTS";

pub struct EventReader {
    inner: AsyncFd<RingBuf<MapData>>,
}

impl EventReader {
    pub fn from_ebpf(bpf: &mut Ebpf) -> Result<Self> {
        let map = bpf
            .take_map(MAP_NAME)
            .ok_or_else(|| anyhow!("eBPF object missing map `{MAP_NAME}`"))?;
        let ringbuf: RingBuf<MapData> = RingBuf::try_from(map)
            .with_context(|| format!("converting map `{MAP_NAME}` to RingBuf"))?;
        let inner = AsyncFd::with_interest(ringbuf, Interest::READABLE)
            .context("registering RingBuf fd with tokio")?;
        Ok(Self { inner })
    }

    /// Run the reader until the inner fd reports an unrecoverable error.
    /// `on_event` is called synchronously for each `ConnectEvent`.
    pub async fn run<F: FnMut(&ConnectEvent)>(&mut self, mut on_event: F) -> Result<()> {
        loop {
            let mut guard = self.inner.readable_mut().await?;
            let ringbuf = guard.get_inner_mut();
            while let Some(item) = ringbuf.next() {
                let bytes: &[u8] = &item;
                if let Some(event) = decode(bytes) {
                    on_event(&event);
                }
            }
            guard.clear_ready();
        }
    }
}

fn decode(bytes: &[u8]) -> Option<ConnectEvent> {
    if bytes.len() < size_of::<ConnectEvent>() {
        tracing::warn!(
            len = bytes.len(),
            expected = size_of::<ConnectEvent>(),
            "short ring buffer event — discarding",
        );
        return None;
    }
    // SAFETY: `ConnectEvent` is `#[repr(C)]` with explicit padding (compile-time
    // size-pinned in `sluice-common`). The eBPF program writes exactly
    // `size_of::<ConnectEvent>()` bytes via `RingBuf::output`. We use an
    // unaligned read because the ring buffer item slice is not guaranteed to
    // satisfy `ConnectEvent`'s alignment.
    let event = unsafe { read_unaligned(bytes.as_ptr() as *const ConnectEvent) };
    Some(event)
}
