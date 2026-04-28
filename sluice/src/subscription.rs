//! Bridges the IPC client (which uses `tokio::sync::mpsc`) into iced's
//! `futures::channel::mpsc`-flavoured `Subscription`, and exposes the
//! request side as a process-global channel so the iced `update`
//! function can post requests synchronously from any handler.

use std::sync::OnceLock;

use futures::stream::Stream;
use sluice_common::ipc::{resolve_socket_path, Request};
use tokio::sync::mpsc;

use crate::app::Message;
use crate::ipc_client::{self, ClientMessage};

const BUFFER: usize = 64;

/// Holds the [`UnboundedSender`] the subscription installs on first
/// run. The iced `update` function calls [`send_request`] to post
/// requests; the IPC client drains the receiver in its session loop.
static REQUEST_CHANNEL: OnceLock<mpsc::UnboundedSender<Request>> = OnceLock::new();

/// Send a request to the daemon. Drops silently when the IPC
/// subscription hasn't been started yet (during the first 1–2 frames
/// after launch) or when the underlying channel has been closed.
pub fn send_request(req: Request) {
    if let Some(tx) = REQUEST_CHANNEL.get() {
        let _ = tx.send(req);
    }
}

/// Top-level function the iced subscription registers. Must be a `fn`
/// pointer (not a closure), so we read configuration via env each time
/// rather than capturing it.
pub fn ipc_subscription() -> impl Stream<Item = Message> {
    iced::stream::channel(BUFFER, |mut output| async move {
        let socket_path = resolve_socket_path();
        let (msg_tx, mut msg_rx) = mpsc::channel::<ClientMessage>(BUFFER);
        let (req_tx, req_rx) = mpsc::unbounded_channel::<Request>();
        // First subscription wins; subsequent installs are ignored —
        // iced may restart the stream after a panic but we only ever
        // intend a single client.
        let _ = REQUEST_CHANNEL.set(req_tx);

        let client = ipc_client::connect_and_run(&socket_path, msg_tx, req_rx);
        let bridge = async {
            while let Some(msg) = msg_rx.recv().await {
                use futures::SinkExt;
                if output.send(Message::Ipc(msg)).await.is_err() {
                    break;
                }
            }
        };

        // Both run forever on the happy path; we wait on both so the
        // task completes only when iced drops the subscription.
        let _ = futures::future::join(client, bridge).await;
    })
}
