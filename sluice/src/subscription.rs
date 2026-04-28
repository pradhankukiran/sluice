//! Bridges the IPC client (which uses `tokio::sync::mpsc`) into iced's
//! `futures::channel::mpsc`-flavoured `Subscription`.

use futures::stream::Stream;
use sluice_common::ipc::resolve_socket_path;
use tokio::sync::mpsc;

use crate::app::Message;
use crate::ipc_client::{self, ClientMessage};

const BUFFER: usize = 64;

/// Top-level function the iced subscription registers. Must be a `fn`
/// pointer (not a closure), so we read configuration via env each time
/// rather than capturing it.
pub fn ipc_subscription() -> impl Stream<Item = Message> {
    iced::stream::channel(BUFFER, |mut output| async move {
        let socket_path = resolve_socket_path();
        let (tx, mut rx) = mpsc::channel::<ClientMessage>(BUFFER);

        let client = ipc_client::connect_and_run(&socket_path, tx);
        let bridge = async {
            while let Some(msg) = rx.recv().await {
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
