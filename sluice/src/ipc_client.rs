// `connect_and_run` is consumed by the iced subscription in the next
// commit; until then the wiring would otherwise warn dead.
#![allow(dead_code)]

//! Minimal IPC client for the Sluice GUI.
//!
//! Streams [`ClientMessage`]s into the iced UI: connection state
//! transitions, the initial snapshot, then a continuous flow of
//! [`Event`]s after the daemon accepts our `SubscribeEvents` request.

use std::path::Path;

use anyhow::{anyhow, Context, Result};
use sluice_common::ipc::{Event, Frame, Request, Response, RuleSummary};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::mpsc;

/// Messages the client emits into the GUI runtime.
#[derive(Debug, Clone)]
pub enum ClientMessage {
    Connecting,
    Connected {
        server_version: String,
    },
    Snapshot {
        rules: Vec<RuleSummary>,
        default_policy: String,
    },
    Event(Event),
    Disconnected {
        reason: String,
    },
}

/// Run a connect/handshake/subscribe loop until the receiver is dropped.
/// Reconnects automatically on disconnect with a fixed backoff.
pub async fn connect_and_run(socket_path: &Path, output: mpsc::Sender<ClientMessage>) {
    let backoff = std::time::Duration::from_secs(2);
    loop {
        if output.send(ClientMessage::Connecting).await.is_err() {
            return;
        }

        match session(socket_path, &output).await {
            Ok(()) => {
                let _ = output
                    .send(ClientMessage::Disconnected {
                        reason: "stream ended".to_string(),
                    })
                    .await;
            }
            Err(err) => {
                let _ = output
                    .send(ClientMessage::Disconnected {
                        reason: format!("{err}"),
                    })
                    .await;
            }
        }

        tokio::time::sleep(backoff).await;
    }
}

async fn session(socket_path: &Path, output: &mpsc::Sender<ClientMessage>) -> Result<()> {
    let stream = UnixStream::connect(socket_path)
        .await
        .with_context(|| format!("connecting to ipc socket {}", socket_path.display()))?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half).lines();

    // Handshake: Hello → Hello.
    send_request(&mut write_half, 1, Request::Hello).await?;
    let hello = expect_response(&mut reader, 1).await?;
    let server_version = match hello {
        Response::Hello { version } => version,
        Response::Error { message } => {
            return Err(anyhow!("server rejected Hello: {message}"));
        }
        other => return Err(anyhow!("unexpected response to Hello: {other:?}")),
    };
    send_message(output, ClientMessage::Connected { server_version }).await;

    // Snapshot.
    send_request(&mut write_half, 2, Request::Snapshot).await?;
    let snapshot = expect_response(&mut reader, 2).await?;
    let (rules, default_policy) = match snapshot {
        Response::Snapshot {
            rules,
            default_policy,
        } => (rules, default_policy),
        Response::Error { message } => {
            return Err(anyhow!("server rejected Snapshot: {message}"));
        }
        other => return Err(anyhow!("unexpected response to Snapshot: {other:?}")),
    };
    send_message(
        output,
        ClientMessage::Snapshot {
            rules,
            default_policy,
        },
    )
    .await;

    // Subscribe and forward events forever.
    send_request(&mut write_half, 3, Request::SubscribeEvents).await?;
    let subscribed = expect_response(&mut reader, 3).await?;
    match subscribed {
        Response::Subscribed => {}
        Response::Error { message } => {
            return Err(anyhow!("server rejected SubscribeEvents: {message}"));
        }
        other => return Err(anyhow!("unexpected response to SubscribeEvents: {other:?}")),
    }

    while let Some(line) = reader.next_line().await? {
        let frame: Frame =
            serde_json::from_str(&line).with_context(|| format!("malformed frame: {line}"))?;
        match frame {
            Frame::Event(event) => {
                send_message(output, ClientMessage::Event(event)).await;
            }
            // Phase 6 ignores any further responses — phase 7 will care
            // when we send verdict requests back.
            Frame::Response { .. } | Frame::Request { .. } => {}
        }
    }
    Ok(())
}

async fn send_request(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    id: u64,
    body: Request,
) -> Result<()> {
    let frame = Frame::Request { id, body };
    let mut json = serde_json::to_vec(&frame).context("encoding request")?;
    json.push(b'\n');
    writer.write_all(&json).await?;
    writer.flush().await?;
    Ok(())
}

async fn expect_response(
    reader: &mut tokio::io::Lines<BufReader<tokio::net::unix::OwnedReadHalf>>,
    expected_id: u64,
) -> Result<Response> {
    loop {
        let line = reader
            .next_line()
            .await?
            .ok_or_else(|| anyhow!("ipc socket closed before response"))?;
        let frame: Frame =
            serde_json::from_str(&line).with_context(|| format!("malformed frame: {line}"))?;
        match frame {
            Frame::Response { id, body } if id == expected_id => return Ok(body),
            Frame::Response { id, .. } => {
                tracing::warn!(
                    expected = expected_id,
                    got = id,
                    "ignoring unexpected response id"
                );
            }
            // The daemon shouldn't push events before SubscribeEvents,
            // but if it does we ignore — phase 7 may reorder.
            Frame::Event(_) | Frame::Request { .. } => {}
        }
    }
}

async fn send_message(output: &mpsc::Sender<ClientMessage>, msg: ClientMessage) {
    if output.send(msg).await.is_err() {
        // Receiver dropped — caller is shutting down. The session loop
        // will exit on the next IO error.
    }
}
