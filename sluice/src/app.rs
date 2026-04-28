//! Iced application: state, update, view, subscription.

use std::collections::VecDeque;

use iced::widget::{column, container, scrollable, text};
use iced::{Element, Length, Subscription, Task};
use sluice_common::ipc::{Event, RuleSummary};

use crate::ipc_client::ClientMessage;
use crate::subscription::ipc_subscription;

const MAX_EVENTS: usize = 500;

#[derive(Default)]
pub struct SluiceApp {
    status: ConnectionStatus,
    rules: Vec<RuleSummary>,
    default_policy: String,
    events: VecDeque<Event>,
}

#[derive(Default, Debug, Clone)]
pub enum ConnectionStatus {
    #[default]
    NotConnected,
    Connecting,
    Connected {
        server_version: String,
    },
    Disconnected {
        reason: String,
    },
}

#[derive(Debug, Clone)]
pub enum Message {
    Ipc(ClientMessage),
}

impl SluiceApp {
    pub fn title(&self) -> String {
        "Sluice".to_string()
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Ipc(ClientMessage::Connecting) => {
                self.status = ConnectionStatus::Connecting;
            }
            Message::Ipc(ClientMessage::Connected { server_version }) => {
                self.status = ConnectionStatus::Connected { server_version };
            }
            Message::Ipc(ClientMessage::Snapshot {
                rules,
                default_policy,
            }) => {
                self.rules = rules;
                self.default_policy = default_policy;
            }
            Message::Ipc(ClientMessage::Event(event)) => {
                if self.events.len() == MAX_EVENTS {
                    self.events.pop_back();
                }
                self.events.push_front(event);
            }
            Message::Ipc(ClientMessage::Disconnected { reason }) => {
                self.status = ConnectionStatus::Disconnected { reason };
            }
        }
        Task::none()
    }

    pub fn view(&self) -> Element<'_, Message> {
        column![self.header(), self.events_view()]
            .spacing(12)
            .padding(16)
            .into()
    }

    pub fn subscription(&self) -> Subscription<Message> {
        Subscription::run(ipc_subscription)
    }

    fn header(&self) -> Element<'_, Message> {
        let status_line = match &self.status {
            ConnectionStatus::NotConnected => text("not connected").size(14),
            ConnectionStatus::Connecting => text("connecting…").size(14),
            ConnectionStatus::Connected { server_version } => {
                text(format!("connected — sluiced {server_version}")).size(14)
            }
            ConnectionStatus::Disconnected { reason } => {
                text(format!("disconnected: {reason}")).size(14)
            }
        };

        let policy_line = text(format!(
            "default policy: {}    rules: {}",
            if self.default_policy.is_empty() {
                "?"
            } else {
                self.default_policy.as_str()
            },
            self.rules.len(),
        ))
        .size(14);

        column![text("Sluice").size(24), status_line, policy_line]
            .spacing(4)
            .into()
    }

    fn events_view(&self) -> Element<'_, Message> {
        let header = text(format!("Live connections ({})", self.events.len())).size(16);

        let rows = self.events.iter().map(event_row).collect::<Vec<_>>();

        let body: Element<'_, Message> = if rows.is_empty() {
            text("waiting for events…").size(14).into()
        } else {
            scrollable(column(rows).spacing(4))
                .height(Length::Fill)
                .into()
        };

        column![header, body].spacing(8).into()
    }
}

fn event_row(evt: &Event) -> Element<'_, Message> {
    let line = match evt {
        Event::Connection {
            pid,
            exe,
            family,
            protocol,
            addr,
            dport,
            verdict,
            ..
        } => {
            let label = exe.clone().unwrap_or_else(|| "(no exe)".to_string());
            let dst = if family == "ipv6" {
                format!("[{addr}]:{dport}")
            } else {
                format!("{addr}:{dport}")
            };
            format!("{verdict:>5} {label} pid={pid} -> {dst} ({protocol})")
        }
        // Prompts get their own panel; if one slips into the events
        // list (shouldn't happen) render a placeholder rather than
        // panicking.
        Event::Prompt { pid, exe, .. } => {
            let label = exe.clone().unwrap_or_else(|| "(no exe)".to_string());
            format!("prompt pid={pid} {label}")
        }
    };
    container(text(line).size(13))
        .padding([2, 0])
        .width(Length::Fill)
        .into()
}
