//! Iced application: state, update, view, subscription.

use std::collections::VecDeque;

use iced::widget::{button, column, container, row, scrollable, text};
use iced::{Element, Length, Subscription, Task};
use sluice_common::ipc::{Event, Request, RuleSummary};

use crate::ipc_client::ClientMessage;
use crate::subscription::{ipc_subscription, send_request};

const MAX_EVENTS: usize = 500;

#[derive(Default)]
pub struct SluiceApp {
    status: ConnectionStatus,
    rules: Vec<RuleSummary>,
    default_policy: String,
    events: VecDeque<Event>,
    pending_prompts: VecDeque<PendingPrompt>,
}

#[derive(Clone)]
struct PendingPrompt {
    pid: u32,
    exe: Option<String>,
    family: String,
    addr: String,
    dport: u16,
    protocol: String,
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
    Allow(u32),
    Deny(u32),
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
                self.absorb_event(event);
            }
            Message::Ipc(ClientMessage::Disconnected { reason }) => {
                self.status = ConnectionStatus::Disconnected { reason };
            }
            Message::Allow(pid) => self.dispatch_verdict(pid, "allow"),
            Message::Deny(pid) => self.dispatch_verdict(pid, "deny"),
        }
        Task::none()
    }

    fn absorb_event(&mut self, event: Event) {
        match &event {
            Event::Connection { .. } => {}
            Event::Prompt {
                pid,
                exe,
                family,
                addr,
                dport,
                protocol,
                ..
            } => {
                if !self.pending_prompts.iter().any(|p| p.pid == *pid) {
                    self.pending_prompts.push_back(PendingPrompt {
                        pid: *pid,
                        exe: exe.clone(),
                        family: family.clone(),
                        addr: addr.clone(),
                        dport: *dport,
                        protocol: protocol.clone(),
                    });
                }
            }
            // Phase 8 task 72 wires rules + policy refresh in.
            Event::RulesChanged { .. } => {}
        }
        if self.events.len() == MAX_EVENTS {
            self.events.pop_back();
        }
        self.events.push_front(event);
    }

    fn dispatch_verdict(&mut self, pid: u32, verdict: &str) {
        self.pending_prompts.retain(|p| p.pid != pid);
        send_request(Request::SetVerdict {
            pid,
            verdict: verdict.to_string(),
        });
    }

    pub fn view(&self) -> Element<'_, Message> {
        column![self.header(), self.prompts_view(), self.events_view()]
            .spacing(12)
            .padding(16)
            .into()
    }

    fn prompts_view(&self) -> Element<'_, Message> {
        if self.pending_prompts.is_empty() {
            return column![].into();
        }
        let header = text(format!("Pending prompts ({})", self.pending_prompts.len())).size(16);

        let rows = self
            .pending_prompts
            .iter()
            .map(prompt_row)
            .collect::<Vec<_>>();
        column![header, column(rows).spacing(6)].spacing(8).into()
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

fn prompt_row(p: &PendingPrompt) -> Element<'_, Message> {
    let label = p.exe.clone().unwrap_or_else(|| "(no exe)".to_string());
    let dst = if p.family == "ipv6" {
        format!("[{}]:{}", p.addr, p.dport)
    } else {
        format!("{}:{}", p.addr, p.dport)
    };
    let summary = text(format!(
        "{label} pid={pid} -> {dst} ({proto})",
        pid = p.pid,
        proto = p.protocol,
    ))
    .size(13);
    let allow = button("Allow").on_press(Message::Allow(p.pid));
    let deny = button("Deny").on_press(Message::Deny(p.pid));
    container(
        row![summary, allow, deny]
            .spacing(8)
            .align_y(iced::Alignment::Center),
    )
    .padding(6)
    .width(Length::Fill)
    .into()
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
        Event::RulesChanged { rules, .. } => {
            format!("rules changed (now {})", rules.len())
        }
    };
    container(text(line).size(13))
        .padding([2, 0])
        .width(Length::Fill)
        .into()
}
