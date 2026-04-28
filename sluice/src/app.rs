//! Iced application: state, update, view, subscription.

use std::collections::VecDeque;

use iced::widget::{button, column, container, row, scrollable, text, text_input};
use iced::{Element, Length, Subscription, Task};
use sluice_common::ipc::{Event, RateEntry, Request, RuleSummary};

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
    tab: Tab,
    form: RuleForm,
    rates: Vec<RateEntry>,
    rate_form: RateForm,
}

// Form fields wired into the Bandwidth view in the next commit.
#[allow(dead_code)]
#[derive(Default)]
struct RateForm {
    pid: String,
    rate_kbps: String,
}

#[derive(Default)]
struct RuleForm {
    exe: String,
    host: String,
    port: String,
    protocol: String,
    verdict: String,
}

impl RuleForm {
    fn fresh() -> Self {
        Self {
            exe: "any".to_string(),
            host: "any".to_string(),
            port: "any".to_string(),
            protocol: "any".to_string(),
            verdict: "deny".to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum FormField {
    Exe,
    Host,
    Port,
    Protocol,
    Verdict,
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    #[default]
    Events,
    Rules,
    Policy,
    Bandwidth,
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
    SelectTab(Tab),
    FormFieldChanged(FormField, String),
    AddRuleClicked,
    DeleteRule(i64),
    SetPolicy(String),
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
            Message::SelectTab(tab) => {
                self.tab = tab;
                if matches!(tab, Tab::Rules) && self.form.exe.is_empty() {
                    self.form = RuleForm::fresh();
                }
            }
            Message::FormFieldChanged(field, value) => match field {
                FormField::Exe => self.form.exe = value,
                FormField::Host => self.form.host = value,
                FormField::Port => self.form.port = value,
                FormField::Protocol => self.form.protocol = value,
                FormField::Verdict => self.form.verdict = value,
            },
            Message::AddRuleClicked => {
                send_request(Request::AddRule {
                    exe: self.form.exe.clone(),
                    host: self.form.host.clone(),
                    port: self.form.port.clone(),
                    protocol: self.form.protocol.clone(),
                    verdict: self.form.verdict.clone(),
                });
                self.form = RuleForm::fresh();
            }
            Message::DeleteRule(id) => {
                send_request(Request::DeleteRule { id });
            }
            Message::SetPolicy(policy) => {
                send_request(Request::SetPolicy { policy });
            }
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
            Event::RulesChanged {
                rules,
                default_policy,
            } => {
                self.rules = rules.clone();
                self.default_policy = default_policy.clone();
            }
            Event::RatesChanged { entries } => {
                self.rates = entries.clone();
            }
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
        let tab_view: Element<'_, Message> = match self.tab {
            Tab::Events => self.events_view(),
            Tab::Rules => self.rules_view(),
            Tab::Policy => self.policy_view(),
            Tab::Bandwidth => self.bandwidth_view(),
        };
        column![self.header(), self.tab_bar(), self.prompts_view(), tab_view]
            .spacing(12)
            .padding(16)
            .into()
    }

    fn tab_bar(&self) -> Element<'_, Message> {
        let make = |label: &str, tab: Tab| -> Element<'_, Message> {
            let mut b = button(text(label.to_string())).on_press(Message::SelectTab(tab));
            if self.tab == tab {
                // Mark the active tab visually with a wider button.
                // iced 0.13 doesn't expose a clean "selected" style on
                // the basic Button, so we lean on width as the hint.
                b = b.width(Length::Fixed(110.0));
            }
            b.into()
        };
        row![
            make("Events", Tab::Events),
            make("Rules", Tab::Rules),
            make("Policy", Tab::Policy),
            make("Bandwidth", Tab::Bandwidth),
        ]
        .spacing(6)
        .into()
    }

    fn rules_view(&self) -> Element<'_, Message> {
        let header = text(format!("Rules ({})", self.rules.len())).size(16);

        let list: Element<'_, Message> = if self.rules.is_empty() {
            text("(no rules — add one below)").size(13).into()
        } else {
            let rows = self.rules.iter().map(rule_row).collect::<Vec<_>>();
            scrollable(column(rows).spacing(4))
                .height(Length::Fixed(200.0))
                .into()
        };

        let form_label = text("Add rule").size(15);
        let form = column![
            field_row("exe", &self.form.exe, FormField::Exe),
            field_row("host", &self.form.host, FormField::Host),
            field_row("port", &self.form.port, FormField::Port),
            field_row("protocol", &self.form.protocol, FormField::Protocol),
            field_row("verdict", &self.form.verdict, FormField::Verdict),
            button("Add rule").on_press(Message::AddRuleClicked),
        ]
        .spacing(6);

        column![header, list, form_label, form].spacing(10).into()
    }

    fn bandwidth_view(&self) -> Element<'_, Message> {
        // Real implementation arrives in the next commit (task 93).
        text(format!("Rate limits ({})", self.rates.len()))
            .size(14)
            .into()
    }

    fn policy_view(&self) -> Element<'_, Message> {
        let current = if self.default_policy.is_empty() {
            "?".to_string()
        } else {
            self.default_policy.clone()
        };
        let header = text(format!("Default policy: {current}")).size(15);

        let make_btn = |name: &'static str, value: &'static str| -> Element<'_, Message> {
            let mut b = button(text(name)).on_press(Message::SetPolicy(value.to_string()));
            if self.default_policy == value {
                b = b.width(Length::Fixed(110.0));
            }
            b.into()
        };

        let buttons = row![
            make_btn("Allow", "allow"),
            make_btn("Deny", "deny"),
            make_btn("Ask", "ask"),
        ]
        .spacing(8);

        let help = text(
            "Allow = pass through · Deny = block all · \
             Ask = prompt unrecognized processes",
        )
        .size(12);

        column![header, buttons, help].spacing(8).into()
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

fn rule_row(r: &RuleSummary) -> Element<'_, Message> {
    let summary = text(format!(
        "[{:>4}] {} exe={} host={} port={} proto={}",
        r.id, r.verdict, r.exe, r.host, r.port, r.protocol,
    ))
    .size(13);
    let delete = button(text("Delete").size(12)).on_press(Message::DeleteRule(r.id));
    container(
        row![summary, delete]
            .spacing(8)
            .align_y(iced::Alignment::Center),
    )
    .padding(4)
    .width(Length::Fill)
    .into()
}

fn field_row<'a>(label: &'a str, value: &str, field: FormField) -> Element<'a, Message> {
    let input = text_input("any", value)
        .on_input(move |v| Message::FormFieldChanged(field, v))
        .padding(4)
        .width(Length::Fixed(220.0));
    row![text(label).size(13).width(Length::Fixed(80.0)), input]
        .spacing(6)
        .align_y(iced::Alignment::Center)
        .into()
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
        Event::RatesChanged { entries } => {
            format!("rates changed (now {})", entries.len())
        }
    };
    container(text(line).size(13))
        .padding([2, 0])
        .width(Length::Fill)
        .into()
}
