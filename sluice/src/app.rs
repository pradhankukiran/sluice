//! Iced application: state, update, view, subscription.

use std::collections::{HashMap, VecDeque};
use std::time::Instant;

use iced::widget::{button, column, container, row, scrollable, text, text_input, Space};
use iced::{Alignment, Element, Length, Subscription, Task};
use sluice_common::ipc::{Event, RateEntry, Request, RuleSummary};

use crate::icons::{icon, Icon};
use crate::ipc_client::ClientMessage;
use crate::style;
use crate::subscription::{ipc_subscription, send_request};

const MAX_EVENTS: usize = 2000;
const MAX_RECENT_PIDS: usize = 32;

#[derive(Default)]
pub struct SluiceApp {
    status: ConnectionStatus,
    rules: Vec<RuleSummary>,
    default_policy: String,
    events: VecDeque<EventEntry>,
    pending_prompts: VecDeque<PendingPrompt>,
    tab: Tab,
    form: RuleForm,
    rates: Vec<RateEntry>,
    rate_form: RateForm,
    rate_form_error: Option<String>,
    throughput: HashMap<u32, u64>,
    recent_pids: VecDeque<RecentPid>,
    /// Counters for the top status bar.
    total_events: u64,
    deny_count: u64,
}

/// Wraps an IPC `Event` with the local wall-clock time it arrived at —
/// the daemon's `bpf_ktime_get_ns` is monotonic-since-boot and not
/// directly mappable to a clock the user recognises.
#[derive(Clone)]
struct EventEntry {
    received_at: Instant,
    event: Event,
}

#[derive(Clone)]
struct RecentPid {
    pid: u32,
    label: String,
}

#[derive(Default)]
struct RateForm {
    pid: String,
    rate_kbps: String,
}

#[derive(Debug, Clone, Copy)]
pub enum RateField {
    Pid,
    RateKbps,
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
    addr: String,
    dport: u16,
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
    RateFieldChanged(RateField, String),
    AddRate,
    ClearRate(u32),
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
            Message::RateFieldChanged(field, value) => match field {
                RateField::Pid => self.rate_form.pid = value,
                RateField::RateKbps => self.rate_form.rate_kbps = value,
            },
            Message::AddRate => match self.parse_rate_form() {
                Ok((pid, rate_bps)) => {
                    send_request(Request::SetRate {
                        pid,
                        rate_bps,
                        burst_bytes: rate_bps,
                    });
                    self.rate_form = RateForm::default();
                    self.rate_form_error = None;
                }
                Err(msg) => {
                    self.rate_form_error = Some(msg);
                }
            },
            Message::ClearRate(pid) => {
                send_request(Request::ClearRate { pid });
            }
        }
        Task::none()
    }

    fn absorb_event(&mut self, event: Event) {
        match &event {
            Event::Connection { pid, exe, verdict, .. } => {
                self.total_events += 1;
                if verdict == "deny" {
                    self.deny_count += 1;
                }
                let label = exe
                    .as_ref()
                    .and_then(|p| p.rsplit('/').next().map(|s| s.to_string()))
                    .unwrap_or_else(|| "(?)".to_string());
                let candidate = RecentPid { pid: *pid, label };
                self.recent_pids.retain(|r| r.pid != candidate.pid);
                self.recent_pids.push_front(candidate);
                while self.recent_pids.len() > MAX_RECENT_PIDS {
                    self.recent_pids.pop_back();
                }
            }
            Event::Prompt {
                pid,
                exe,
                addr,
                dport,
                ..
            } => {
                if !self.pending_prompts.iter().any(|p| p.pid == *pid) {
                    self.pending_prompts.push_back(PendingPrompt {
                        pid: *pid,
                        exe: exe.clone(),
                        addr: addr.clone(),
                        dport: *dport,
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
            Event::Throughput { entries } => {
                self.throughput.clear();
                for e in entries {
                    self.throughput.insert(e.pid, e.bps);
                }
            }
        }
        if matches!(event, Event::Connection { .. } | Event::Prompt { .. }) {
            if self.events.len() == MAX_EVENTS {
                self.events.pop_back();
            }
            self.events.push_front(EventEntry {
                received_at: Instant::now(),
                event,
            });
        }
    }

    fn parse_rate_form(&self) -> Result<(u32, u64), String> {
        let pid: u32 = self
            .rate_form
            .pid
            .trim()
            .parse()
            .map_err(|_| format!("invalid pid `{}`", self.rate_form.pid))?;
        let rate_kbps: u64 = self
            .rate_form
            .rate_kbps
            .trim()
            .parse()
            .map_err(|_| format!("invalid rate `{}` (KB/s)", self.rate_form.rate_kbps))?;
        Ok((pid, rate_kbps.saturating_mul(1024)))
    }

    fn dispatch_verdict(&mut self, pid: u32, verdict: &str) {
        self.pending_prompts.retain(|p| p.pid != pid);
        send_request(Request::SetVerdict {
            pid,
            verdict: verdict.to_string(),
        });
    }

    pub fn view(&self) -> Element<'_, Message> {
        let main_panel: Element<'_, Message> = match self.tab {
            Tab::Events => self.events_view(),
            Tab::Rules => self.rules_view(),
            Tab::Policy => self.policy_view(),
            Tab::Bandwidth => self.bandwidth_view(),
        };

        let body = row![self.sidebar(), main_panel].height(Length::Fill);

        let layout = column![self.statusbar(), body, self.footer()].spacing(0);

        container(layout)
            .width(Length::Fill)
            .height(Length::Fill)
            .style(style::page)
            .into()
    }

    pub fn subscription(&self) -> Subscription<Message> {
        Subscription::run(ipc_subscription)
    }

    // ---------- chrome ----------

    fn statusbar(&self) -> Element<'_, Message> {
        let dot_color = match &self.status {
            ConnectionStatus::Connected { .. } => style::SUCCESS,
            ConnectionStatus::Disconnected { .. } => style::DANGER,
            _ => style::TEXT_MUTED,
        };
        let dot = container(Space::with_width(Length::Fixed(12.0)))
            .height(Length::Fixed(12.0))
            .style(move |_| iced::widget::container::Style {
                background: Some(iced::Background::Color(dot_color)),
                border: iced::Border {
                    color: dot_color,
                    width: 0.0,
                    radius: 6.0.into(),
                },
                ..Default::default()
            });

        let conn = match &self.status {
            ConnectionStatus::Connected { server_version } => {
                format!("connected · sluiced {server_version}")
            }
            ConnectionStatus::Connecting => "connecting…".to_string(),
            ConnectionStatus::Disconnected { reason } => format!("disconnected · {reason}"),
            ConnectionStatus::NotConnected => "not connected".to_string(),
        };

        let metric =
            |label: &'static str, value: String| -> Element<'_, Message> {
                column![
                    text(label)
                        .size(style::SIZE_XS)
                        .color(style::STATUSBAR_TEXT)
                        .font(style::SEMI),
                    text(value)
                        .size(style::SIZE_LG)
                        .color(style::STATUSBAR_TEXT_BRIGHT)
                        .font(style::MONO_BOLD),
                ]
                .spacing(0)
                .align_x(Alignment::Start)
                .into()
            };

        let stats = row![
            metric("EVENTS", self.total_events.to_string()),
            metric("BUFFERED", self.events.len().to_string()),
            metric("DENY", self.deny_count.to_string()),
            metric("RULES", self.rules.len().to_string()),
            metric("LIMITS", self.rates.len().to_string()),
            metric("POLICY", self.default_policy_display().to_string()),
        ]
        .spacing(28)
        .align_y(Alignment::Center);

        container(
            row![
                icon(Icon::Logo, 28.0, style::STATUSBAR_TEXT_BRIGHT),
                text("SLUICE")
                    .size(style::SIZE_XL)
                    .color(style::STATUSBAR_TEXT_BRIGHT)
                    .font(style::BOLD),
                Space::with_width(Length::Fixed(20.0)),
                dot,
                text(conn)
                    .size(style::SIZE_SM)
                    .color(style::STATUSBAR_TEXT)
                    .font(style::SEMI),
                Space::with_width(Length::Fill),
                stats,
            ]
            .spacing(10)
            .align_y(Alignment::Center)
            .padding([14, 24]),
        )
        .width(Length::Fill)
        .style(style::statusbar)
        .into()
    }

    fn sidebar(&self) -> Element<'_, Message> {
        let nav_item = |label: &'static str,
                        ic: Icon,
                        tab: Tab,
                        count: Option<usize>|
         -> Element<'_, Message> {
            let active = self.tab == tab;
            let icon_color = if active {
                style::PRIMARY
            } else {
                style::TEXT_MUTED
            };
            let count_label: Element<'_, Message> = match count {
                Some(n) => text(n.to_string())
                    .size(style::SIZE_SM)
                    .color(style::TEXT_MUTED)
                    .font(style::MONO_BOLD)
                    .into(),
                None => Space::with_width(Length::Fixed(0.0)).into(),
            };
            let content = row![
                icon(ic, 20.0, icon_color),
                text(label)
                    .size(style::SIZE_MD)
                    .font(if active { style::BOLD } else { style::SEMI }),
                Space::with_width(Length::Fill),
                count_label,
            ]
            .align_y(Alignment::Center)
            .spacing(12);
            button(content)
                .on_press(Message::SelectTab(tab))
                .padding([14, 18])
                .width(Length::Fill)
                .style(style::sidebar_item(active))
                .into()
        };

        let nav = column![
            nav_item("Events", Icon::Events, Tab::Events, Some(self.events.len())),
            nav_item("Rules", Icon::Rules, Tab::Rules, Some(self.rules.len())),
            nav_item("Policy", Icon::Policy, Tab::Policy, None),
            nav_item(
                "Bandwidth",
                Icon::Bandwidth,
                Tab::Bandwidth,
                Some(self.rates.len())
            ),
        ]
        .spacing(4)
        .padding([12, 0]);

        let prompts_section: Element<'_, Message> = if self.pending_prompts.is_empty() {
            Space::with_height(Length::Fixed(0.0)).into()
        } else {
            let n = self.pending_prompts.len();
            let header = container(
                text(format!("{n} PENDING PROMPT{}", if n == 1 { "" } else { "S" }))
                    .size(style::SIZE_XS)
                    .color(style::TEXT_MUTED)
                    .font(style::BOLD),
            )
            .padding([10, 18]);
            let rows: Vec<Element<'_, Message>> = self
                .pending_prompts
                .iter()
                .take(4)
                .map(|p| {
                    let label = p
                        .exe
                        .as_ref()
                        .map(|s| short_basename(s))
                        .unwrap_or_else(|| format!("pid {}", p.pid));
                    column![
                        text(label)
                            .size(style::SIZE_SM)
                            .color(style::TEXT)
                            .font(style::SEMI),
                        text(format!("→ {}:{}", p.addr, p.dport))
                            .size(style::SIZE_XS)
                            .color(style::TEXT_MUTED)
                            .font(style::MONO),
                        row![
                            small_button("Allow", Message::Allow(p.pid), false),
                            small_button("Deny", Message::Deny(p.pid), true),
                        ]
                        .spacing(6),
                    ]
                    .spacing(4)
                    .padding([10, 18])
                    .into()
                })
                .collect();
            column![header, column(rows).spacing(6)].spacing(0).into()
        };

        container(
            column![
                nav,
                Space::with_height(Length::Fill),
                prompts_section,
            ]
            .spacing(0),
        )
        .width(Length::Fixed(260.0))
        .height(Length::Fill)
        .style(style::sidebar)
        .into()
    }

    fn footer(&self) -> Element<'_, Message> {
        // A second strip below the body for hints + the tiniest bit of
        // hierarchy. Keeps the chrome dense rather than wasting a whole
        // row of pixels.
        container(
            row![
                text("sluice")
                    .size(style::SIZE_XS)
                    .color(style::STATUSBAR_TEXT)
                    .font(style::SEMI),
                Space::with_width(Length::Fill),
                text(format!(
                    "{} pids tracked · {} recent",
                    self.throughput.len(),
                    self.recent_pids.len()
                ))
                .size(style::SIZE_XS)
                .color(style::STATUSBAR_TEXT)
                .font(style::MONO),
            ]
            .spacing(8)
            .padding([8, 24]),
        )
        .width(Length::Fill)
        .style(style::statusbar)
        .into()
    }

    fn default_policy_display(&self) -> &str {
        if self.default_policy.is_empty() {
            "—"
        } else {
            self.default_policy.as_str()
        }
    }

    // ---------- views ----------

    fn events_view(&self) -> Element<'_, Message> {
        let header = events_column_header();
        let body: Element<'_, Message> = if self.events.is_empty() {
            empty_state(
                "Waiting for traffic",
                "Open a browser tab or run `curl example.com` to populate the feed.",
            )
        } else {
            let rows: Vec<Element<'_, Message>> = self
                .events
                .iter()
                .filter_map(event_row)
                .collect();
            scrollable(column(rows).spacing(0))
                .height(Length::Fill)
                .into()
        };

        container(column![header, body].spacing(0))
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn rules_view(&self) -> Element<'_, Message> {
        let header = rules_column_header();
        let body: Element<'_, Message> = if self.rules.is_empty() {
            empty_state(
                "No rules yet",
                "Add a rule on the right · matches by exe + host + port + protocol.",
            )
        } else {
            let rows: Vec<Element<'_, Message>> = self.rules.iter().map(rule_row).collect();
            scrollable(column(rows).spacing(0)).height(Length::Fill).into()
        };
        let table = container(column![header, body].spacing(0))
            .width(Length::Fill)
            .height(Length::Fill);

        let form = self.rule_form_panel();

        row![table, form].spacing(0).height(Length::Fill).into()
    }

    fn rule_form_panel(&self) -> Element<'_, Message> {
        let title = text("ADD RULE")
            .size(style::SIZE_XS)
            .color(style::TEXT_MUTED)
            .font(style::BOLD);
        let body = column![
            title,
            form_field("Executable", "any | /usr/bin/...", &self.form.exe, FormField::Exe),
            form_field("Host", "any | 1.2.3.4 | example.com", &self.form.host, FormField::Host),
            form_field("Port", "any | 443 | 8000-8100", &self.form.port, FormField::Port),
            form_field("Protocol", "any | tcp | udp", &self.form.protocol, FormField::Protocol),
            form_field("Verdict", "allow | deny", &self.form.verdict, FormField::Verdict),
            primary_button("Add rule", Message::AddRuleClicked),
        ]
        .spacing(14);

        container(body)
            .width(Length::Fixed(360.0))
            .height(Length::Fill)
            .padding([24, 24])
            .style(|_| iced::widget::container::Style {
                background: Some(iced::Background::Color(style::SIDEBAR_BG)),
                border: iced::Border {
                    color: style::BORDER,
                    width: 0.0,
                    radius: 0.0.into(),
                },
                text_color: Some(style::TEXT),
                ..Default::default()
            })
            .into()
    }

    fn policy_view(&self) -> Element<'_, Message> {
        let current = self.default_policy_display();

        let title = text("DEFAULT POLICY")
            .size(style::SIZE_XS)
            .color(style::TEXT_MUTED)
            .font(style::BOLD);
        let big = text(current.to_string())
            .size(style::SIZE_HERO)
            .color(style::TEXT)
            .font(style::BOLD);
        let descr = text(policy_description(current))
            .size(style::SIZE_MD)
            .color(style::TEXT_MUTED);

        let opt = |label: &'static str, value: &'static str, body: &'static str| -> Element<'_, Message> {
            let active = current == value;
            let dot_color = if active { style::PRIMARY } else { style::BORDER_STRONG };
            let dot = container(Space::with_width(Length::Fixed(16.0)))
                .height(Length::Fixed(16.0))
                .style(move |_| iced::widget::container::Style {
                    background: Some(iced::Background::Color(if active {
                        style::PRIMARY
                    } else {
                        style::CARD
                    })),
                    border: iced::Border {
                        color: dot_color,
                        width: 2.0,
                        radius: 8.0.into(),
                    },
                    ..Default::default()
                });
            let label_text = text(label)
                .size(style::SIZE_LG)
                .color(style::TEXT)
                .font(style::BOLD);
            let body_text = text(body).size(style::SIZE_SM).color(style::TEXT_MUTED);

            button(
                row![
                    dot,
                    column![label_text, body_text].spacing(4),
                ]
                .spacing(16)
                .align_y(Alignment::Center)
                .padding([12, 8]),
            )
            .on_press(Message::SetPolicy(value.to_string()))
            .width(Length::Fill)
            .style(style::sidebar_item(active))
            .into()
        };

        let options = column![
            opt("Allow", "allow", "Pass everything through. Logs only."),
            opt("Deny", "deny", "Block everything not explicitly allowed."),
            opt("Ask", "ask", "Prompt for unrecognised processes (mode B: first connect slips through)."),
        ]
        .spacing(6);

        container(
            column![
                title,
                big,
                descr,
                Space::with_height(Length::Fixed(28.0)),
                options,
            ]
            .spacing(12)
            .padding([32, 48]),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
    }

    fn bandwidth_view(&self) -> Element<'_, Message> {
        let header = rates_column_header();
        let body: Element<'_, Message> = if self.rates.is_empty() {
            empty_state(
                "No rate limits",
                "Pick a process from the right or type a PID to throttle its egress bandwidth.",
            )
        } else {
            let rows: Vec<Element<'_, Message>> = self
                .rates
                .iter()
                .map(|r| rate_row(r, self.throughput.get(&r.pid).copied().unwrap_or(0)))
                .collect();
            scrollable(column(rows).spacing(0)).height(Length::Fill).into()
        };

        let table = container(column![header, body].spacing(0))
            .width(Length::Fill)
            .height(Length::Fill);

        let form = self.rate_form_panel();

        row![table, form].spacing(0).height(Length::Fill).into()
    }

    fn rate_form_panel(&self) -> Element<'_, Message> {
        let title = text("ADD LIMIT")
            .size(style::SIZE_XS)
            .color(style::TEXT_MUTED)
            .font(style::BOLD);

        let mut form = column![
            title,
            form_field_simple("PID", "1234", &self.rate_form.pid, RateField::Pid),
            form_field_simple(
                "Rate (KB/s)",
                "256",
                &self.rate_form.rate_kbps,
                RateField::RateKbps,
            ),
            primary_button("Apply limit", Message::AddRate),
        ]
        .spacing(14);

        if let Some(msg) = &self.rate_form_error {
            form = form.push(
                text(msg.clone())
                    .size(style::SIZE_SM)
                    .color(style::DANGER)
                    .font(style::SEMI),
            );
        }

        let picker_label = text("RECENT PROCESSES")
            .size(style::SIZE_XS)
            .color(style::TEXT_MUTED)
            .font(style::BOLD);

        let picker_rows: Vec<Element<'_, Message>> = self
            .recent_pids
            .iter()
            .take(20)
            .map(|r| {
                let bps = self.throughput.get(&r.pid).copied().unwrap_or(0);
                let bps_label = if bps == 0 {
                    "—".to_string()
                } else {
                    format!("{} KB/s", bps / 1024)
                };
                button(
                    row![
                        column![
                            text(r.label.clone())
                                .size(style::SIZE_SM)
                                .color(style::TEXT)
                                .font(style::SEMI),
                            text(format!("pid {}", r.pid))
                                .size(style::SIZE_XS)
                                .color(style::TEXT_MUTED)
                                .font(style::MONO),
                        ]
                        .spacing(2),
                        Space::with_width(Length::Fill),
                        text(bps_label)
                            .size(style::SIZE_SM)
                            .color(if bps > 0 { style::PRIMARY } else { style::TEXT_MUTED })
                            .font(style::MONO_BOLD),
                    ]
                    .align_y(Alignment::Center)
                    .spacing(6),
                )
                .on_press(Message::RateFieldChanged(
                    RateField::Pid,
                    r.pid.to_string(),
                ))
                .width(Length::Fill)
                .padding([10, 14])
                .style(style::picker_button)
                .into()
            })
            .collect();

        let picker_body: Element<'_, Message> = if picker_rows.is_empty() {
            text("No recent processes seen yet")
                .size(style::SIZE_SM)
                .color(style::TEXT_MUTED)
                .into()
        } else {
            scrollable(column(picker_rows).spacing(4))
                .height(Length::Fill)
                .into()
        };

        let panel = column![
            form,
            Space::with_height(Length::Fixed(28.0)),
            picker_label,
            picker_body,
        ]
        .spacing(12);

        container(panel)
            .width(Length::Fixed(380.0))
            .height(Length::Fill)
            .padding([24, 24])
            .style(|_| iced::widget::container::Style {
                background: Some(iced::Background::Color(style::SIDEBAR_BG)),
                border: iced::Border {
                    color: style::BORDER,
                    width: 0.0,
                    radius: 0.0.into(),
                },
                text_color: Some(style::TEXT),
                ..Default::default()
            })
            .into()
    }
}

// ---------- presentational helpers ----------

fn primary_button<'a, M: Clone + 'a>(label: &str, msg: M) -> Element<'a, M> {
    button(
        row![
            icon(Icon::Plus, 16.0, iced::Color::WHITE),
            text(label.to_string())
                .size(style::SIZE_MD)
                .font(style::SEMI),
        ]
        .spacing(8)
        .align_y(Alignment::Center),
    )
    .on_press(msg)
    .padding([12, 20])
    .width(Length::Fill)
    .style(style::primary_button)
    .into()
}

fn small_button<'a, M: Clone + 'a>(label: &str, msg: M, danger: bool) -> Element<'a, M> {
    let style_fn: fn(&iced::Theme, button::Status) -> button::Style = if danger {
        style::danger_button
    } else {
        style::secondary_button
    };
    let icon_color = if danger {
        iced::Color::WHITE
    } else {
        style::TEXT
    };
    let icon_kind = if danger { Icon::X } else { Icon::Check };
    button(
        row![
            icon(icon_kind, 13.0, icon_color),
            text(label.to_string())
                .size(style::SIZE_SM)
                .font(style::SEMI),
        ]
        .spacing(6)
        .align_y(Alignment::Center),
    )
    .on_press(msg)
    .padding([6, 14])
    .style(style_fn)
    .into()
}

fn form_field<'a>(
    label: &'a str,
    placeholder: &'a str,
    value: &str,
    field: FormField,
) -> Element<'a, Message> {
    let label = text(label)
        .size(style::SIZE_XS)
        .color(style::TEXT_MUTED)
        .font(style::BOLD);
    let input = text_input(placeholder, value)
        .on_input(move |v| Message::FormFieldChanged(field, v))
        .padding([10, 12])
        .size(style::SIZE_SM)
        .style(style::text_input_style);
    column![label, input].spacing(6).into()
}

fn form_field_simple<'a>(
    label: &'a str,
    placeholder: &'a str,
    value: &str,
    field: RateField,
) -> Element<'a, Message> {
    let label = text(label)
        .size(style::SIZE_XS)
        .color(style::TEXT_MUTED)
        .font(style::BOLD);
    let input = text_input(placeholder, value)
        .on_input(move |v| Message::RateFieldChanged(field, v))
        .padding([10, 12])
        .size(style::SIZE_SM)
        .style(style::text_input_style);
    column![label, input].spacing(6).into()
}

fn empty_state<'a, M: 'a>(title: &str, body: &str) -> Element<'a, M> {
    container(
        column![
            text(title.to_string())
                .size(style::SIZE_XL)
                .color(style::TEXT)
                .font(style::BOLD),
            text(body.to_string())
                .size(style::SIZE_MD)
                .color(style::TEXT_MUTED),
        ]
        .spacing(10)
        .align_x(Alignment::Center),
    )
    .padding([80, 24])
    .width(Length::Fill)
    .height(Length::Fill)
    .center_x(Length::Fill)
    .center_y(Length::Fill)
    .into()
}

// ---------- column headers ----------

fn events_column_header<'a>() -> Element<'a, Message> {
    container(
        row![
            cell_header("AGE", 80.0),
            cell_header("VERDICT", 110.0),
            cell_header("PROCESS", 340.0),
            cell_header("PID", 80.0),
            cell_header("UID", 70.0),
            cell_header("DESTINATION", 280.0),
            cell_header("PROTO", 80.0),
        ]
        .spacing(14)
        .align_y(Alignment::Center),
    )
    .padding([12, 24])
    .width(Length::Fill)
    .style(style::table_header)
    .into()
}

fn rules_column_header<'a>() -> Element<'a, Message> {
    container(
        row![
            cell_header("ID", 70.0),
            cell_header("VERDICT", 110.0),
            cell_header("EXE", 320.0),
            cell_header("HOST", 240.0),
            cell_header("PORT", 110.0),
            cell_header("PROTO", 80.0),
            Space::with_width(Length::Fill),
            cell_header("", 100.0),
        ]
        .spacing(14)
        .align_y(Alignment::Center),
    )
    .padding([12, 24])
    .width(Length::Fill)
    .style(style::table_header)
    .into()
}

fn rates_column_header<'a>() -> Element<'a, Message> {
    container(
        row![
            cell_header("PID", 100.0),
            cell_header("CONFIGURED", 170.0),
            cell_header("LIVE", 170.0),
            cell_header("BURST", 160.0),
            Space::with_width(Length::Fill),
            cell_header("", 100.0),
        ]
        .spacing(14)
        .align_y(Alignment::Center),
    )
    .padding([12, 24])
    .width(Length::Fill)
    .style(style::table_header)
    .into()
}

fn cell_header<'a, M: 'a>(label: &str, width: f32) -> Element<'a, M> {
    text(label.to_string())
        .size(style::SIZE_XS)
        .color(style::TEXT_MUTED)
        .font(style::BOLD)
        .width(Length::Fixed(width))
        .into()
}

// ---------- row renderers ----------

fn event_row(entry: &EventEntry) -> Option<Element<'_, Message>> {
    match &entry.event {
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
            let age = format_age(entry.received_at.elapsed());
            let label = exe
                .as_ref()
                .map(|s| short_path(s))
                .unwrap_or_else(|| "(no exe)".to_string());
            let dst = if family == "ipv6" {
                format!("[{addr}]:{dport}")
            } else {
                format!("{addr}:{dport}")
            };
            let row = row![
                mono_cell(&age, 80.0),
                container(verdict_badge(verdict)).width(Length::Fixed(110.0)),
                mono_cell(&label, 340.0),
                mono_cell(&pid.to_string(), 80.0),
                mono_cell(&extract_uid(&entry.event), 70.0),
                mono_cell(&dst, 280.0),
                mono_cell(protocol, 80.0),
            ]
            .spacing(14)
            .align_y(Alignment::Center);
            Some(
                container(row)
                    .padding([10, 24])
                    .width(Length::Fill)
                    .style(style::table_row)
                    .into(),
            )
        }
        Event::Prompt { .. }
        | Event::RulesChanged { .. }
        | Event::RatesChanged { .. }
        | Event::Throughput { .. } => None,
    }
}

fn rule_row(r: &RuleSummary) -> Element<'_, Message> {
    let delete_btn = button(
        row![
            icon(Icon::Trash, 14.0, iced::Color::WHITE),
            text("Delete").size(style::SIZE_SM).font(style::SEMI),
        ]
        .spacing(6)
        .align_y(Alignment::Center),
    )
    .on_press(Message::DeleteRule(r.id))
    .padding([6, 14])
    .style(style::danger_button);

    let row = row![
        mono_cell(&format!("#{}", r.id), 70.0),
        container(verdict_badge(&r.verdict)).width(Length::Fixed(110.0)),
        mono_cell(&r.exe, 320.0),
        mono_cell(&r.host, 240.0),
        mono_cell(&r.port, 110.0),
        mono_cell(&r.protocol, 80.0),
        Space::with_width(Length::Fill),
        delete_btn,
    ]
    .spacing(14)
    .align_y(Alignment::Center);
    container(row)
        .padding([10, 24])
        .width(Length::Fill)
        .style(style::table_row)
        .into()
}

fn rate_row<'a>(r: &'a RateEntry, current_bps: u64) -> Element<'a, Message> {
    let configured = if r.rate_bps == 0 {
        "unlimited".to_string()
    } else {
        format!("{} KB/s", r.rate_bps / 1024)
    };
    let live = if current_bps == 0 {
        "—".to_string()
    } else {
        format!("{} KB/s", current_bps / 1024)
    };
    let live_color = if current_bps == 0 {
        style::TEXT_MUTED
    } else {
        style::PRIMARY
    };
    let burst = format!("{} B", r.burst_bytes);

    let row = row![
        mono_cell(&r.pid.to_string(), 100.0),
        mono_cell(&configured, 170.0),
        text(live)
            .size(style::SIZE_MD)
            .color(live_color)
            .font(style::MONO_BOLD)
            .width(Length::Fixed(170.0)),
        mono_cell(&burst, 160.0),
        Space::with_width(Length::Fill),
        container(small_button("Clear", Message::ClearRate(r.pid), true))
            .width(Length::Fixed(100.0)),
    ]
    .spacing(14)
    .align_y(Alignment::Center);
    container(row)
        .padding([10, 24])
        .width(Length::Fill)
        .style(style::table_row)
        .into()
}

fn verdict_badge<'a, M: 'a>(verdict: &str) -> Element<'a, M> {
    type StyleFn = fn(&iced::Theme) -> iced::widget::container::Style;
    let style_fn: StyleFn = match verdict {
        "allow" => style::badge_allow,
        "deny" => style::badge_deny,
        _ => style::badge_neutral,
    };
    let icon_kind: Option<Icon> = match verdict {
        "allow" => Some(Icon::Check),
        "deny" => Some(Icon::X),
        _ => None,
    };
    let icon_color = match verdict {
        "allow" => style::SUCCESS,
        "deny" => style::DANGER,
        _ => style::TEXT_MUTED,
    };
    let label = text(verdict.to_uppercase())
        .size(style::SIZE_XS)
        .font(style::BOLD);
    let body: Element<'_, M> = match icon_kind {
        Some(k) => row![icon(k, 12.0, icon_color), label]
            .spacing(4)
            .align_y(Alignment::Center)
            .into(),
        None => label.into(),
    };
    container(body).padding([4, 10]).style(style_fn).into()
}

fn mono_cell<'a, M: 'a>(value: &str, width: f32) -> Element<'a, M> {
    text(value.to_string())
        .size(style::SIZE_MD)
        .color(style::TEXT)
        .font(style::MONO)
        .width(Length::Fixed(width))
        .into()
}

fn short_path(path: &str) -> String {
    if path.len() <= 44 {
        return path.to_string();
    }
    // Keep the last two segments + a leading "…/".
    let segs: Vec<&str> = path.rsplit('/').take(2).collect();
    if segs.len() == 2 {
        format!("…/{}/{}", segs[1], segs[0])
    } else {
        path.to_string()
    }
}

fn short_basename(path: &str) -> String {
    path.rsplit('/')
        .next()
        .map(|s| s.to_string())
        .unwrap_or_else(|| path.to_string())
}

fn format_age(d: std::time::Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else {
        format!("{}h", secs / 3600)
    }
}

/// Pull a UID out of a `ConnectEvent`-shaped IPC `Event`. The IPC type
/// drops UID for now (only the formatter uses it on the daemon side);
/// always return "—" until the wire format is extended.
fn extract_uid(_event: &Event) -> String {
    "—".to_string()
}

fn policy_description(policy: &str) -> &'static str {
    match policy {
        "allow" => "All outbound connections pass through. Sluiced still logs and surfaces them in the Events feed.",
        "deny" => "All outbound connections are blocked unless an explicit Allow rule matches.",
        "ask" => "Unrecognised processes raise a prompt before their next connect.",
        _ => "Daemon hasn't reported a policy yet.",
    }
}
