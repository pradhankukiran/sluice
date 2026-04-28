//! Visual styling — palette, button styles, container styles.
//!
//! White background, sharp corners, no gradients. The palette is
//! Tailwind-flavoured neutrals with a handful of accent colors for
//! status (deny / allow / warn).

use iced::font::{Family, Weight};
use iced::widget::{button, container, text_input};
use iced::{Background, Border, Color, Font, Shadow, Theme};

/// Monospace font for tabular data (paths, IPs, PIDs, ports, bytes).
pub const MONO: Font = Font::MONOSPACE;

/// Bold sans-serif for headlines, totals, and table column headers.
pub const BOLD: Font = Font {
    family: Family::SansSerif,
    weight: Weight::Bold,
    ..Font::DEFAULT
};

/// Semibold sans-serif for nav labels, button text, status pills.
pub const SEMI: Font = Font {
    family: Family::SansSerif,
    weight: Weight::Semibold,
    ..Font::DEFAULT
};

/// Bold monospace for the big numeric counters in the status bar.
pub const MONO_BOLD: Font = Font {
    family: Family::Monospace,
    weight: Weight::Bold,
    ..Font::DEFAULT
};

// ---------- size scale ----------
//
// One source of truth for type sizes. The scale jumps in a 2-3pt
// progression so adjacent text doesn't visually wobble.

pub const SIZE_XS: u16 = 12;
pub const SIZE_SM: u16 = 14;
pub const SIZE_MD: u16 = 16;
pub const SIZE_LG: u16 = 19;
pub const SIZE_XL: u16 = 24;
pub const SIZE_HERO: u16 = 56;

// ---------- palette ----------

pub const BG: Color = Color::from_rgb(0.969, 0.969, 0.973); // page background
pub const CARD: Color = Color::WHITE;
pub const BORDER: Color = Color::from_rgb(0.898, 0.906, 0.918);
pub const BORDER_STRONG: Color = Color::from_rgb(0.820, 0.835, 0.851);
pub const TEXT: Color = Color::from_rgb(0.067, 0.094, 0.153);
pub const TEXT_MUTED: Color = Color::from_rgb(0.420, 0.447, 0.502);
pub const PRIMARY: Color = Color::from_rgb(0.149, 0.388, 0.922);
pub const PRIMARY_HOVER: Color = Color::from_rgb(0.118, 0.318, 0.776);
pub const DANGER: Color = Color::from_rgb(0.863, 0.149, 0.149);
pub const DANGER_HOVER: Color = Color::from_rgb(0.722, 0.110, 0.110);
pub const SUCCESS: Color = Color::from_rgb(0.086, 0.639, 0.290);
pub const TABLE_HEADER_BG: Color = Color::from_rgb(0.976, 0.980, 0.984);
pub const SIDEBAR_BG: Color = Color::from_rgb(0.957, 0.961, 0.969);
pub const SIDEBAR_ACTIVE_BG: Color = Color::WHITE;
pub const STATUSBAR_BG: Color = Color::from_rgb(0.110, 0.137, 0.184);
pub const STATUSBAR_TEXT: Color = Color::from_rgb(0.745, 0.776, 0.824);
pub const STATUSBAR_TEXT_BRIGHT: Color = Color::from_rgb(0.937, 0.945, 0.961);

// ---------- container styles ----------

/// Page-level frame (everything below the title bar). Just sets the
/// background color so the cards stand out.
pub fn page(_: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(BG)),
        text_color: Some(TEXT),
        ..Default::default()
    }
}

/// Table column-header row.
pub fn table_header(_: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(TABLE_HEADER_BG)),
        border: Border {
            color: BORDER,
            width: 0.0,
            radius: 0.0.into(),
        },
        text_color: Some(TEXT_MUTED),
        shadow: Shadow::default(),
    }
}

/// Table data row with a hairline bottom border.
pub fn table_row(_: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(CARD)),
        border: Border {
            color: BORDER,
            width: 0.0,
            radius: 0.0.into(),
        },
        text_color: Some(TEXT),
        shadow: Shadow::default(),
    }
}

/// Status badge for allow/deny verdict labels in the events feed.
pub fn badge_allow(_: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(Color::from_rgb(0.910, 0.965, 0.929))),
        border: Border {
            color: SUCCESS,
            width: 1.0,
            radius: 0.0.into(),
        },
        text_color: Some(SUCCESS),
        shadow: Shadow::default(),
    }
}

pub fn badge_deny(_: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(Color::from_rgb(0.992, 0.910, 0.918))),
        border: Border {
            color: DANGER,
            width: 1.0,
            radius: 0.0.into(),
        },
        text_color: Some(DANGER),
        shadow: Shadow::default(),
    }
}

pub fn badge_neutral(_: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(TABLE_HEADER_BG)),
        border: Border {
            color: BORDER_STRONG,
            width: 1.0,
            radius: 0.0.into(),
        },
        text_color: Some(TEXT_MUTED),
        shadow: Shadow::default(),
    }
}

// ---------- button styles ----------

pub fn primary_button(_: &Theme, status: button::Status) -> button::Style {
    let bg = match status {
        button::Status::Hovered | button::Status::Pressed => PRIMARY_HOVER,
        _ => PRIMARY,
    };
    button::Style {
        background: Some(Background::Color(bg)),
        text_color: Color::WHITE,
        border: Border {
            color: bg,
            width: 1.0,
            radius: 0.0.into(),
        },
        shadow: Shadow::default(),
    }
}

pub fn secondary_button(_: &Theme, status: button::Status) -> button::Style {
    let (bg, fg) = match status {
        button::Status::Hovered | button::Status::Pressed => (TABLE_HEADER_BG, TEXT),
        _ => (CARD, TEXT),
    };
    button::Style {
        background: Some(Background::Color(bg)),
        text_color: fg,
        border: Border {
            color: BORDER_STRONG,
            width: 1.0,
            radius: 0.0.into(),
        },
        shadow: Shadow::default(),
    }
}

pub fn danger_button(_: &Theme, status: button::Status) -> button::Style {
    let bg = match status {
        button::Status::Hovered | button::Status::Pressed => DANGER_HOVER,
        _ => DANGER,
    };
    button::Style {
        background: Some(Background::Color(bg)),
        text_color: Color::WHITE,
        border: Border {
            color: bg,
            width: 1.0,
            radius: 0.0.into(),
        },
        shadow: Shadow::default(),
    }
}

pub fn picker_button(_: &Theme, status: button::Status) -> button::Style {
    let bg = match status {
        button::Status::Hovered | button::Status::Pressed => TABLE_HEADER_BG,
        _ => CARD,
    };
    button::Style {
        background: Some(Background::Color(bg)),
        text_color: TEXT_MUTED,
        border: Border {
            color: BORDER,
            width: 1.0,
            radius: 0.0.into(),
        },
        shadow: Shadow::default(),
    }
}

pub fn sidebar_item(active: bool) -> impl Fn(&Theme, button::Status) -> button::Style {
    move |_, status| {
        let bg = if active {
            SIDEBAR_ACTIVE_BG
        } else if matches!(status, button::Status::Hovered | button::Status::Pressed) {
            CARD
        } else {
            Color::TRANSPARENT
        };
        let fg = if active { TEXT } else { TEXT_MUTED };
        button::Style {
            background: Some(Background::Color(bg)),
            text_color: fg,
            border: Border {
                color: if active { BORDER } else { Color::TRANSPARENT },
                width: 1.0,
                radius: 0.0.into(),
            },
            shadow: Shadow::default(),
        }
    }
}

pub fn statusbar(_: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(STATUSBAR_BG)),
        text_color: Some(STATUSBAR_TEXT),
        border: Border {
            color: STATUSBAR_BG,
            width: 0.0,
            radius: 0.0.into(),
        },
        shadow: Shadow::default(),
    }
}

pub fn sidebar(_: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(SIDEBAR_BG)),
        text_color: Some(TEXT),
        border: Border {
            color: BORDER,
            width: 0.0,
            radius: 0.0.into(),
        },
        shadow: Shadow::default(),
    }
}

// ---------- input styles ----------

pub fn text_input_style(_: &Theme, status: text_input::Status) -> text_input::Style {
    let border_color = match status {
        text_input::Status::Focused { .. } => PRIMARY,
        _ => BORDER_STRONG,
    };
    text_input::Style {
        background: Background::Color(CARD),
        border: Border {
            color: border_color,
            width: 1.0,
            radius: 0.0.into(),
        },
        icon: TEXT_MUTED,
        placeholder: TEXT_MUTED,
        value: TEXT,
        selection: Color::from_rgba(PRIMARY.r, PRIMARY.g, PRIMARY.b, 0.18),
    }
}
