//! SVG icon set for the GUI.
//!
//! Each function returns a sized + colorised `iced::widget::svg::Svg`
//! ready to drop into a layout. SVGs are embedded at compile time via
//! `include_bytes!`, then handed to `Handle::from_memory(Cow::Borrowed)`
//! so there's no runtime IO and no allocation per render.

use std::borrow::Cow;

use iced::widget::svg::{self, Handle, Svg};
use iced::{Color, Length};

const EVENTS_BYTES: &[u8] = include_bytes!("../assets/icons/events.svg");
const RULES_BYTES: &[u8] = include_bytes!("../assets/icons/rules.svg");
const POLICY_BYTES: &[u8] = include_bytes!("../assets/icons/policy.svg");
const BANDWIDTH_BYTES: &[u8] = include_bytes!("../assets/icons/bandwidth.svg");
const CHECK_BYTES: &[u8] = include_bytes!("../assets/icons/check.svg");
const X_BYTES: &[u8] = include_bytes!("../assets/icons/x.svg");
const PLUS_BYTES: &[u8] = include_bytes!("../assets/icons/plus.svg");
const TRASH_BYTES: &[u8] = include_bytes!("../assets/icons/trash.svg");
const LOGO_BYTES: &[u8] = include_bytes!("../assets/icons/logo.svg");

#[derive(Clone, Copy)]
pub enum Icon {
    Events,
    Rules,
    Policy,
    Bandwidth,
    Check,
    X,
    Plus,
    Trash,
    Logo,
}

impl Icon {
    fn bytes(self) -> &'static [u8] {
        match self {
            Icon::Events => EVENTS_BYTES,
            Icon::Rules => RULES_BYTES,
            Icon::Policy => POLICY_BYTES,
            Icon::Bandwidth => BANDWIDTH_BYTES,
            Icon::Check => CHECK_BYTES,
            Icon::X => X_BYTES,
            Icon::Plus => PLUS_BYTES,
            Icon::Trash => TRASH_BYTES,
            Icon::Logo => LOGO_BYTES,
        }
    }
}

/// Render `icon` at `size` × `size` pixels in `color`.
pub fn icon<'a, M: 'a>(icon: Icon, size: f32, color: Color) -> iced::Element<'a, M> {
    let handle = Handle::from_memory(Cow::Borrowed(icon.bytes()));
    Svg::new(handle)
        .width(Length::Fixed(size))
        .height(Length::Fixed(size))
        .style(move |_, _| svg::Style { color: Some(color) })
        .into()
}
