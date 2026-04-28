//! `sluice` — the GUI front-end.

mod app;
mod icons;
mod ipc_client;
mod style;
mod subscription;

use crate::app::SluiceApp;

fn main() -> iced::Result {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    iced::application(SluiceApp::title, SluiceApp::update, SluiceApp::view)
        .subscription(SluiceApp::subscription)
        .theme(|_| iced::Theme::Light)
        .window_size((1440.0, 900.0))
        .run()
}
