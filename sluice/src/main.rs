//! `sluice` — the GUI front-end.

mod app;
mod ipc_client;
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
        .run()
}
