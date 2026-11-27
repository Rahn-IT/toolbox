use std::net::IpAddr;

use super::check_view::{badge, error_badge};
use crate::network_scanner::ping;
use iced::{
    Alignment, Element,
    widget::{row, text},
};

#[derive(Clone)]
pub struct PingResult(pub(super) ping::Outcome);

impl PingResult {
    pub(super) async fn check(target: IpAddr) -> Self {
        Self(match ping::prepare().await {
            Ok(runner) => runner.echo(None, target).await,
            Err(error) => ping::Outcome::Failed(error),
        })
    }

    pub(super) fn view<M: 'static>(&self) -> Element<'_, M> {
        match &self.0 {
            ping::Outcome::Reply(timing) => row![badge("Reply", true), timing.as_deref().map(text)]
                .align_y(Alignment::Center)
                .spacing(8)
                .into(),
            ping::Outcome::NoReply => badge("No reply", false),
            ping::Outcome::TimedOut => badge("Timed out", false),
            ping::Outcome::Failed(error) => error_badge("No reply", error),
        }
    }
}
