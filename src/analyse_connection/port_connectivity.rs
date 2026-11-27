use std::{
    io::ErrorKind,
    net::{IpAddr, SocketAddr},
    num::NonZeroU16,
    time::Duration,
};

use iced::{Element, Task};
use tokio::net::TcpStream;

use super::check_view::{badge, checking, error_badge, section};

#[derive(Clone)]
pub enum Message {
    CheckStarted,
    Finished(Outcome),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Connected,
    Refused,
    TimedOut,
    Failed(String),
}

#[derive(Default)]
pub(super) enum State {
    #[default]
    Disabled,
    Waiting(NonZeroU16),
    Pending(SocketAddr),
    Checking(SocketAddr),
    Complete(SocketAddr, Outcome),
}

impl State {
    pub fn start(&mut self, ip: IpAddr) {
        if let Self::Waiting(port) = self {
            *self = Self::Pending(SocketAddr::new(ip, (*port).into()));
        }
    }

    pub fn is_running(&self) -> bool {
        matches!(self, Self::Pending(_) | Self::Checking(_))
    }

    pub fn next_checks(&self) -> Task<Message> {
        match *self {
            Self::Pending(endpoint) => Task::perform(connect(endpoint), Message::Finished),
            _ => Task::none(),
        }
    }

    pub fn update(&mut self, message: Message) {
        match (message, &*self) {
            (Message::CheckStarted, Self::Pending(endpoint)) => *self = Self::Checking(*endpoint),
            (Message::Finished(outcome), Self::Checking(endpoint)) => {
                *self = Self::Complete(*endpoint, outcome);
            }
            _ => {}
        }
    }

    pub fn view(&self) -> Option<Element<'_, Message>> {
        let (endpoint, result) = match self {
            Self::Checking(endpoint) => (endpoint, checking()),
            Self::Complete(endpoint, outcome) => (
                endpoint,
                match outcome {
                    Outcome::Connected => badge("Connected", true),
                    Outcome::Refused => badge("Connection refused", false),
                    Outcome::TimedOut => badge("Timed out", false),
                    Outcome::Failed(error) => error_badge("Connection failed", error),
                },
            ),
            _ => return None,
        };
        Some(section(
            format!("Port Connectivity ({endpoint})"),
            "TCP connection",
            result,
        ))
    }
}

async fn connect(endpoint: SocketAddr) -> Outcome {
    match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(endpoint)).await {
        Ok(Ok(_)) => Outcome::Connected,
        Ok(Err(error)) if error.kind() == ErrorKind::ConnectionRefused => Outcome::Refused,
        Ok(Err(error)) if error.kind() != ErrorKind::TimedOut => Outcome::Failed(error.to_string()),
        Ok(Err(_)) | Err(_) => Outcome::TimedOut,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connects_to_the_explicit_tcp_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        assert_eq!(connect(target).await, Outcome::Connected);
    }

    #[test]
    fn an_unspecified_port_never_schedules_a_check() {
        let mut state = State::default();
        state.start(IpAddr::from([192, 0, 2, 1]));
        assert_eq!(state.next_checks().units(), 0);
        assert!(state.view().is_none());
    }

    #[test]
    fn the_check_keeps_the_selected_ip_and_port() {
        let mut state = State::Waiting(NonZeroU16::new(443).unwrap());
        let ip = "2001:db8::1".parse().unwrap();
        assert!(state.view().is_none());
        state.start(ip);
        assert_eq!(state.next_checks().units(), 1);
        state.update(Message::CheckStarted);
        assert_eq!(state.next_checks().units(), 0);
        state.update(Message::Finished(Outcome::Refused));
        assert!(matches!(state, State::Complete(endpoint, Outcome::Refused)
            if endpoint == SocketAddr::new(ip, 443)));
    }
}
