use std::{
    io::ErrorKind,
    net::{IpAddr, SocketAddr},
    num::NonZeroU16,
    time::Duration,
};

use futures_util::stream;
use iced::{Element, Task};
use tokio::net::TcpStream;

use super::{
    check_view::{badge, checking, error_badge},
    tls,
};

#[derive(Clone)]
pub enum Message {
    CheckStarted,
    Finished(Outcome),
    TlsFinished(tls::Report),
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

    pub fn next_checks(&self, tls: Option<tls::Request>) -> Task<Message> {
        match *self {
            Self::Pending(endpoint) => {
                Task::stream(stream::unfold(Probe::Tcp(endpoint, tls), Probe::next))
            }
            _ => Task::none(),
        }
    }

    pub fn connected(&self) -> bool {
        matches!(self, Self::Complete(_, Outcome::Connected))
    }

    pub fn visible_endpoint(&self) -> Option<SocketAddr> {
        match self {
            Self::Checking(endpoint) | Self::Complete(endpoint, _) => Some(*endpoint),
            _ => None,
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
        Some(match self {
            Self::Checking(_) => checking(),
            Self::Complete(_, outcome) => match outcome {
                Outcome::Connected => badge("Connected", true),
                Outcome::Refused => badge("Connection refused", false),
                Outcome::TimedOut => badge("Timed out", false),
                Outcome::Failed(error) => error_badge("Connection failed", error),
            },
            _ => return None,
        })
    }
}

enum Probe {
    Tcp(SocketAddr, Option<tls::Request>),
    Tls(TcpStream, tls::Request),
    Done,
}

impl Probe {
    async fn next(self) -> Option<(Message, Self)> {
        match self {
            Self::Tcp(endpoint, tls) => match connect(endpoint).await {
                Ok(stream) => {
                    let next = tls.map_or(Self::Done, |request| Self::Tls(stream, request));
                    Some((Message::Finished(Outcome::Connected), next))
                }
                Err(error) => Some((Message::Finished(error), Self::Done)),
            },
            Self::Tls(stream, request) => Some((
                Message::TlsFinished(tls::inspect(stream, request).await),
                Self::Done,
            )),
            Self::Done => None,
        }
    }
}

async fn connect(endpoint: SocketAddr) -> Result<TcpStream, Outcome> {
    match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(endpoint)).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(error)) if error.kind() == ErrorKind::ConnectionRefused => Err(Outcome::Refused),
        Ok(Err(error)) if error.kind() != ErrorKind::TimedOut => {
            Err(Outcome::Failed(error.to_string()))
        }
        Ok(Err(_)) | Err(_) => Err(Outcome::TimedOut),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connects_to_the_explicit_tcp_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        assert!(connect(target).await.is_ok());
    }

    #[test]
    fn an_unspecified_port_never_schedules_a_check() {
        let mut state = State::default();
        state.start(IpAddr::from([192, 0, 2, 1]));
        assert_eq!(state.next_checks(None).units(), 0);
        assert!(state.view().is_none());
    }

    #[test]
    fn the_check_keeps_the_selected_ip_and_port() {
        let mut state = State::Waiting(NonZeroU16::new(443).unwrap());
        let ip = "2001:db8::1".parse().unwrap();
        assert!(state.view().is_none());
        state.start(ip);
        assert_eq!(state.next_checks(None).units(), 1);
        state.update(Message::CheckStarted);
        assert_eq!(state.next_checks(None).units(), 0);
        state.update(Message::Finished(Outcome::Refused));
        assert!(matches!(state, State::Complete(endpoint, Outcome::Refused)
            if endpoint == SocketAddr::new(ip, 443)));
    }
}
