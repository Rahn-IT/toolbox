use std::{
    io::ErrorKind,
    net::{IpAddr, SocketAddr},
    num::NonZeroU16,
    time::Duration,
};

use futures_util::stream;
use iced::{Element, Task};
use tokio::{net::TcpStream, time::Instant};
use tokio_rustls::{client::TlsStream, rustls::pki_types::ServerName};

use super::{
    check_view::{badge, checking, error_badge},
    protocol_detection::{self, Application, Detected, GREETING_WINDOW, Greeting},
    tls,
};

#[derive(Clone)]
pub enum Message {
    CheckStarted,
    Finished(Outcome),
    PassiveFinished(Option<Detected>),
    TlsStarted,
    TlsFinished(tls::Report),
    ActiveFinished(Option<Detected>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Connected,
    Refused,
    TimedOut,
    Failed(String),
}

impl Outcome {
    pub(super) fn view<M: 'static>(&self) -> Element<'_, M> {
        match self {
            Self::Connected => badge("Connected", true),
            Self::Refused => badge("Connection refused", false),
            Self::TimedOut => badge("Timed out", false),
            Self::Failed(error) => error_badge("Connection failed", error),
        }
    }
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

    pub fn next_checks(&self, host: &str) -> Task<Message> {
        match *self {
            Self::Pending(endpoint) => Task::stream(stream::unfold(
                Probe::Tcp(endpoint, host.to_owned()),
                Probe::next,
            )),
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
            Self::Complete(_, outcome) => outcome.view(),
            _ => return None,
        })
    }
}

enum Probe {
    Tcp(SocketAddr, String),
    Passive(TcpStream, SocketAddr, String, Instant),
    StartActive(Option<TcpStream>, Target),
    Tls(TcpStream, Target),
    TlsApplication(Box<TlsStream<TcpStream>>, Target),
    Plaintext(Target),
    Finish(Option<Detected>),
    Done,
}

struct Target {
    endpoint: SocketAddr,
    name: ServerName<'static>,
    started: Instant,
}

impl Target {
    fn authority(&self) -> String {
        let port = self.endpoint.port();
        let host = self.name.to_str();
        if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        }
    }

    fn deadline(&self) -> Instant {
        self.started + Duration::from_secs(8)
    }
}

impl Probe {
    async fn next(self) -> Option<(Message, Self)> {
        match self {
            Self::Tcp(endpoint, host) => match connect(endpoint).await {
                Ok(stream) => Some((
                    Message::Finished(Outcome::Connected),
                    Self::Passive(stream, endpoint, host, Instant::now()),
                )),
                Err(error) => Some((Message::Finished(error), Self::Done)),
            },
            Self::Passive(mut stream, endpoint, host, started) => {
                let greeting =
                    protocol_detection::passive(&mut stream, started + GREETING_WINDOW).await;
                let detected = match greeting {
                    Greeting::Recognized(application) => Some(Detected::Plain(application)),
                    _ => None,
                };
                let next = if detected.is_some() {
                    Self::Done
                } else if let Ok(name) = tls::server_name(&host) {
                    Self::StartActive(
                        (greeting == Greeting::Silent).then_some(stream),
                        Target {
                            endpoint,
                            name,
                            started,
                        },
                    )
                } else {
                    Self::Finish(None)
                };
                Some((Message::PassiveFinished(detected), next))
            }
            Self::StartActive(stream, target) => {
                let stream = match stream {
                    Some(stream) => Some(stream),
                    None => tokio::time::timeout_at(
                        target.started + Duration::from_secs(5),
                        connect(target.endpoint),
                    )
                    .await
                    .ok()
                    .and_then(Result::ok),
                };
                match stream {
                    Some(stream) => Some((Message::TlsStarted, Self::Tls(stream, target))),
                    None => Some((Message::ActiveFinished(None), Self::Done)),
                }
            }
            Self::Tls(stream, target) => {
                let (report, transport) = tls::inspect(
                    stream,
                    target.name.clone(),
                    target.started + Duration::from_secs(5),
                )
                .await;
                let next = match transport {
                    Some(stream) => Self::TlsApplication(Box::new(stream), target),
                    None if report.peer_alert || !report.presented.certificates.is_empty() => {
                        Self::Finish(Some(Detected::Tls(None)))
                    }
                    None => Self::Plaintext(target),
                };
                Some((Message::TlsFinished(report), next))
            }
            Self::TlsApplication(mut stream, target) => {
                let alpn = stream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
                let application = protocol_detection::inside_tls(
                    &mut *stream,
                    alpn.as_deref(),
                    &target.authority(),
                    target.deadline(),
                )
                .await;
                Some((
                    Message::ActiveFinished(Some(Detected::Tls(application))),
                    Self::Done,
                ))
            }
            Self::Plaintext(target) => {
                let detected = plaintext(&target).await.map(Detected::Plain);
                Some((Message::ActiveFinished(detected), Self::Done))
            }
            Self::Finish(detected) => Some((Message::ActiveFinished(detected), Self::Done)),
            Self::Done => None,
        }
    }
}

async fn plaintext(target: &Target) -> Option<Application> {
    const BINARY_WINDOW: Duration = Duration::from_millis(750);
    let deadline = target.deadline();
    let http_deadline = deadline - BINARY_WINDOW * 2;
    let http = async {
        let mut stream = connect(target.endpoint).await.ok()?;
        protocol_detection::http(&mut stream, &target.authority(), http_deadline)
            .await
            .then_some(Application::Http)
    };
    if let Ok(Some(application)) = tokio::time::timeout_at(http_deadline, http).await {
        return Some(application);
    }
    let smb = async {
        let mut stream = connect(target.endpoint).await.ok()?;
        protocol_detection::smb_tcp(&mut stream).await
    };
    let smb_deadline = (Instant::now() + BINARY_WINDOW).min(deadline - BINARY_WINDOW);
    if let Ok(Some(())) = tokio::time::timeout_at(smb_deadline, smb).await {
        return Some(Application::Smb);
    }
    let dns = async {
        let mut stream = connect(target.endpoint).await.ok()?;
        protocol_detection::dns_tcp(&mut stream).await
    };
    tokio::time::timeout_at((Instant::now() + BINARY_WINDOW).min(deadline), dns)
        .await
        .ok()
        .flatten()
        .map(|()| Application::Dns)
}

pub(super) async fn connect(endpoint: SocketAddr) -> Result<TcpStream, Outcome> {
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
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        time::timeout,
    };

    #[tokio::test]
    async fn discovers_smb_and_dns_on_ephemeral_tcp_ports() {
        use hickory_client::proto::op::{Message as DnsMessage, MessageType, ResponseCode};

        for application in [Application::Smb, Application::Dns] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                for first_byte in [22, b'H'] {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    assert_eq!(stream.read_u8().await.unwrap(), first_byte);
                    stream.shutdown().await.unwrap();
                }
                let (mut smb, _) = listener.accept().await.unwrap();
                let length = smb.read_u32().await.unwrap() as usize;
                assert!((100..=1024).contains(&length));
                let mut request = vec![0; length];
                smb.read_exact(&mut request).await.unwrap();
                assert!(request.starts_with(b"\xfeSMB"));
                assert_eq!(request[12..14], [0, 0]);
                if application == Application::Smb {
                    let mut response = [0; 128];
                    response[..6].copy_from_slice(b"\xfeSMB\x40\x00");
                    response[16] = 1;
                    response[64] = 65;
                    response[68..70].copy_from_slice(&0x0302u16.to_le_bytes());
                    smb.write_u32(response.len() as u32).await.unwrap();
                    smb.write_all(&response).await.unwrap();
                } else {
                    smb.shutdown().await.unwrap();
                    let (mut dns, _) = listener.accept().await.unwrap();
                    let length = dns.read_u16().await.unwrap() as usize;
                    let mut buffer = vec![0; length];
                    dns.read_exact(&mut buffer).await.unwrap();
                    let mut response = DnsMessage::from_vec(&buffer).unwrap();
                    assert!(!response.recursion_desired());
                    response
                        .set_message_type(MessageType::Response)
                        .set_response_code(ResponseCode::Refused);
                    let response = response.to_vec().unwrap();
                    dns.write_u16(response.len() as u16).await.unwrap();
                    dns.write_all(&response).await.unwrap();
                }
                assert!(
                    timeout(Duration::from_millis(50), listener.accept())
                        .await
                        .is_err()
                );
            });
            let mut probe = Probe::Tcp(endpoint, "localhost".into());
            let mut result = None;
            while let Some((message, next)) = probe.next().await {
                if let Message::ActiveFinished(detected) = message {
                    result = detected;
                }
                probe = next;
            }
            assert_eq!(result, Some(Detected::Plain(application)));
            timeout(Duration::from_secs(2), server)
                .await
                .unwrap()
                .unwrap();
        }
    }

    #[tokio::test]
    async fn a_fragmented_ssh_greeting_finishes_without_active_probes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"Welcome\r\nSSH-2.0-").await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            stream.write_all(b"OpenSSH\r\n").await.unwrap();
            assert_eq!(
                stream.read_u8().await.unwrap_err().kind(),
                ErrorKind::UnexpectedEof
            );
            assert!(
                timeout(Duration::from_millis(50), listener.accept())
                    .await
                    .is_err()
            );
        });
        let (message, next) = Probe::Tcp(endpoint, "localhost".into())
            .next()
            .await
            .unwrap();
        assert!(matches!(message, Message::Finished(Outcome::Connected)));
        let (message, next) = next.next().await.unwrap();
        assert!(matches!(
            message,
            Message::PassiveFinished(Some(Detected::Plain(Application::Ssh)))
        ));
        assert!(next.next().await.is_none());
        timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn plaintext_http_uses_a_fresh_connection_and_the_requested_authority() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut tls_attempt, _) = listener.accept().await.unwrap();
            assert_eq!(tls_attempt.read_u8().await.unwrap(), 22);
            tls_attempt.shutdown().await.unwrap();
            let (mut http_attempt, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                assert!(request.len() < 256);
                request.push(http_attempt.read_u8().await.unwrap());
            }
            assert_eq!(
                String::from_utf8(request).unwrap(),
                format!(
                    "HEAD / HTTP/1.1\r\nHost: example.com:{}\r\nConnection: close\r\n\r\n",
                    endpoint.port()
                )
            );
            http_attempt
                .write_all(b"HTTP/1.1 302 Found\r\nLocation: /elsewhere\r\n\r\n")
                .await
                .unwrap();
            assert!(
                timeout(Duration::from_millis(50), listener.accept())
                    .await
                    .is_err()
            );
        });
        let mut probe = Probe::Tcp(endpoint, "example.com".into());
        let mut result = None;
        while let Some((message, next)) = probe.next().await {
            if let Message::ActiveFinished(detected) = message {
                result = detected;
            }
            probe = next;
        }
        assert_eq!(result, Some(Detected::Plain(Application::Http)));
        timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn a_tls_peer_alert_keeps_the_result_tls_and_prevents_plaintext_fallback() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut header = [0; 5];
            stream.read_exact(&mut header).await.unwrap();
            assert_eq!(header[0], 22);
            let mut client_hello = vec![0; u16::from_be_bytes([header[3], header[4]]) as usize];
            stream.read_exact(&mut client_hello).await.unwrap();
            stream.write_all(&[21, 3, 3, 0, 2, 2, 40]).await.unwrap();
            assert!(
                timeout(Duration::from_millis(50), listener.accept())
                    .await
                    .is_err()
            );
        });
        let mut probe = Probe::Tcp(endpoint, "localhost".into());
        let mut result = None;
        while let Some((message, next)) = probe.next().await {
            if let Message::ActiveFinished(detected) = message {
                result = detected;
            }
            probe = next;
        }
        assert_eq!(result, Some(Detected::Tls(None)));
        timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }

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
        assert_eq!(state.next_checks("192.0.2.1").units(), 0);
        assert!(state.view().is_none());
    }

    #[test]
    fn the_check_keeps_the_selected_ip_and_port() {
        let mut state = State::Waiting(NonZeroU16::new(443).unwrap());
        let ip = "2001:db8::1".parse().unwrap();
        assert!(state.view().is_none());
        state.start(ip);
        assert_eq!(state.next_checks("2001:db8::1").units(), 1);
        state.update(Message::CheckStarted);
        assert_eq!(state.next_checks("2001:db8::1").units(), 0);
        state.update(Message::Finished(Outcome::Refused));
        assert!(matches!(state, State::Complete(endpoint, Outcome::Refused)
            if endpoint == SocketAddr::new(ip, 443)));
    }
}
