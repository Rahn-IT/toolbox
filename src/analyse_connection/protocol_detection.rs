use std::{fmt, io, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::{Instant, timeout_at},
};

use super::Protocol;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Application {
    Http,
    Ssh,
    Smtp,
    Ftp,
    Imap,
    Pop3,
}

impl fmt::Display for Application {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Http => "HTTP",
            Self::Ssh => "SSH",
            Self::Smtp => "SMTP",
            Self::Ftp => "FTP",
            Self::Imap => "IMAP",
            Self::Pop3 => "POP3",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Detected {
    Plain(Application),
    Tls(Option<Application>),
}

impl Detected {
    pub fn from_selection(protocol: Protocol) -> Option<Self> {
        match protocol {
            Protocol::Http => Some(Self::Plain(Application::Http)),
            Protocol::Https => Some(Self::Tls(Some(Application::Http))),
            Protocol::Tls => Some(Self::Tls(None)),
            Protocol::Autodetect => None,
        }
    }

    pub fn conflicts_with(self, expected: Self) -> bool {
        self != expected
            && !matches!(
                (self, expected),
                (Self::Tls(_), Self::Tls(None))
                    | (Self::Tls(None), Self::Tls(Some(Application::Http)))
            )
    }

    pub fn comparison(self, selected: Protocol) -> Option<bool> {
        let expected = Self::from_selection(selected)?;
        if self == Self::Tls(None) && selected == Protocol::Https {
            return None;
        }
        Some(!self.conflicts_with(expected))
    }
}

impl fmt::Display for Detected {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plain(application) => application.fmt(formatter),
            Self::Tls(None) => formatter.write_str("TLS"),
            Self::Tls(Some(Application::Http)) => formatter.write_str("HTTPS"),
            Self::Tls(Some(Application::Imap)) => formatter.write_str("IMAPS"),
            Self::Tls(Some(Application::Pop3)) => formatter.write_str("POP3S"),
            Self::Tls(Some(application)) => write!(formatter, "{application} over TLS"),
        }
    }
}

#[derive(Default)]
pub(super) enum Check {
    #[default]
    Skipped,
    Checking,
    Complete(Option<Detected>),
}

impl Check {
    pub fn detected(&self) -> Option<Detected> {
        match self {
            Self::Complete(detected) => *detected,
            _ => None,
        }
    }
}

pub(super) const GREETING_WINDOW: Duration = Duration::from_millis(300);

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Greeting {
    Recognized(Application),
    Silent,
    Inconclusive,
}

pub(super) async fn passive(stream: &mut (impl AsyncRead + Unpin), deadline: Instant) -> Greeting {
    let mut consumed = false;
    let result = timeout_at(deadline, async {
        let mut input = [0; 1024];
        let mut end = 0;
        let mut start = 0;
        while end < input.len() {
            let Ok(count) = stream.read(&mut input[end..]).await else {
                return Greeting::Inconclusive;
            };
            if count == 0 {
                return Greeting::Inconclusive;
            }
            consumed = true;
            end += count;
            while let Some(newline) = input[start..end].iter().position(|byte| *byte == b'\n') {
                let line_end = start + newline;
                if let Some(detected) = greeting(&input[start..line_end]) {
                    return Greeting::Recognized(detected);
                }
                start = line_end + 1;
            }
        }
        Greeting::Inconclusive
    })
    .await;
    result.unwrap_or(if consumed {
        Greeting::Inconclusive
    } else {
        Greeting::Silent
    })
}

fn greeting(line: &[u8]) -> Option<Application> {
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    if line.iter().any(|&byte| !(b' '..=b'~').contains(&byte)) {
        return None;
    }
    if let Some(identifier) = line.strip_prefix(b"SSH-")
        && let Some(dash) = identifier.iter().position(|&byte| byte == b'-')
        && let Some(dot) = identifier[..dash].iter().position(|&byte| byte == b'.')
        && decimal(&identifier[..dot])
        && decimal(&identifier[dot + 1..dash])
        && identifier.get(dash + 1).is_some_and(|&byte| byte != b' ')
    {
        return Some(Application::Ssh);
    }

    let (response, body) = line.split_at_checked(line.iter().position(|&byte| byte == b' ')?)?;
    let has_token = |token: &[u8]| {
        body.split(|byte: &u8| !byte.is_ascii_alphanumeric())
            .any(|word| word.eq_ignore_ascii_case(token))
    };
    match response {
        b"220" => match (has_token(b"SMTP") || has_token(b"ESMTP"), has_token(b"FTP")) {
            (true, false) => Some(Application::Smtp),
            (false, true) => Some(Application::Ftp),
            _ => None,
        },
        b"*" if (body.starts_with(b" OK ") || body.starts_with(b" PREAUTH "))
            && (has_token(b"IMAP")
                || has_token(b"IMAP4")
                || has_token(b"IMAP4rev1")
                || has_token(b"IMAP4rev2")) =>
        {
            Some(Application::Imap)
        }
        b"+OK" if has_token(b"POP3") => Some(Application::Pop3),
        _ => None,
    }
}

pub(super) async fn inside_tls(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    alpn: Option<&[u8]>,
    authority: &str,
    deadline: Instant,
) -> Option<Application> {
    match alpn {
        Some(b"h2" | b"http/1.1") => return Some(Application::Http),
        Some(_) => return None,
        None => {}
    }

    let now = Instant::now();
    if now >= deadline {
        return None;
    }
    match passive(stream, (now + GREETING_WINDOW).min(deadline)).await {
        Greeting::Recognized(application) => Some(application),
        Greeting::Silent if Instant::now() < deadline => http(stream, authority, deadline)
            .await
            .then_some(Application::Http),
        _ => None,
    }
}

pub(super) async fn http(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    authority: &str,
    deadline: Instant,
) -> bool {
    async fn exchange(
        stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
        authority: &str,
    ) -> io::Result<bool> {
        let request = format!("HEAD / HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;
        let mut input = [0; 1024];
        let mut end = 0;
        while end < input.len() {
            let count = stream.read(&mut input[end..]).await?;
            if count == 0 {
                break;
            }
            if let Some(newline) = input[end..end + count]
                .iter()
                .position(|&byte| byte == b'\n')
            {
                return Ok(http_status(&input[..end + newline]));
            }
            end += count;
        }
        Ok(false)
    }

    matches!(
        tokio::time::timeout_at(deadline, exchange(stream, authority)).await,
        Ok(Ok(true))
    )
}

fn http_status(line: &[u8]) -> bool {
    let Some(line) = line.strip_suffix(b"\r") else {
        return false;
    };
    let Some(status) = line
        .strip_prefix(b"HTTP/1.1 ")
        .or_else(|| line.strip_prefix(b"HTTP/1.0 "))
    else {
        return false;
    };
    matches!(status, [b'1'..=b'5', b'0'..=b'9', b'0'..=b'9', b' ', ..])
        && status[4..]
            .iter()
            .all(|&byte| byte == b'\t' || (byte >= b' ' && byte != 127))
}

fn decimal(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.iter().all(u8::is_ascii_digit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[test]
    fn tls_application_labels_and_comparison_use_transport() {
        let imaps = Detected::Tls(Some(Application::Imap));
        let pop3s = Detected::Tls(Some(Application::Pop3));
        let smtps = Detected::Tls(Some(Application::Smtp));
        let https = Detected::Tls(Some(Application::Http));
        assert_eq!(imaps.to_string(), "IMAPS");
        assert_eq!(pop3s.to_string(), "POP3S");
        assert_eq!(smtps.to_string(), "SMTP over TLS");
        assert_eq!(https.to_string(), "HTTPS");
        assert_eq!(imaps.comparison(Protocol::Tls), Some(true));
        assert_eq!(https.comparison(Protocol::Tls), Some(true));
        assert_eq!(https.comparison(Protocol::Https), Some(true));
        assert_eq!(imaps.comparison(Protocol::Https), Some(false));
        assert_eq!(imaps.comparison(Protocol::Http), Some(false));
        assert_eq!(
            Detected::Plain(Application::Http).comparison(Protocol::Tls),
            Some(false)
        );
        assert_eq!(Detected::Tls(None).comparison(Protocol::Https), None);
        assert_eq!(imaps.comparison(Protocol::Autodetect), None);
    }

    #[tokio::test]
    async fn tls_inspection_uses_alpn_without_reading_or_writing() {
        for (alpn, expected) in [
            (&b"h2"[..], Some(Application::Http)),
            (&b"http/1.1"[..], Some(Application::Http)),
            (&b"imap"[..], None),
        ] {
            let (mut client, _server) = duplex(256);
            assert_eq!(
                inside_tls(&mut client, Some(alpn), "example.com", Instant::now()).await,
                expected
            );
        }
    }

    #[tokio::test]
    async fn tls_greetings_are_classified_without_sending_http() {
        for (greeting, expected) in [
            (
                &b"* OK [CAPABILITY IMAP4rev1] ready\r\n"[..],
                Some(Application::Imap),
            ),
            (&b"+OK POP3 ready\r\n"[..], Some(Application::Pop3)),
            (&b"220 ready\r\n"[..], None),
            (&b"+OK POP3"[..], None),
        ] {
            let (mut client, mut server) = duplex(256);
            server.write_all(greeting).await.unwrap();
            let result = inside_tls(
                &mut client,
                None,
                "example.com",
                Instant::now() + Duration::from_secs(2),
            )
            .await;
            assert_eq!(result, expected);
            drop(client);
            assert_eq!(server.read(&mut [0]).await.unwrap(), 0);
        }
    }

    #[tokio::test]
    async fn tls_inspection_does_not_write_after_eof_or_deadline() {
        for eof in [true, false] {
            let (mut client, mut server) = duplex(256);
            if eof {
                server.shutdown().await.unwrap();
            }
            let deadline = Instant::now() + Duration::from_millis(30);
            assert_eq!(
                inside_tls(&mut client, None, "example.com", deadline).await,
                None
            );
            drop(client);
            assert_eq!(server.read(&mut [0]).await.unwrap(), 0);
        }
    }

    #[tokio::test]
    async fn a_silent_tls_stream_can_be_identified_by_http() {
        let (mut client, mut server) = duplex(256);
        let request = b"HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
        let serve = async {
            let mut input = vec![0; request.len()];
            server.read_exact(&mut input).await.unwrap();
            assert_eq!(input, request);
            server.write_all(b"HTTP/1.1 200 OK\r\n").await.unwrap();
        };
        let deadline = Instant::now() + Duration::from_secs(2);
        let (result, ()) = timeout_at(deadline, async {
            tokio::join!(
                inside_tls(&mut client, None, "example.com", deadline),
                serve
            )
        })
        .await
        .unwrap();
        assert_eq!(result, Some(Application::Http));
    }

    #[test]
    fn recognizes_protocol_specific_greetings() {
        for (line, detected) in [
            ("SSH-2.0-OpenSSH", Application::Ssh),
            ("220 mail.example ESMTP ready", Application::Smtp),
            ("220 FTP service ready", Application::Ftp),
            ("* OK [CAPABILITY IMAP4rev1] ready", Application::Imap),
            ("+OK POP3 ready", Application::Pop3),
        ] {
            assert_eq!(greeting(line.as_bytes()), Some(detected));
        }
        for line in [
            "220 ready",
            "220 FTP SMTP",
            "* OK Ready",
            "+OK Ready",
            "SSH-2.-x",
            "SSH-2.0-",
        ] {
            assert_eq!(greeting(line.as_bytes()), None);
        }
    }

    #[test]
    fn accepts_only_complete_http_status_lines() {
        assert!(http_status(b"HTTP/1.1 405 Method Not Allowed\r"));
        assert!(http_status(b"HTTP/1.0 302 Found\r"));
        assert!(!http_status(b"HTTP/1.1 200"));
        assert!(!http_status(b"HTTP/1.1 2000 OK\r"));
    }
}
