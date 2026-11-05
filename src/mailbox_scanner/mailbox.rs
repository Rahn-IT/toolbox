//! Certificate-checked IMAP access with UID identity and tagged acknowledgments.

use std::collections::HashSet;
use std::fmt;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use async_imap::imap_proto;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, rustls};

use crate::mailbox_scanner::core::{config, message};

/// Largest original message accepted for scanning or download.
pub const MAX_MESSAGE: usize = crate::mailbox_scanner::core::limits::MESSAGE_BYTES;
const CHUNK: usize = 1024 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_FOLDERS: usize = 4096;
const MAX_UIDS: usize = 100_000;

/// Mailbox transport, identity, protocol and server rejection failures.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("IMAP transport failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("IMAP operation failed: {0}")]
    Imap(#[from] async_imap::error::Error),
    #[error("IMAP authentication failed; check the account credentials")]
    Authentication(#[source] async_imap::error::Error),
    #[error("Invalid TLS server name")]
    ServerName,
    #[error("IMAP {0} timed out")]
    Timeout(&'static str),
    #[error("IMAP server rejected {operation}: {status}")]
    Rejected {
        operation: &'static str,
        status: &'static str,
    },
    #[error("Unexpected IMAP response: {0}")]
    Unexpected(&'static str),
    #[error("The mailbox UIDVALIDITY changed; scan this folder again")]
    Stale,
    #[error("The message is no longer in its original IMAP folder")]
    Missing,
    #[error("Message exceeds the 200 MiB limit ({0} bytes)")]
    Oversize(u64),
    #[error("The server did not provide a reliable message size")]
    Size,
    #[error("Folder or UID discovery limit exceeded: {0}")]
    Limit(&'static str),
    #[error("Invalid IMAP folder name: {0}")]
    Folder(#[from] message::Error),
    #[error("The selected account does not match the scanned message")]
    Account,
    #[error("The IMAP connection was interrupted and must be reopened")]
    Disconnected,
    #[error("This server does not support selective UID expunge")]
    UnsupportedPurge,
    #[error("The selected folder is read-only")]
    ReadOnly,
}

/// Stable UIDs captured from one examined folder.
#[derive(Debug)]
pub struct Snapshot {
    pub folder: message::Folder,
    pub uidvalidity: NonZeroU32,
    pub uids: Vec<NonZeroU32>,
}

/// Relevant flags of an exact UID, independent of sequence numbers.
#[derive(Debug, Clone, Copy)]
pub struct Flags {
    pub deleted: bool,
}

struct Selected {
    folder: message::Folder,
    uidvalidity: NonZeroU32,
    writable: bool,
}

/// One authenticated connection; interrupted commands discard its session.
pub struct Client<T = tokio_rustls::client::TlsStream<TcpStream>>
where
    T: AsyncRead + AsyncWrite + Unpin + fmt::Debug + Send,
{
    session: Option<async_imap::Session<T>>,
    account: message::Account,
    selected: Option<Selected>,
    purge: bool,
}

#[cfg(test)]
impl Client<tokio::io::DuplexStream> {
    /// Authenticate only the in-memory scripted peer with fixed dummy credentials.
    pub(crate) async fn scripted(
        stream: tokio::io::DuplexStream,
        account: message::Account,
        purge: bool,
    ) -> Result<Self, Error> {
        let mut client = async_imap::Client::new(stream);
        greeting(&mut client).await?;
        let session = client
            .login("user", "password")
            .await
            .map_err(|(error, _)| Error::Authentication(error))?;
        Ok(Self {
            session: Some(session),
            account,
            selected: None,
            purge,
        })
    }
}

impl Client {
    /// Connect and authenticate only after a certificate-validated TLS handshake.
    pub async fn connect(settings: &config::Settings) -> Result<Self, Error> {
        let tcp = deadline(
            "connection",
            TcpStream::connect((settings.host(), settings.port())),
        )
        .await??;
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(tls));
        let name = rustls::pki_types::ServerName::try_from(settings.host().to_owned())
            .map_err(|_| Error::ServerName)?;

        let mut client = match settings.tls() {
            config::Tls::Implicit => {
                let stream = deadline("TLS handshake", connector.connect(name, tcp)).await??;
                let mut client = async_imap::Client::new(stream);
                greeting(&mut client).await?;
                client
            }
            config::Tls::StartTls => {
                let mut client = async_imap::Client::new(tcp);
                greeting(&mut client).await?;
                deadline(
                    "STARTTLS",
                    client.run_command_and_check_ok("STARTTLS", None),
                )
                .await??;
                let stream = deadline(
                    "TLS handshake",
                    connector.connect(name, client.into_inner()),
                )
                .await??;
                // STARTTLS upgrades the existing session: there is no second greeting.
                async_imap::Client::new(stream)
            }
        };
        deadline(
            "post-TLS capabilities",
            client.run_command_and_check_ok("CAPABILITY", None),
        )
        .await??;
        let session = deadline(
            "authentication",
            client.login(settings.username(), settings.password()),
        )
        .await?
        .map_err(|(error, _)| Error::Authentication(error))?;
        let mut client = Self {
            session: Some(session),
            account: message::Account::from_settings(settings),
            selected: None,
            purge: false,
        };
        client.capabilities().await?;
        Ok(client)
    }
}

impl<T> Client<T>
where
    T: AsyncRead + AsyncWrite + Unpin + fmt::Debug + Send,
{
    /// Whether this authenticated server supports targeted UID expunge.
    pub fn supports_purge(&self) -> bool {
        self.purge
    }

    /// List every selectable folder, including folders not subscribed to.
    pub async fn folders(&mut self) -> Result<Vec<message::Folder>, Error> {
        let mut folders = Vec::new();
        let mut names = HashSet::new();
        self.command("folder listing", "LIST \"\" \"*\"", |response| {
            if let imap_proto::Response::MailboxData(imap_proto::MailboxDatum::List(data)) =
                response
            {
                if data
                    .name_attributes
                    .iter()
                    .any(|attribute| matches!(attribute, imap_proto::NameAttribute::NoSelect))
                {
                    return Ok(());
                }
                if names.insert(data.name.to_string()) {
                    if folders.len() == MAX_FOLDERS {
                        return Err(Error::Limit("more than 4096 selectable folders"));
                    }
                    let display = display_folder(&data.name);
                    folders.push(message::Folder::new(data.name.to_string(), display)?);
                }
            }
            Ok(())
        })
        .await?;
        Ok(folders)
    }

    /// Examine a folder and snapshot all its current UIDs without changing flags.
    pub async fn snapshot(&mut self, folder: &message::Folder) -> Result<Snapshot, Error> {
        let uidvalidity = self.open_folder(folder, false).await?;
        let mut uids = Vec::new();
        let mut found = false;
        self.command("UID search", "UID SEARCH ALL", |response| {
            if let imap_proto::Response::MailboxData(imap_proto::MailboxDatum::Search(values)) =
                response
            {
                found = true;
                if uids.len().saturating_add(values.len()) > MAX_UIDS {
                    return Err(Error::Limit("more than 100000 UIDs in one folder"));
                }
                for uid in values {
                    uids.push(NonZeroU32::new(*uid).ok_or(Error::Unexpected("UID zero"))?);
                }
            }
            Ok(())
        })
        .await?;
        if !found {
            return Err(Error::Unexpected("missing UID SEARCH result"));
        }
        uids.sort_unstable();
        uids.dedup();
        Ok(Snapshot {
            folder: folder.clone(),
            uidvalidity,
            uids,
        })
    }

    /// Select the exact scanned folder and reject changed UIDVALIDITY or account.
    pub async fn open(
        &mut self,
        identity: &message::Identity,
        writable: bool,
    ) -> Result<(), Error> {
        self.check_account(identity)?;
        let validity = self.open_folder(identity.folder(), writable).await?;
        if validity.get() != identity.uidvalidity() {
            self.session.take();
            self.selected = None;
            return Err(Error::Stale);
        }
        Ok(())
    }

    /// Fetch unchanged EML bytes in bounded, UID/origin-checked BODY.PEEK chunks.
    pub async fn fetch(&mut self, identity: &message::Identity) -> Result<Vec<u8>, Error> {
        self.check_selected(identity, false)?;
        match tokio::time::timeout(DOWNLOAD_TIMEOUT, self.fetch_inner(identity)).await {
            Ok(result) => result,
            Err(_) => {
                self.session.take();
                Err(Error::Timeout("message download"))
            }
        }
    }

    /// Get flags for the exact selected UID; None means the UID is absent.
    pub async fn flags(&mut self, identity: &message::Identity) -> Result<Option<Flags>, Error> {
        self.check_selected(identity, false)?;
        let uid = identity.uid();
        let mut result = None;
        let mut present = false;
        let command = format!("UID FETCH {uid} (UID FLAGS)");
        self.command("UID flags", &command, |response| {
            if let imap_proto::Response::Fetch(_, attributes) = response
                && response_uid(attributes)? == Some(uid)
            {
                present = true;
                for attribute in attributes {
                    if let imap_proto::AttributeValue::Flags(flags) = attribute {
                        if result.is_some() {
                            return Err(Error::Unexpected("duplicate flags for requested UID"));
                        }
                        result = Some(Flags {
                            deleted: flags
                                .iter()
                                .any(|flag| flag.eq_ignore_ascii_case("\\Deleted")),
                        });
                    }
                }
            }
            Ok(())
        })
        .await?;
        if present && result.is_none() {
            return Err(Error::Unexpected("requested UID omitted its flags"));
        }
        Ok(result)
    }

    /// Mark only the specified UID deleted after the caller verifies quarantine.
    pub async fn mark_deleted(&mut self, identity: &message::Identity) -> Result<(), Error> {
        self.check_selected(identity, true)?;
        if !self.purge {
            return Err(Error::UnsupportedPurge);
        }
        self.command(
            "mark deleted",
            &format!("UID STORE {} +FLAGS.SILENT (\\Deleted)", identity.uid()),
            |_| Ok(()),
        )
        .await
    }

    /// Expunge only the specified UID, never unrelated previously deleted mail.
    pub async fn expunge(&mut self, identity: &message::Identity) -> Result<(), Error> {
        self.check_selected(identity, true)?;
        if !self.purge {
            return Err(Error::UnsupportedPurge);
        }
        self.command(
            "UID expunge",
            &format!("UID EXPUNGE {}", identity.uid()),
            |_| Ok(()),
        )
        .await
    }

    /// Log out without CLOSE or a broad expunge.
    pub async fn logout(&mut self) -> Result<(), Error> {
        let result = self.command("logout", "LOGOUT", |_| Ok(())).await;
        self.session.take();
        result
    }

    async fn capabilities(&mut self) -> Result<(), Error> {
        let mut supported = false;
        self.command("capabilities", "CAPABILITY", |response| {
            if let imap_proto::Response::Capabilities(capabilities) = response {
                supported = capabilities.iter().any(|capability| match capability {
                    imap_proto::Capability::Atom(atom) => {
                        atom.eq_ignore_ascii_case("UIDPLUS")
                            || atom.eq_ignore_ascii_case("IMAP4rev2")
                    }
                    _ => false,
                });
            }
            Ok(())
        })
        .await?;
        self.purge = supported;
        Ok(())
    }

    async fn open_folder(
        &mut self,
        folder: &message::Folder,
        writable: bool,
    ) -> Result<NonZeroU32, Error> {
        self.selected = None;
        let command = format!(
            "{} {}",
            if writable { "SELECT" } else { "EXAMINE" },
            quoted(folder.wire())
        );
        let mut validity = None;
        let mut read_only = !writable;
        self.command("folder selection", &command, |response| {
            let code = match response {
                imap_proto::Response::Data { outcome, .. }
                | imap_proto::Response::Done { outcome, .. } => outcome.code.as_ref(),
                _ => None,
            };
            match code {
                Some(imap_proto::ResponseCode::UidValidity(value)) => {
                    let value =
                        NonZeroU32::new(*value).ok_or(Error::Unexpected("UIDVALIDITY zero"))?;
                    if validity.is_some_and(|previous| previous != value) {
                        return Err(Error::Stale);
                    }
                    validity = Some(value);
                }
                Some(imap_proto::ResponseCode::ReadOnly) => read_only = true,
                Some(imap_proto::ResponseCode::ReadWrite) => read_only = false,
                _ => {}
            }
            Ok(())
        })
        .await?;
        let uidvalidity = validity.ok_or(Error::Unexpected("missing UIDVALIDITY"))?;
        if writable && read_only {
            return Err(Error::ReadOnly);
        }
        self.selected = Some(Selected {
            folder: folder.clone(),
            uidvalidity,
            writable,
        });
        Ok(uidvalidity)
    }

    async fn fetch_inner(&mut self, identity: &message::Identity) -> Result<Vec<u8>, Error> {
        let uid = identity.uid();
        let mut size = None;
        self.command(
            "message size",
            &format!("UID FETCH {uid} (UID RFC822.SIZE)"),
            |response| {
                if let imap_proto::Response::Fetch(_, attributes) = response
                    && response_uid(attributes)? == Some(uid)
                {
                    for attribute in attributes {
                        if let imap_proto::AttributeValue::Rfc822Size(value) = attribute
                            && size.replace(*value).is_some()
                        {
                            return Err(Error::Unexpected("duplicate message size"));
                        }
                    }
                }
                Ok(())
            },
        )
        .await?;
        let size = match size {
            Some(size) => size as usize,
            None => {
                return Err(if self.flags(identity).await?.is_none() {
                    Error::Missing
                } else {
                    Error::Size
                });
            }
        };
        if size > MAX_MESSAGE {
            return Err(Error::Oversize(size as u64));
        }
        let mut bytes = Vec::with_capacity(size);
        while bytes.len() < size {
            let origin = bytes.len();
            let length = CHUNK.min(size - origin);
            let mut found = false;
            self.command(
                "message body",
                &format!("UID FETCH {uid} (UID BODY.PEEK[]<{origin}.{length}>)"),
                |response| {
                    if let imap_proto::Response::Fetch(_, attributes) = response {
                        let actual_uid = response_uid(attributes)?;
                        for attribute in attributes {
                            if let imap_proto::AttributeValue::BodySection {
                                section,
                                index,
                                data,
                            } = attribute
                            {
                                if actual_uid != Some(uid) {
                                    return Err(Error::Unexpected(
                                        "body returned for a foreign or missing UID",
                                    ));
                                }
                                if section.is_some() || *index != Some(origin as u32) || found {
                                    return Err(Error::Unexpected(
                                        "wrong or duplicate partial body origin",
                                    ));
                                }
                                let data = data
                                    .as_deref()
                                    .ok_or(Error::Unexpected("NIL message body"))?;
                                if data.len() != length {
                                    return Err(Error::Unexpected(
                                        "truncated or oversized body chunk",
                                    ));
                                }
                                bytes.extend_from_slice(data);
                                found = true;
                            }
                        }
                    }
                    Ok(())
                },
            )
            .await?;
            if !found {
                return Err(if self.flags(identity).await?.is_none() {
                    Error::Missing
                } else {
                    Error::Unexpected("missing requested body")
                });
            }
        }
        Ok(bytes)
    }

    fn check_account(&self, identity: &message::Identity) -> Result<(), Error> {
        if identity.account() != &self.account {
            return Err(Error::Account);
        }
        Ok(())
    }

    fn check_selected(&self, identity: &message::Identity, writable: bool) -> Result<(), Error> {
        self.check_account(identity)?;
        let selected = self.selected.as_ref().ok_or(Error::Disconnected)?;
        if selected.folder.wire() != identity.folder().wire()
            || selected.uidvalidity.get() != identity.uidvalidity()
        {
            return Err(Error::Stale);
        }
        if writable && !selected.writable {
            return Err(Error::ReadOnly);
        }
        Ok(())
    }

    async fn command<F>(
        &mut self,
        operation: &'static str,
        command: &str,
        mut receive: F,
    ) -> Result<(), Error>
    where
        F: FnMut(&imap_proto::Response<'_>) -> Result<(), Error>,
    {
        // Taking ownership before awaiting makes dropped/cancelled commands close
        // the stream instead of leaving an unread response tail for a later call.
        let mut session = self.session.take().ok_or(Error::Disconnected)?;
        let expected_validity = self.selected.as_ref().map(|selected| selected.uidvalidity);
        let result = deadline(operation, async {
            let tag = session.run_command(command).await?;
            loop {
                let response = session.read_response().await?.ok_or(Error::Disconnected)?;
                let response = response.parsed();
                if let imap_proto::Response::Data {
                    status: imap_proto::Status::Bye,
                    ..
                } = response
                    && command != "LOGOUT"
                {
                    return Err(Error::Disconnected);
                }
                if let imap_proto::Response::Data { status, .. } = response
                    && matches!(status, imap_proto::Status::No | imap_proto::Status::Bad)
                {
                    return Err(Error::Rejected {
                        operation,
                        status: status_name(status),
                    });
                }
                if matches!(response, imap_proto::Response::Continue(_)) {
                    return Err(Error::Unexpected("unexpected command continuation"));
                }
                let code = match response {
                    imap_proto::Response::Data { outcome, .. }
                    | imap_proto::Response::Done { outcome, .. } => outcome.code.as_ref(),
                    _ => None,
                };
                if let Some(imap_proto::ResponseCode::UidValidity(value)) = code
                    && expected_validity.is_some_and(|expected| expected.get() != *value)
                {
                    return Err(Error::Stale);
                }
                if let imap_proto::Response::Done {
                    tag: actual,
                    status,
                    ..
                } = response
                {
                    if actual != &tag {
                        return Err(Error::Unexpected("mismatched command completion tag"));
                    }
                    if *status != imap_proto::Status::Ok {
                        return Err(Error::Rejected {
                            operation,
                            status: status_name(status),
                        });
                    }
                    receive(response)?;
                    return Ok(());
                }
                receive(response)?;
            }
        })
        .await?;
        if result.is_ok() {
            self.session = Some(session);
        }
        result
    }
}

async fn deadline<F: std::future::Future>(
    operation: &'static str,
    future: F,
) -> Result<F::Output, Error> {
    tokio::time::timeout(COMMAND_TIMEOUT, future)
        .await
        .map_err(|_| Error::Timeout(operation))
}

async fn greeting<T>(client: &mut async_imap::Client<T>) -> Result<(), Error>
where
    T: AsyncRead + AsyncWrite + Unpin + fmt::Debug + Send,
{
    let response = deadline("greeting", client.read_response())
        .await??
        .ok_or(Error::Disconnected)?;
    match response.parsed() {
        imap_proto::Response::Data {
            status: imap_proto::Status::Ok,
            ..
        } => Ok(()),
        imap_proto::Response::Data {
            status: imap_proto::Status::PreAuth,
            ..
        } => Err(Error::Unexpected(
            "PREAUTH is not supported by password-login setup",
        )),
        _ => Err(Error::Unexpected("expected one OK greeting")),
    }
}

fn response_uid(attributes: &[imap_proto::AttributeValue<'_>]) -> Result<Option<u32>, Error> {
    let mut uid = None;
    for attribute in attributes {
        if let imap_proto::AttributeValue::Uid(value) = attribute
            && (*value == 0 || uid.replace(*value).is_some())
        {
            return Err(Error::Unexpected("zero or duplicate UID attribute"));
        }
    }
    Ok(uid)
}

fn status_name(status: &imap_proto::Status) -> &'static str {
    match status {
        imap_proto::Status::Ok => "OK",
        imap_proto::Status::No => "NO",
        imap_proto::Status::Bad => "BAD",
        imap_proto::Status::PreAuth => "PREAUTH",
        imap_proto::Status::Bye => "BYE",
    }
}

fn quoted(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn display_folder(wire: &str) -> String {
    decode_folder(wire).unwrap_or_else(|| wire.escape_debug().to_string())
}

fn decode_folder(wire: &str) -> Option<String> {
    if wire.len() > 8192 {
        return None;
    }
    let mut display = String::new();
    let mut rest = wire;
    while let Some(start) = rest.find('&') {
        display.push_str(&rest[..start]);
        rest = &rest[start + 1..];
        let end = rest.find('-')?;
        if end == 0 {
            display.push('&');
        } else {
            let mut accumulator = 0_u32;
            let mut bits = 0_u8;
            let mut bytes = Vec::new();
            for byte in rest[..end].bytes() {
                let digit = match byte {
                    b'A'..=b'Z' => byte - b'A',
                    b'a'..=b'z' => byte - b'a' + 26,
                    b'0'..=b'9' => byte - b'0' + 52,
                    b'+' => 62,
                    b',' => 63,
                    _ => return None,
                };
                accumulator = (accumulator << 6) | u32::from(digit);
                bits += 6;
                if bits >= 8 {
                    bits -= 8;
                    bytes.push((accumulator >> bits) as u8);
                    accumulator &= (1_u32 << bits) - 1;
                }
            }
            if bytes.is_empty() || bytes.len() % 2 != 0 || accumulator != 0 || bits == 6 {
                return None;
            }
            let words = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_be_bytes([pair[0], pair[1]]));
            for character in char::decode_utf16(words) {
                display.push(character.ok()?);
            }
        }
        rest = &rest[end + 1..];
    }
    display.push_str(rest);
    Some(display)
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};

    use super::{Client, Error, decode_folder, greeting, quoted};
    use crate::mailbox_scanner::core::{config, message};

    fn settings() -> config::Settings {
        config::Settings::try_from(config::Draft {
            host: "example.org".into(),
            username: "user".into(),
            password: "password".into(),
            scan_dir: "scan".into(),
            quarantine_dir: "quarantine".into(),
            ..config::Draft::default()
        })
        .unwrap()
    }

    fn folder() -> message::Folder {
        message::Folder::new("INBOX".into(), "INBOX".into()).unwrap()
    }

    fn identity() -> message::Identity {
        message::Identity::new(
            message::Account::from_settings(&settings()),
            folder(),
            NonZeroU32::new(7).unwrap(),
            NonZeroU32::new(9).unwrap(),
        )
    }

    async fn scripted(
        steps: Vec<(&'static str, &'static str)>,
    ) -> (Client<DuplexStream>, tokio::task::JoinHandle<()>) {
        let (stream, peer) = tokio::io::duplex(4096);
        let peer = tokio::spawn(async move {
            let mut peer = BufReader::new(peer);
            peer.write_all(b"* OK test peer\r\n").await.unwrap();
            let mut commands = vec![("LOGIN \"user\" \"password\"", "{tag} OK logged in\r\n")];
            commands.extend(steps);
            for (expected, reply) in commands {
                let mut line = String::new();
                peer.read_line(&mut line).await.unwrap();
                let (tag, actual) = line.trim_end_matches(['\r', '\n']).split_once(' ').unwrap();
                assert_eq!(actual, expected);
                peer.write_all(reply.replace("{tag}", tag).as_bytes())
                    .await
                    .unwrap();
            }
        });
        (
            Client::scripted(stream, message::Account::from_settings(&settings()), false)
                .await
                .unwrap(),
            peer,
        )
    }

    const EXAMINE: (&str, &str) = (
        "EXAMINE \"INBOX\"",
        "* 2 EXISTS\r\n* OK [UIDVALIDITY 7] stable\r\n{tag} OK [READ-ONLY] examined\r\n",
    );
    const SELECT: (&str, &str) = (
        "SELECT \"INBOX\"",
        "* 2 EXISTS\r\n* OK [UIDVALIDITY 7] stable\r\n{tag} OK [READ-WRITE] selected\r\n",
    );
    const SIZE: (&str, &str) = (
        "UID FETCH 9 (UID RFC822.SIZE)",
        "* 2 FETCH (UID 9 RFC822.SIZE 4)\r\n{tag} OK size\r\n",
    );

    #[tokio::test]
    async fn messages_above_the_old_limit_and_at_200_mib_reach_body_fetch() {
        for response in [
            "* 2 FETCH (UID 9 RFC822.SIZE 27262976)\r\n{tag} OK size\r\n",
            "* 2 FETCH (UID 9 RFC822.SIZE 209715200)\r\n{tag} OK size\r\n",
        ] {
            let (mut client, peer) = scripted(vec![
                EXAMINE,
                ("UID FETCH 9 (UID RFC822.SIZE)", response),
                (
                    "UID FETCH 9 (UID BODY.PEEK[]<0.1048576>)",
                    "{tag} NO stop after preflight\r\n",
                ),
            ])
            .await;
            client.open(&identity(), false).await.unwrap();
            assert!(matches!(
                client.fetch(&identity()).await,
                Err(Error::Rejected {
                    operation: "message body",
                    ..
                })
            ));
            peer.await.unwrap();
        }
    }

    #[tokio::test]
    async fn over_200_mib_is_rejected_before_fetching_a_body() {
        let (mut client, peer) = scripted(vec![
            EXAMINE,
            (
                "UID FETCH 9 (UID RFC822.SIZE)",
                "* 2 FETCH (UID 9 RFC822.SIZE 209715201)\r\n{tag} OK size\r\n",
            ),
        ])
        .await;
        client.open(&identity(), false).await.unwrap();
        assert!(matches!(
            client.fetch(&identity()).await,
            Err(Error::Oversize(209715201))
        ));
        peer.await.unwrap();
    }

    #[test]
    fn folder_display_preserves_wire_semantics_and_handles_modified_utf7() {
        assert_eq!(decode_folder("Mail.&AOQ-"), Some("Mail.ä".into()));
        assert_eq!(decode_folder("A&-B"), Some("A&B".into()));
        assert_eq!(decode_folder("&ZeVnLIqe-"), Some("日本語".into()));
        assert_eq!(decode_folder("&2D3eAA-"), Some("😀".into()));
        for malformed in ["&", "&A-", "&AA-", "&!!!-", "&2AA-"] {
            assert_eq!(decode_folder(malformed), None);
        }
        assert_eq!(quoted("a\\b\"c"), "\"a\\\\b\\\"c\"");
    }

    #[tokio::test]
    async fn rejected_list_does_not_become_an_empty_mailbox() {
        let (mut client, peer) =
            scripted(vec![("LIST \"\" \"*\"", "{tag} NO not permitted\r\n")]).await;
        assert!(matches!(
            client.folders().await,
            Err(Error::Rejected {
                operation: "folder listing",
                ..
            })
        ));
        assert!(client.session.is_none());
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn lists_unsubscribed_selectable_folders_and_decodes_only_display() {
        let (mut client, peer) = scripted(vec![(
            "LIST \"\" \"*\"",
            "* LIST (\\Noselect) \".\" \"container\"\r\n* LIST () \".\" \"Mail.&AOQ-\"\r\n* LIST () NIL \"INBOX\"\r\n{tag} OK listed\r\n",
        )]).await;
        let folders = client.folders().await.unwrap();
        assert_eq!(folders.len(), 2);
        assert_eq!(folders[0].wire(), "Mail.&AOQ-");
        assert_eq!(folders[0].display(), "Mail.ä");
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn rejected_search_does_not_become_an_empty_snapshot() {
        let (mut client, peer) = scripted(vec![
            EXAMINE,
            ("UID SEARCH ALL", "{tag} BAD cannot search\r\n"),
        ])
        .await;
        assert!(matches!(
            client.snapshot(&folder()).await,
            Err(Error::Rejected {
                operation: "UID search",
                ..
            })
        ));
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn missing_search_data_is_not_an_empty_snapshot() {
        let (mut client, peer) = scripted(vec![
            EXAMINE,
            ("UID SEARCH ALL", "{tag} OK no result data\r\n"),
        ])
        .await;
        assert!(matches!(
            client.snapshot(&folder()).await,
            Err(Error::Unexpected("missing UID SEARCH result"))
        ));
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn untagged_rejection_does_not_become_a_successful_listing() {
        let (mut client, peer) = scripted(vec![(
            "LIST \"\" \"*\"",
            "* NO listing unavailable\r\n{tag} OK done\r\n",
        )])
        .await;
        assert!(matches!(
            client.folders().await,
            Err(Error::Rejected {
                operation: "folder listing",
                ..
            })
        ));
        assert!(client.session.is_none());
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn uidvalidity_change_prevents_fetching_a_reused_uid() {
        let (mut client, peer) = scripted(vec![(
            "EXAMINE \"INBOX\"",
            "* OK [UIDVALIDITY 8] changed\r\n{tag} OK selected\r\n",
        )])
        .await;
        assert!(matches!(
            client.open(&identity(), false).await,
            Err(Error::Stale)
        ));
        assert!(client.session.is_none());
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn fetches_the_exact_uid_with_peek_and_checks_completion() {
        let (mut client, peer) = scripted(vec![EXAMINE, SIZE, (
            "UID FETCH 9 (UID BODY.PEEK[]<0.4>)",
            "* 1 EXISTS\r\n* 7 FETCH (FLAGS (\\Seen))\r\n* 2 FETCH (UID 9 BODY[]<0> {4}\r\neml!)\r\n{tag} OK fetched\r\n",
        )]).await;
        client.open(&identity(), false).await.unwrap();
        assert_eq!(client.fetch(&identity()).await.unwrap(), b"eml!");
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn wrong_partial_origin_is_not_accepted_as_a_complete_eml() {
        let (mut client, peer) = scripted(vec![
            EXAMINE,
            SIZE,
            (
                "UID FETCH 9 (UID BODY.PEEK[]<0.4>)",
                "* 2 FETCH (UID 9 BODY[]<1> {4}\r\neml!)\r\n{tag} OK fetched\r\n",
            ),
        ])
        .await;
        client.open(&identity(), false).await.unwrap();
        assert!(matches!(
            client.fetch(&identity()).await,
            Err(Error::Unexpected("wrong or duplicate partial body origin"))
        ));
        assert!(client.session.is_none());
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn a_body_followed_by_tagged_no_is_not_a_successful_download() {
        let (mut client, peer) = scripted(vec![
            EXAMINE,
            SIZE,
            (
                "UID FETCH 9 (UID BODY.PEEK[]<0.4>)",
                "* 2 FETCH (UID 9 BODY[]<0> {4}\r\neml!)\r\n{tag} NO incomplete request\r\n",
            ),
        ])
        .await;
        client.open(&identity(), false).await.unwrap();
        assert!(matches!(
            client.fetch(&identity()).await,
            Err(Error::Rejected {
                operation: "message body",
                ..
            })
        ));
        assert!(client.session.is_none());
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn short_final_chunk_is_not_a_complete_eml() {
        let (mut client, peer) = scripted(vec![
            EXAMINE,
            SIZE,
            (
                "UID FETCH 9 (UID BODY.PEEK[]<0.4>)",
                "* 2 FETCH (UID 9 BODY[]<0> {3}\r\neml)\r\n{tag} OK fetched\r\n",
            ),
        ])
        .await;
        client.open(&identity(), false).await.unwrap();
        assert!(matches!(
            client.fetch(&identity()).await,
            Err(Error::Unexpected("truncated or oversized body chunk"))
        ));
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn foreign_uid_body_is_not_substituted_for_requested_mail() {
        let (mut client, peer) = scripted(vec![
            EXAMINE,
            SIZE,
            (
                "UID FETCH 9 (UID BODY.PEEK[]<0.4>)",
                "* 2 FETCH (UID 10 BODY[]<0> {4}\r\neml!)\r\n{tag} OK fetched\r\n",
            ),
        ])
        .await;
        client.open(&identity(), false).await.unwrap();
        assert!(matches!(
            client.fetch(&identity()).await,
            Err(Error::Unexpected(
                "body returned for a foreign or missing UID"
            ))
        ));
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn rejected_expunge_cannot_be_reported_as_success() {
        let (mut client, peer) = scripted(vec![
            (
                "CAPABILITY",
                "* CAPABILITY IMAP4rev1 UIDPLUS\r\n{tag} OK caps\r\n",
            ),
            SELECT,
            (
                "UID STORE 9 +FLAGS.SILENT (\\Deleted)",
                "{tag} OK marked\r\n",
            ),
            ("UID EXPUNGE 9", "{tag} NO expunge denied\r\n"),
        ])
        .await;
        client.capabilities().await.unwrap();
        client.open(&identity(), true).await.unwrap();
        client.mark_deleted(&identity()).await.unwrap();
        assert!(matches!(
            client.expunge(&identity()).await,
            Err(Error::Rejected {
                operation: "UID expunge",
                ..
            })
        ));
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn unsupported_targeted_expunge_does_not_send_store() {
        let (mut client, peer) = scripted(vec![SELECT]).await;
        client.open(&identity(), true).await.unwrap();
        assert!(matches!(
            client.mark_deleted(&identity()).await,
            Err(Error::UnsupportedPurge)
        ));
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn rejected_store_is_not_treated_as_a_successful_mark() {
        let (mut client, peer) = scripted(vec![
            SELECT,
            (
                "UID STORE 9 +FLAGS.SILENT (\\Deleted)",
                "{tag} NO no write permission\r\n",
            ),
        ])
        .await;
        client.purge = true;
        client.open(&identity(), true).await.unwrap();
        assert!(matches!(
            client.mark_deleted(&identity()).await,
            Err(Error::Rejected {
                operation: "mark deleted",
                ..
            })
        ));
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn unexpected_preauth_greeting_is_rejected_without_login() {
        let (stream, mut peer) = tokio::io::duplex(1024);
        peer.write_all(b"* PREAUTH already authenticated\r\n")
            .await
            .unwrap();
        let mut client = async_imap::Client::new(stream);
        assert!(matches!(
            greeting(&mut client).await,
            Err(Error::Unexpected(
                "PREAUTH is not supported by password-login setup"
            ))
        ));
    }

    #[tokio::test]
    async fn cancelled_protocol_future_drops_the_session() {
        let (stream, mut peer) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move {
            peer.write_all(b"* OK test\r\n").await.unwrap();
            let mut peer = BufReader::new(peer);
            let mut line = String::new();
            peer.read_line(&mut line).await.unwrap();
            let tag = line.split_once(' ').unwrap().0;
            peer.write_all(format!("{tag} OK login\r\n").as_bytes())
                .await
                .unwrap();
            line.clear();
            peer.read_line(&mut line).await.unwrap();
            assert!(line.contains("LIST"));
            line.clear();
            assert_eq!(peer.read_line(&mut line).await.unwrap(), 0);
        });
        let mut raw = async_imap::Client::new(stream);
        greeting(&mut raw).await.unwrap();
        let session = raw.login("user", "password").await.unwrap();
        let mut client = Client {
            session: Some(session),
            account: message::Account::from_settings(&settings()),
            selected: None,
            purge: false,
        };
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(25), client.folders())
                .await
                .is_err()
        );
        assert!(client.session.is_none());
        server.await.unwrap();
    }
}
