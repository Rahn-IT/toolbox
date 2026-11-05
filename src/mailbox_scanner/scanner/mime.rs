//! Bounded MIME work on blocking workers, one decoded leaf at a time.

use std::sync::Arc;

use crate::mailbox_scanner::core::detection;

pub(super) const MAX_ORIGINAL: usize = crate::mailbox_scanner::core::limits::MESSAGE_BYTES;
const MAX_LEAF: usize = crate::mailbox_scanner::core::limits::MESSAGE_BYTES;
const MAX_TOTAL: usize = crate::mailbox_scanner::core::limits::DECODED_BYTES;

pub(super) struct Parsed {
    message: Arc<mail_parser::Message<'static>>,
    index: usize,
    decoded: usize,
}

pub(super) struct Leaf {
    pub bytes: Option<Vec<u8>>,
    pub issues: Vec<detection::Issue>,
}

#[derive(Debug, thiserror::Error)]
pub(super) enum Error {
    #[error("Mail has no parseable message structure")]
    Invalid,
    #[error("MIME worker failed: {0}")]
    Worker(#[from] tokio::task::JoinError),
}

impl Parsed {
    pub(super) async fn parse(raw: Vec<u8>) -> Result<Self, Error> {
        let message = tokio::task::spawn_blocking(move || {
            mail_parser::MessageParser::new()
                .max_depth(16)
                .max_parts(256)
                .max_encoded_nesting(3)
                .parse_owned(raw)
        })
        .await?
        .ok_or(Error::Invalid)?;
        Ok(Self {
            message: Arc::new(message),
            index: 0,
            decoded: 0,
        })
    }

    pub(super) async fn next(&mut self) -> Result<Option<Leaf>, Error> {
        if self.index >= self.message.parts().len() {
            return Ok(None);
        }
        let message = Arc::clone(&self.message);
        let index = self.index;
        self.index += 1;
        let mut leaf = tokio::task::spawn_blocking(move || decode(&message, index)).await?;
        if let Some(bytes) = &leaf.bytes {
            if self.decoded.saturating_add(bytes.len()) > MAX_TOTAL {
                leaf.bytes = None;
                leaf.issues.push(detection::Issue::Limit(
                    "Decoded MIME material exceeds 400 MiB",
                ));
                self.index = self.message.parts().len();
            } else {
                self.decoded += bytes.len();
            }
        }
        Ok(Some(leaf))
    }
}

fn decode(message: &mail_parser::Message<'_>, index: usize) -> Leaf {
    let mut leaf = Leaf {
        bytes: None,
        issues: Vec::new(),
    };
    let Some(part) = message.parts().nth(index) else {
        leaf.issues
            .push(detection::Issue::Decode("MIME part is unavailable".into()));
        return leaf;
    };
    if part.has_problems() {
        leaf.issues.push(detection::Issue::Decode(format!(
            "MIME structure is incomplete or exceeded parser limits: {:?}",
            part.flags()
        )));
    }
    if part.is_content_type("multipart", "encrypted")
        || part.is_content_type("application", "pkcs7-mime")
        || part.is_content_type("application", "x-pkcs7-mime")
    {
        leaf.issues.push(detection::Issue::Decode(
            "Encrypted MIME content cannot be fully inspected".into(),
        ));
    }
    if part.is_multipart() || part.is_message() {
        return leaf;
    }
    if part.decoded_len() > MAX_LEAF {
        leaf.issues.push(detection::Issue::Limit(
            "A decoded MIME part exceeds 200 MiB",
        ));
        return leaf;
    }
    let (bytes, problems) = part.decoded_checked();
    if !problems.is_empty() {
        leaf.issues.push(detection::Issue::Decode(format!(
            "MIME transfer decoding was incomplete: {problems:?}"
        )));
    }
    if bytes.len() > MAX_LEAF {
        leaf.issues.push(detection::Issue::Limit(
            "A decoded MIME part exceeds 200 MiB",
        ));
    } else if !bytes.is_empty() {
        leaf.bytes = Some(bytes.into_owned());
    }
    leaf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn decoded_parts_can_exceed_the_previous_part_and_total_limits() {
        let size = 26 * 1024 * 1024;
        let mut raw = b"From: test@example.invalid\r\nContent-Type: multipart/mixed; boundary=buffer-test\r\n\r\n".to_vec();
        for _ in 0..2 {
            raw.extend_from_slice(b"--buffer-test\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\n");
            raw.resize(raw.len() + size, b'x');
            raw.extend_from_slice(b"\r\n");
        }
        raw.extend_from_slice(b"--buffer-test--\r\n");
        let mut parsed = Parsed::parse(raw).await.unwrap();
        let mut decoded = 0;
        while let Some(leaf) = parsed.next().await.unwrap() {
            assert!(leaf.issues.is_empty());
            if let Some(bytes) = leaf.bytes {
                decoded += bytes.len();
            }
        }
        assert_eq!(decoded, 2 * size);
    }

    #[tokio::test]
    async fn base64_and_quoted_printable_are_decoded() {
        for (encoding, body) in [("base64", "aGVsbG8="), ("quoted-printable", "he=6Clo")] {
            let raw = format!(
                "From: example@example.test\r\nContent-Transfer-Encoding: {encoding}\r\n\r\n{body}"
            );
            let mut parsed = Parsed::parse(raw.into_bytes()).await.unwrap();
            let leaf = parsed.next().await.unwrap().unwrap();
            assert_eq!(leaf.bytes.unwrap(), b"hello");
            assert!(leaf.issues.is_empty());
        }
    }

    #[tokio::test]
    async fn nested_messages_are_visited() {
        let raw = b"From: outer@example.test\r\nContent-Type: message/rfc822\r\n\r\nFrom: inner@example.test\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8=";
        let mut parsed = Parsed::parse(raw.to_vec()).await.unwrap();
        let mut found = false;
        while let Some(leaf) = parsed.next().await.unwrap() {
            found |= leaf.bytes.as_deref() == Some(b"hello");
        }
        assert!(found);
    }

    #[tokio::test]
    async fn malformed_transfer_encoding_is_incomplete() {
        let raw = b"From: example@example.test\r\nContent-Transfer-Encoding: unknown\r\n\r\nhello";
        let mut parsed = Parsed::parse(raw.to_vec()).await.unwrap();
        let leaf = parsed.next().await.unwrap().unwrap();
        assert!(!leaf.issues.is_empty());
    }

    #[tokio::test]
    async fn excessive_parts_produce_an_incomplete_warning() {
        let mut raw =
            "From: example@example.test\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n"
                .to_owned();
        for _ in 0..257 {
            raw.push_str("--b\r\nContent-Type: text/plain\r\n\r\nhello\r\n");
        }
        raw.push_str("--b--\r\n");
        let mut parsed = Parsed::parse(raw.into_bytes()).await.unwrap();
        let mut warned = false;
        let mut count = 0;
        while let Some(leaf) = parsed.next().await.unwrap() {
            warned |= !leaf.issues.is_empty();
            count += 1;
        }
        assert!(warned);
        assert!(count <= 256);
    }
}
