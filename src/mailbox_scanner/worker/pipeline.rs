//! Bounded connection-local requests and connection-independent message buffers.

use super::{Retry, mailbox, message};
use async_imap::imap_proto;
use std::collections::VecDeque;
use std::time::Duration;
use tokio::time::Instant;

pub(super) const DEPTH: usize = 4;
const CHUNK: usize = 1024 * 1024;

pub(super) struct Entry {
    pub identity: message::Identity,
    pub size: usize,
    pub bytes: Option<Vec<u8>>,
    pub request: Option<Request>,
    pub result: Option<Result<Vec<u8>, mailbox::Error>>,
    pub retired: bool,
    pub retries: Retry,
    pub attempted: bool,
}

pub(super) struct Request {
    pub tag: String,
    pub origin: usize,
    pub length: usize,
    pub body: Option<()>,
    pub seen: bool,
    pub deadline: Instant,
}

#[derive(Default)]
pub(super) struct Pipeline {
    pub pending: VecDeque<message::Identity>,
    pub entries: Vec<Entry>,
    pub selected: bool,
    pub held: usize,
    pub paused: Option<Instant>,
    pub fatal: Option<mailbox::Error>,
}

pub(super) enum Change {
    None,
    Reconcile(usize),
    Reject(usize),
}

impl Pipeline {
    pub fn remaining(&self) -> usize {
        self.pending.len() + self.entries.iter().filter(|entry| !entry.retired).count()
    }

    pub fn resume(&mut self) {
        self.held = 0;
        if let Some(paused) = self.paused.take() {
            let elapsed = paused.elapsed();
            for entry in &mut self.entries {
                if let Some(request) = &mut entry.request {
                    request.deadline += elapsed;
                }
            }
        }
    }

    pub fn reset(&mut self, error: Option<&mailbox::Error>) -> Result<Duration, ()> {
        self.selected = false;
        let mut delay = Duration::ZERO;
        let mut exhausted = false;
        for entry in &mut self.entries {
            if entry.retired || entry.result.is_some() {
                continue;
            }
            if entry.attempted
                && let Some(error) = error
            {
                match entry.retries.delay(error) {
                    Some(wait) => delay = delay.max(wait),
                    None => exhausted = true,
                }
            }
            entry.bytes = None;
            entry.request = None;
        }
        if exhausted { Err(()) } else { Ok(delay) }
    }

    pub fn candidate(&mut self) -> Option<usize> {
        let mut reserved = self.held;
        let mut active = usize::from(self.held > 0);
        for entry in &self.entries {
            if !entry.retired && (entry.bytes.is_some() || entry.result.is_some()) {
                reserved += entry.size;
                active += 1;
            }
        }
        for (index, entry) in self.entries.iter_mut().enumerate() {
            if entry.retired || entry.result.is_some() || entry.request.is_some() {
                continue;
            }
            if entry.bytes.is_none() {
                if active == DEPTH || reserved + entry.size > mailbox::MAX_MESSAGE {
                    return None;
                }
                entry.bytes = Some(Vec::with_capacity(entry.size));
                entry.attempted = true;
                if entry.size == 0 {
                    entry.result = entry.bytes.take().map(Ok);
                    return None;
                }
            }
            return Some(index);
        }
        None
    }

    pub fn command(&self, index: usize) -> String {
        let entry = &self.entries[index];
        let origin = entry.bytes.as_ref().expect("admitted message").len();
        let length = CHUNK.min(entry.size - origin);
        format!(
            "UID FETCH {} (UID BODY.PEEK[]<{origin}.{length}>)",
            entry.identity.uid()
        )
    }

    pub fn sent(&mut self, index: usize, tag: String) {
        let entry = &mut self.entries[index];
        let origin = entry.bytes.as_ref().expect("admitted message").len();
        entry.request = Some(Request {
            tag,
            origin,
            length: CHUNK.min(entry.size - origin),
            body: None,
            seen: false,
            deadline: Instant::now() + Duration::from_secs(300),
        });
    }

    pub fn receive(
        &mut self,
        response: &imap_proto::Response<'_>,
    ) -> Result<Change, mailbox::Error> {
        let expected = self
            .entries
            .first()
            .map(|entry| entry.identity.uidvalidity());
        let code = match response {
            imap_proto::Response::Data { outcome, .. }
            | imap_proto::Response::Done { outcome, .. } => outcome.code.as_ref(),
            _ => None,
        };
        if let Some(imap_proto::ResponseCode::UidValidity(value)) = code
            && expected.is_some_and(|expected| expected != *value)
        {
            return Err(mailbox::Error::Stale);
        }
        match response {
            imap_proto::Response::Data {
                status: imap_proto::Status::Bye,
                ..
            } => return Err(mailbox::Error::Disconnected),
            imap_proto::Response::Data { status, .. }
                if matches!(status, imap_proto::Status::No | imap_proto::Status::Bad) =>
            {
                return Err(mailbox::Error::Unsolicited {
                    operation: "pipeline",
                    status: if *status == imap_proto::Status::No {
                        "NO"
                    } else {
                        "BAD"
                    },
                });
            }
            imap_proto::Response::Continue(_) => {
                return Err(mailbox::Error::Unexpected("pipeline continuation"));
            }
            imap_proto::Response::Fetch(_, attributes) => {
                let mut uid = None;
                for attribute in attributes {
                    if let imap_proto::AttributeValue::Uid(value) = attribute
                        && (*value == 0 || uid.replace(*value).is_some())
                    {
                        return Err(mailbox::Error::Unexpected("duplicate or zero UID"));
                    }
                }
                for attribute in attributes {
                    if let imap_proto::AttributeValue::BodySection {
                        section,
                        index,
                        data,
                    } = attribute
                    {
                        let entry = self
                            .entries
                            .iter_mut()
                            .find(|entry| {
                                Some(entry.identity.uid()) == uid && entry.request.is_some()
                            })
                            .ok_or(mailbox::Error::Unexpected("foreign body UID"))?;
                        let request = entry.request.as_mut().expect("matched request");
                        if section.is_some()
                            || *index != Some(request.origin as u32)
                            || request.seen
                        {
                            return Err(mailbox::Error::Unexpected(
                                "wrong or duplicate body origin",
                            ));
                        }
                        request.seen = true;
                        if let Some(data) = data {
                            if data.len() != request.length {
                                return Err(mailbox::Error::Unexpected("wrong body length"));
                            }
                            entry
                                .bytes
                                .as_mut()
                                .expect("request owns buffer")
                                .extend_from_slice(data);
                            request.body = Some(());
                        }
                    }
                }
            }
            imap_proto::Response::Done { tag, status, .. } => {
                let index = self
                    .entries
                    .iter()
                    .position(|entry| {
                        entry
                            .request
                            .as_ref()
                            .is_some_and(|request| request.tag == tag.0)
                    })
                    .ok_or(mailbox::Error::Unexpected("unknown completion tag"))?;
                let entry = &mut self.entries[index];
                if *status == imap_proto::Status::No {
                    return Ok(Change::Reject(index));
                }
                if *status != imap_proto::Status::Ok {
                    return Err(mailbox::Error::Rejected {
                        operation: "message body",
                        status: "BAD",
                    });
                }
                let request = entry.request.take().expect("matched request");
                let Some(()) = request.body else {
                    return Ok(Change::Reconcile(index));
                };
                let bytes = entry.bytes.as_mut().expect("request owns buffer");
                if bytes.len() == entry.size {
                    entry.result = entry.bytes.take().map(Ok);
                }
            }
            _ => {}
        }
        Ok(Change::None)
    }
}
