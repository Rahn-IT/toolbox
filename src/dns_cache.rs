#[cfg(any(windows, target_os = "linux"))]
use std::time::Duration;

use iced::{
    Alignment, Element, Length, Task,
    widget::{button, column, container, row, rule, scrollable, text, text_input},
};

use crate::{Module, OpenedModule, tab_manager::TabMessage};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Entry {
    name: String,
    records: String,
}

#[derive(Clone)]
pub enum Message {
    FilterChanged(String),
    Refresh,
    Loaded(Result<Vec<Entry>, String>),
    Flush,
    Flushed(Result<(), String>),
}

pub struct State {
    filter: String,
    entries: Option<Result<Vec<Entry>, String>>,
    flushing: bool,
    flush_status: Option<Result<(), String>>,
}

impl State {
    pub const TITLE: &'static str = "DNS Cache";

    pub fn new() -> OpenedModule {
        let state = Self {
            filter: String::new(),
            entries: None,
            flushing: false,
            flush_status: None,
        };
        (
            Module::DnsCache(state),
            Task::perform(read(), Message::Loaded).map(TabMessage::DnsCache),
        )
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::FilterChanged(filter) => self.filter = filter,
            Message::Refresh if self.can_change_cache() => {
                self.entries = None;
                self.flush_status = None;
                return Task::perform(read(), Message::Loaded);
            }
            Message::Loaded(entries) => self.entries = Some(entries),
            Message::Flush
                if self.can_change_cache() && cfg!(any(windows, target_os = "linux")) =>
            {
                self.flushing = true;
                self.flush_status = None;
                return Task::perform(flush(), Message::Flushed);
            }
            Message::Flushed(result) if self.flushing => {
                self.flushing = false;
                let flushed = result.is_ok();
                self.flush_status = Some(result);
                if flushed {
                    self.entries = None;
                    return Task::perform(read(), Message::Loaded);
                }
            }
            Message::Refresh | Message::Flush | Message::Flushed(_) => {}
        }
        Task::none()
    }

    fn can_change_cache(&self) -> bool {
        self.entries.is_some() && !self.flushing
    }

    pub fn view(&self) -> Element<'_, Message> {
        let controls = row![
            text_input("Search DNS cache", &self.filter)
                .on_input(Message::FilterChanged)
                .padding([12, 16])
                .style(crate::rounded_input_style),
            button("Refresh")
                .padding([10, 16])
                .on_press_maybe(self.can_change_cache().then_some(Message::Refresh)),
            cfg!(any(windows, target_os = "linux")).then(|| {
                button("Flush DNS Cache")
                    .padding([10, 16])
                    .on_press_maybe(self.can_change_cache().then_some(Message::Flush))
            }),
        ]
        .spacing(12)
        .align_y(Alignment::Center);

        let results: Element<'_, Message> = match &self.entries {
            None => crate::loading::content(None, "Reading DNS cache").into(),
            Some(Err(error)) => text(error).into(),
            Some(Ok(entries)) if entries.is_empty() => text("The DNS cache is empty.").into(),
            Some(Ok(entries)) => self.table(entries),
        };
        let status = if self.flushing {
            Some(text("Flushing DNS cache…"))
        } else {
            self.flush_status.as_ref().map(|status| match status {
                Ok(()) => text("DNS cache flushed."),
                Err(error) => text(format!("Could not flush DNS cache. {error}")),
            })
        };
        container(column![controls, status, results].spacing(16))
            .width(Length::Fill)
            .height(Length::Fill)
            .padding(24)
            .into()
    }

    fn table<'a>(&'a self, entries: &'a [Entry]) -> Element<'a, Message> {
        const NAME_WIDTH: f32 = 320.0;
        let query = self.filter.trim().to_ascii_lowercase();
        let mut entries = entries
            .iter()
            .filter(|entry| {
                entry.name.to_ascii_lowercase().contains(&query)
                    || entry.records.to_ascii_lowercase().contains(&query)
            })
            .peekable();
        if entries.peek().is_none() {
            return text("No matching cache entries.").into();
        }
        let rows = column(entries.map(|entry| {
            container(
                row![
                    text(&entry.name).width(NAME_WIDTH),
                    text(&entry.records).width(Length::Fill),
                ]
                .spacing(12),
            )
            .width(Length::Fill)
            .padding([8, 12])
            .style(container::rounded_box)
            .into()
        }))
        .spacing(6);
        column![
            container(row![text("Name").width(NAME_WIDTH), text("Cached records")].spacing(12))
                .padding([0, 12]),
            rule::horizontal(1),
            scrollable(rows).height(Length::Fill),
        ]
        .spacing(8)
        .into()
    }
}

pub(crate) async fn lookup(host: &str) -> Result<Option<String>, String> {
    let entries = read().await?;
    Ok(matching_records(&entries, host))
}

fn matching_records(entries: &[Entry], host: &str) -> Option<String> {
    let records: Vec<_> = entries
        .iter()
        .filter(|entry| {
            entry
                .name
                .trim_end_matches('.')
                .eq_ignore_ascii_case(host.trim_end_matches('.'))
        })
        .map(|entry| entry.records.as_str())
        .collect();
    (!records.is_empty()).then(|| records.join("\n"))
}

#[cfg(any(windows, target_os = "linux"))]
async fn read() -> Result<Vec<Entry>, String> {
    let output = cache_command(CacheCommand::Read).await?;
    #[cfg(windows)]
    let mut entries = parse_windows(&output);
    #[cfg(target_os = "linux")]
    let mut entries = parse_linux(&output);
    entries.sort_unstable();
    entries.dedup();
    Ok(entries)
}

#[cfg(any(windows, target_os = "linux"))]
async fn flush() -> Result<(), String> {
    cache_command(CacheCommand::Flush).await.map(|_| ())
}

#[cfg(any(windows, target_os = "linux"))]
enum CacheCommand {
    Read,
    Flush,
}

#[cfg(any(windows, target_os = "linux"))]
async fn cache_command(operation: CacheCommand) -> Result<String, String> {
    use tokio::process::Command;

    #[cfg(windows)]
    let (mut command, tool) = {
        let path = crate::quick_tools::system::executable("ipconfig.exe")?;
        let mut command = Command::new(path);
        let (argument, tool) = match operation {
            CacheCommand::Read => ("/displaydns", "ipconfig /displaydns"),
            CacheCommand::Flush => ("/flushdns", "ipconfig /flushdns"),
        };
        command.arg(argument).creation_flags(0x0800_0000);
        (command, tool)
    };
    #[cfg(target_os = "linux")]
    let (mut command, tool) = {
        let mut command = Command::new("resolvectl");
        let (argument, tool) = match operation {
            CacheCommand::Read => ("show-cache", "resolvectl show-cache"),
            CacheCommand::Flush => ("flush-caches", "resolvectl flush-caches"),
        };
        command
            .args(["--no-pager", argument])
            .env("LC_ALL", "C")
            .env("SYSTEMD_COLORS", "0");
        (command, tool)
    };
    let output = tokio::time::timeout(Duration::from_secs(4), command.kill_on_drop(true).output())
        .await
        .map_err(|_| format!("{tool} timed out."))?
        .map_err(|error| format!("{tool}: {error}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let details = stderr
            .lines()
            .find(|line| !line.trim().is_empty())
            .or_else(|| stdout.lines().rev().find(|line| !line.trim().is_empty()))
            .map_or_else(|| output.status.to_string(), |line| line.trim().to_owned());
        return Err(format!("{tool}: {details}"));
    }
    Ok(stdout.into_owned())
}

#[cfg(not(any(windows, target_os = "linux")))]
async fn flush() -> Result<(), String> {
    Err("Flushing the system DNS cache is unavailable on this platform.".into())
}

#[cfg(not(any(windows, target_os = "linux")))]
async fn read() -> Result<Vec<Entry>, String> {
    Err(
        "Reading the system DNS cache is supported on Windows and Linux with systemd-resolved."
            .into(),
    )
}

#[cfg(any(windows, test))]
fn parse_windows(output: &str) -> Vec<Entry> {
    let mut entries = Vec::new();
    let mut lines = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .peekable();
    let mut name = None;
    let mut records = Vec::new();
    while let Some(line) = lines.next() {
        if lines
            .peek()
            .is_some_and(|line| line.len() >= 8 && line.bytes().all(|byte| byte == b'-'))
        {
            lines.next();
            if let Some(previous) = name.replace(line) {
                entries.push(windows_entry(previous, &records));
                records.clear();
            }
        } else if name.is_some() {
            records.push(line);
        }
    }
    if let Some(name) = name {
        entries.push(windows_entry(name, &records));
    }
    entries
}

#[cfg(any(windows, test))]
fn windows_entry(name: &str, lines: &[&str]) -> Entry {
    fn field(line: &str) -> Option<(&str, &str)> {
        let (label, value) = line.split_once(':')?;
        let (label, _) = label.split_once(" .")?;
        Some((label.trim_end(), value.trim()))
    }

    // ipconfig localizes labels, but puts the owner, type, TTL, length, and section
    // first in each record. The owner label also marks subsequent records in a group.
    let records = match lines.first().and_then(|line| field(line)) {
        Some((owner_label, _)) => {
            let mut records = Vec::new();
            let mut start = 0;
            for end in 1..=lines.len() {
                if end < lines.len()
                    && field(lines[end]).is_none_or(|(label, _)| label != owner_label)
                {
                    continue;
                }
                let record = &lines[start..end];
                let kind = record
                    .get(1)
                    .and_then(|line| field(line))
                    .and_then(|(_, value)| value.parse::<u16>().ok());
                let ttl = record
                    .get(2)
                    .and_then(|line| field(line))
                    .and_then(|(_, value)| value.parse::<u32>().ok());
                if let (Some(kind), Some(ttl), Some(data)) = (kind, ttl, record.get(5..)) {
                    let kind = hickory_client::proto::rr::RecordType::from(kind);
                    let data = data
                        .iter()
                        .map(|line| field(line).map_or(*line, |(_, value)| value))
                        .collect::<Vec<_>>()
                        .join(" ");
                    records.push(format!("{kind} {data} (TTL {ttl}s)"));
                } else {
                    records.push(record.join(" · "));
                }
                start = end;
            }
            records.join("\n")
        }
        None => lines.join("\n"),
    };
    Entry {
        name: name.into(),
        records,
    }
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux(output: &str) -> Vec<Entry> {
    let mut dns_scope = false;
    output
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if let Some(scope) = line.strip_prefix("Scope protocol=") {
                dns_scope = scope.split_ascii_whitespace().next() == Some("dns");
                return None;
            }
            if !dns_scope || line.is_empty() || line == "No entries." {
                return None;
            }
            let (name, records) = line.split_once(char::is_whitespace)?;
            Some(Entry {
                name: name.into(),
                records: records.trim_start().into(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_successful_flush_reloads_the_cache_snapshot() {
        let Module::DnsCache(mut state) = State::new().0 else {
            panic!("expected DNS cache module");
        };
        let _ = state.update(Message::Loaded(Ok(Vec::new())));
        state.flushing = true;
        let _ = state.update(Message::Flushed(Ok(())));
        assert!(!state.flushing);
        assert!(matches!(state.flush_status, Some(Ok(()))));
        assert!(state.entries.is_none());
        assert!(!state.can_change_cache());
    }

    #[test]
    fn reads_localized_windows_groups_and_matches_only_the_queried_name() {
        let entries = parse_windows(
            "Windows-IP-Konfiguration\n\n\
            Cached.Example.\n------------------------\n\
            Eintragsname . . : Cached.Example\nEintragstyp . . : 1\n\
            Gültigkeitsdauer . . : 42\nDatenlänge . . : 4\nAbschnitt . . : Antwort\n\
            A-Eintrag . . : 192.0.2.10\n\
            missing.example\n------------------------\nName ist nicht vorhanden\n",
        );
        assert_eq!(
            matching_records(&entries, "cached.example").as_deref(),
            Some("A 192.0.2.10 (TTL 42s)")
        );
        assert_eq!(
            matching_records(&entries, "missing.example.").as_deref(),
            Some("Name ist nicht vorhanden")
        );
        assert_eq!(matching_records(&entries, "example"), None);
    }

    #[test]
    fn reads_systemd_dns_records_and_ignores_multicast_scopes() {
        let entries = parse_linux(
            "Scope protocol=dns\nexample.test IN AAAA 2001:db8::1\n\
             Scope protocol=mdns ifname=eth0\nprinter.local IN A 192.0.2.3\n",
        );
        assert_eq!(entries.len(), 1);
        assert_eq!(
            matching_records(&entries, "example.test.").as_deref(),
            Some("IN AAAA 2001:db8::1")
        );
    }
}
