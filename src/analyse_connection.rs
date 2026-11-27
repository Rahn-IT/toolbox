mod name_resolution;

use std::fmt;

use iced::{
    Element, Length, Subscription, Task,
    keyboard::{self, Key, key::Named},
    widget::{button, column, container, pick_list, scrollable, text, text_input},
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Http,
    Https,
    Tls,
    Unknown,
    Autodetect,
}

impl Protocol {
    const ALL: [Self; 5] = [
        Self::Http,
        Self::Https,
        Self::Tls,
        Self::Unknown,
        Self::Autodetect,
    ];
}

impl fmt::Display for Protocol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Http => "HTTP",
            Self::Https => "HTTPS",
            Self::Tls => "TLS",
            Self::Unknown => "Unknown",
            Self::Autodetect => "Autodetect",
        })
    }
}

#[derive(Clone)]
pub enum Message {
    HostEdited(String),
    PortEdited(String),
    ProtocolSelected(Protocol),
    Analyse,
    Resolution(name_resolution::Message),
}

#[derive(Default)]
pub struct State {
    host: String,
    port: String,
    protocol: Option<Protocol>,
    resolver: name_resolution::Resolver,
}

impl State {
    pub const TITLE: &'static str = "Analyse Connection Problems";

    pub fn new() -> crate::OpenedModule {
        (
            crate::Module::AnalyseConnection(Self::default()),
            iced::Task::none(),
        )
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        let resolution = match message {
            Message::HostEdited(host) if !self.resolver.is_running() => {
                self.host = host;
                self.resolver = name_resolution::Resolver::default();
                return Task::none();
            }
            Message::PortEdited(port) => {
                self.port = port;
                return Task::none();
            }
            Message::ProtocolSelected(protocol) => {
                self.protocol = Some(protocol);
                return Task::none();
            }
            Message::Analyse if self.can_analyse() => {
                self.resolver = name_resolution::Resolver::default();
                name_resolution::Message::Start(self.host.trim().into())
            }
            Message::Resolution(message) => message,
            Message::Analyse | Message::HostEdited(_) => return Task::none(),
        };
        self.resolver.update(resolution);
        let task = self.resolver.next_checks();
        // Claim ready checks before returning to iced, where other checks may finish.
        self.resolver
            .update(name_resolution::Message::ChecksStarted);
        task.map(Message::Resolution)
    }

    fn can_analyse(&self) -> bool {
        !self.host.trim().is_empty() && !self.resolver.is_running()
    }

    pub fn subscription(&self) -> Subscription<Message> {
        if !self.can_analyse() {
            return Subscription::none();
        }
        keyboard::listen().filter_map(|event| match event {
            keyboard::Event::KeyPressed {
                key: Key::Named(Named::Enter),
                modifiers,
                repeat: false,
                ..
            } if modifiers.is_empty() => Some(Message::Analyse),
            _ => None,
        })
    }

    pub fn view(&self) -> Element<'_, Message> {
        let submit = self.can_analyse().then_some(Message::Analyse);
        let form = column![
            column![
                text("Hostname or IP"),
                text_input("example.com", &self.host)
                    .on_input_maybe((!self.resolver.is_running()).then_some(Message::HostEdited),)
                    .on_submit_maybe(submit.clone())
                    .padding([12, 16])
                    .style(crate::rounded_input_style),
            ]
            .spacing(6),
            column![
                text("Port (optional)"),
                text_input("", &self.port)
                    .on_input(Message::PortEdited)
                    .on_submit_maybe(submit.clone())
                    .padding([12, 16])
                    .style(crate::rounded_input_style),
            ]
            .spacing(6),
            column![
                text("Protocol"),
                pick_list(Protocol::ALL, self.protocol, Message::ProtocolSelected)
                    .placeholder("Select a protocol")
                    .padding([12, 16])
                    .width(Length::Fill),
            ]
            .spacing(6),
            button("Analyse").on_press_maybe(submit),
        ]
        .spacing(16);

        let content = column![
            container(container(form).width(Length::Fill).max_width(680)).center_x(Length::Fill),
            self.resolver
                .view()
                .map(|view| view.map(Message::Resolution)),
        ]
        .spacing(24);
        scrollable(container(content).width(Length::Fill).padding(24))
            .height(Length::Fill)
            .into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_literals_skip_name_resolution() {
        for host in ["192.0.2.1", "2001:db8::1", "[2001:db8::1]"] {
            let mut state = State::default();
            let _ = state.update(Message::HostEdited(host.into()));
            let _ = state.update(Message::Analyse);
            assert!(matches!(state.resolver, name_resolution::Resolver::Ip(_)));
        }
    }
}
