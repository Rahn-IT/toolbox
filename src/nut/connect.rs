use std::sync::Arc;

use iced::{
    Color, Element, Length, Task,
    widget::{button, container, grid, row, text, text_input},
};
use tokio::io;

use crate::nut::nut::NutClient;

#[derive(Clone)]
pub enum Message {
    Host(String),
    Port(String),
    Username(String),
    Password(String),
    Connect,
    ConnectResult(Arc<io::Result<NutClient>>),
    TogglePasswordVisibility,
}

pub enum Action {
    Run(Task<Message>),
    Client(NutClient),
    None,
}

pub struct Connect {
    host: String,
    port: u16,
    username: String,
    password: String,
    show_password: bool,
    connecting: bool,
    error: Option<String>,
}

impl Connect {
    pub fn new() -> Self {
        Self {
            host: String::new(),
            port: 3493,
            username: String::new(),
            password: String::new(),
            show_password: false,
            connecting: false,
            error: None,
        }
    }

    #[must_use]
    pub fn update(&mut self, message: Message) -> Action {
        match message {
            Message::Host(host) => self.host = host,
            Message::Port(port) => self.port = port.parse().unwrap_or(0),
            Message::Username(username) => self.username = username,
            Message::Password(password) => self.password = password,
            Message::TogglePasswordVisibility => self.show_password = !self.show_password,
            Message::Connect => {
                let host = self.host.clone();
                let port = self.port;
                let username = self.username.clone();
                let password = self.password.clone();

                self.error = None;
                self.connecting = true;

                return Action::Run(
                    Task::future(async move {
                        Arc::new(NutClient::connect(host, port, username, password).await)
                    })
                    .map(Message::ConnectResult),
                );
            }
            Message::ConnectResult(result) => {
                self.connecting = false;
                let result = Arc::try_unwrap(result).unwrap();
                match result {
                    Ok(client) => {
                        self.error = None;
                        return Action::Client(client);
                    }
                    Err(err) => {
                        self.error = Some(err.to_string());
                    }
                }
            }
        };
        Action::None
    }

    pub fn view(&self) -> Element<'_, Message> {
        container(
            grid![
                text!("Host"),
                text_input("Host", &self.host).on_input(Message::Host),
                text!("Port"),
                text_input("Port", &self.port.to_string()).on_input(Message::Port),
                text!("Username"),
                text_input("Username", &self.username).on_input(Message::Username),
                text!("Password"),
                row![
                    text_input("Password", &self.password)
                        .on_input(Message::Password)
                        .secure(!self.show_password),
                    if self.show_password {
                        button("Hide").on_press(Message::TogglePasswordVisibility)
                    } else {
                        button("Show").on_press(Message::TogglePasswordVisibility)
                    },
                ]
                .spacing(10),
                button("Connect").on_press_maybe((!self.connecting).then_some(Message::Connect)),
                if self.connecting {
                    text("Connecting...").color(Color::from_rgb8(255, 255, 0))
                } else {
                    text("")
                },
                if let Some(error) = &self.error {
                    text(error).color(Color::from_rgb8(255, 0, 0))
                } else {
                    text("")
                }
            ]
            .columns(2)
            .spacing(10)
            .height(Length::Shrink),
        )
        .padding(20)
        .into()
    }
}
