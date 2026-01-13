use iced::{
    Task,
    widget::{button, column, rule},
};

mod connect;
mod monitor;
mod nut;

#[derive(Clone)]
pub enum Message {
    Connect(connect::Message),
    Monitor(monitor::Message),
    Disconnect,
}

pub struct Nut {
    connect: connect::Connect,
    monitor: Option<monitor::Monitor>,
}

impl Nut {
    pub fn new() -> Self {
        Self {
            connect: connect::Connect::new(),
            monitor: None,
        }
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Connect(message) => match self.connect.update(message) {
                connect::Action::Run(task) => task.map(Message::Connect),
                connect::Action::Client(nut_client) => {
                    let (monitor, task) = monitor::Monitor::new(nut_client);
                    self.monitor = Some(monitor);
                    task.map(Message::Monitor)
                }
                connect::Action::None => Task::none(),
            },
            Message::Monitor(message) => {
                if let Some(monitor) = &mut self.monitor {
                    match monitor.update(message) {
                        monitor::Action::None => Task::none(),
                    }
                } else {
                    Task::none()
                }
            }
            Message::Disconnect => {
                self.monitor = None;
                Task::none()
            }
        }
    }

    pub fn view(&self) -> iced::Element<'_, Message> {
        match &self.monitor {
            None => self.connect.view().map(Message::Connect),
            Some(monitor) => column![
                button("Disconnect").on_press(Message::Disconnect),
                rule::horizontal(2),
                monitor.view().map(Message::Monitor),
            ]
            .spacing(5)
            .into(),
        }
    }
}
