use std::{collections::HashMap, sync::Arc, time::Duration};

use iced::{
    Element, Length, Task,
    task::{self, sipper},
    widget::{column, row, scrollable, text},
};
use tokio::{io, time::sleep};

use crate::nut::nut::NutClient;

#[derive(Clone)]
pub enum Message {
    Info(HashMap<String, Vec<(String, String)>>),
    Error(Arc<Result<(), io::Error>>),
    Select(String),
}

pub enum Action {
    None,
}

pub struct Monitor {
    status: HashMap<String, Vec<(String, String)>>,
    list: Vec<String>,
    error: Option<String>,
    _drop_handle: task::Handle,
    selected: Option<String>,
}

impl Monitor {
    pub fn new(client: NutClient) -> (Self, Task<Message>) {
        let (task, handle) = Task::sip(
            sipper(|mut sender| async move {
                let mut client = client;
                let list = client.list_ups().await?;
                loop {
                    let mut info = HashMap::new();
                    for (name, _desc) in &list {
                        let status = client.list_vars_raw(name).await?;
                        let mut status = status.into_iter().collect::<Vec<(String, String)>>();
                        status.sort();
                        info.insert(name.clone(), status);
                    }
                    sender.send(info).await;
                    sleep(Duration::from_secs(2)).await;
                }
            }),
            Message::Info,
            |result| Message::Error(Arc::new(result)),
        )
        .abortable();

        (
            Self {
                status: HashMap::new(),
                list: Vec::new(),
                _drop_handle: handle,
                error: None,
                selected: None,
            },
            task,
        )
    }

    pub fn update(&mut self, message: Message) -> Action {
        match message {
            Message::Info(info) => {
                self.list = info.keys().cloned().collect();
                self.status = info;
                Action::None
            }
            Message::Error(err) => {
                if let Err(err) = err.as_ref() {
                    self.error = Some(err.to_string());
                }
                Action::None
            }
            Message::Select(selected) => {
                self.selected = Some(selected);
                Action::None
            }
        }
    }

    pub(crate) fn view(&self) -> Element<'_, Message> {
        scrollable(column![
            iced::widget::pick_list(
                self.list.as_slice(),
                self.selected.as_ref(),
                Message::Select,
            ),
            self.selected
                .as_ref()
                .map(|name| {
                    self.status.get(name.as_str()).map(|status| {
                        column(
                            status
                                .iter()
                                .map(|(key, value)| row![text(key).width(300), text(value)].into()),
                        )
                        .spacing(10)
                    })
                })
                .flatten()
        ])
        .width(Length::Fill)
        .into()
    }
}
