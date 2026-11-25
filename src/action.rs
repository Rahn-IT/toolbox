use iced::Task;

#[must_use]
pub enum Action<M> {
    None,
    Focus,
    Task(Task<M>),
    Close,
}

impl<M: Send + 'static> Action<M> {
    pub fn map<N: Send + 'static>(self, map: impl Fn(M) -> N + Send + 'static) -> Action<N> {
        match self {
            Self::None => Action::None,
            Self::Focus => Action::Focus,
            Self::Task(task) => Action::Task(task.map(map)),
            Self::Close => Action::Close,
        }
    }

    pub(crate) fn into_task(self) -> Task<M> {
        match self {
            Self::Task(task) => task,
            Self::None | Self::Focus | Self::Close => Task::none(),
        }
    }
}
