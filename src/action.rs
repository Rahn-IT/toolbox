use iced::Task;

use crate::OpenedModule;

#[must_use]
pub enum Action<M> {
    None,
    Focus,
    Task(Task<M>),
    OpenModule(OpenedModule),
    Close,
}

impl<M: Send + 'static> Action<M> {
    pub fn map<N: Send + 'static>(self, map: impl Fn(M) -> N + Send + 'static) -> Action<N> {
        match self {
            Self::None => Action::None,
            Self::Focus => Action::Focus,
            Self::Task(task) => Action::Task(task.map(map)),
            Self::OpenModule(opened) => Action::OpenModule(opened),
            Self::Close => Action::Close,
        }
    }
}
