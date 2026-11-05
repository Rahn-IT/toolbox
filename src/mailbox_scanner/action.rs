//! Screen tasks and navigation instructions.

use iced::Task;

#[must_use]
pub struct Action<I, M> {
    pub instruction: Option<I>,
    pub task: Task<M>,
}

impl<I, M> Action<I, M> {
    pub fn none() -> Self {
        Self {
            instruction: None,
            task: Task::none(),
        }
    }

    pub fn instruction(instruction: I) -> Self {
        Self {
            instruction: Some(instruction),
            task: Task::none(),
        }
    }
}
