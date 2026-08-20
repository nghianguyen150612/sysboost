//! Durable-intent storage port.

use sysboost_core::{Session, Snapshot, SysboostError, TransitionRecord};

/// Logical intent returned by a journal implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredIntent {
    /// Session header/state at creation.
    pub session: Session,
    /// Complete preimages captured before apply.
    pub snapshots: Vec<Snapshot>,
}

/// Journal port. Implementations must flush intent before returning success.
pub trait JournalStore {
    /// Create and durably persist a complete intent.
    fn create_intent(
        &mut self,
        session: &Session,
        snapshots: &[Snapshot],
    ) -> Result<(), SysboostError>;

    /// Append and durably persist one state transition.
    fn append_transition(&mut self, transition: &TransitionRecord) -> Result<(), SysboostError>;

    /// Load sessions that were not proven restored.
    fn load_unfinished(&self) -> Result<Vec<StoredIntent>, SysboostError>;
}
