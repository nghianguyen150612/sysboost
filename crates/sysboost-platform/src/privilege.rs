//! Narrow controller-to-helper privilege port.

use sysboost_core::{Plan, SessionId, SessionState, SysboostError};

/// Opaque handle returned by a trusted helper after snapshot and durable-intent
/// preparation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SessionHandle {
    /// Helper-owned session identity.
    pub session_id: SessionId,
}

/// Typed privilege broker. No method accepts a path, command, or raw value.
pub trait PrivilegeBroker {
    /// Ask the helper to revalidate a plan, snapshot it, and durably persist
    /// intent before returning a handle.
    fn prepare(&mut self, plan: &Plan) -> Result<SessionHandle, SysboostError>;

    /// Ask the helper to apply the prepared session.
    fn apply(&mut self, session: SessionHandle) -> Result<SessionState, SysboostError>;

    /// Ask the helper to restore the prepared session.
    fn restore(&mut self, session: SessionHandle) -> Result<SessionState, SysboostError>;

    /// Read helper-owned session state.
    fn status(&self, session: SessionHandle) -> Result<SessionState, SysboostError>;
}
