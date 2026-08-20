//! Process identity ports used for session ownership and deterministic tests.

use sysboost_core::{ErrorCode, SysboostError};

/// Stable enough process identity for a single helper/controller lease.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProcessIdentity {
    /// Operating-system process ID.
    pub pid: u32,
    /// Platform-provided generation/start token when available.
    pub generation: u64,
}

impl ProcessIdentity {
    /// Construct a process identity from platform evidence.
    pub fn new(pid: u32, generation: u64) -> Result<Self, SysboostError> {
        if pid == 0 {
            Err(SysboostError::new(
                ErrorCode::InvalidInput,
                "process ID must be non-zero",
            ))
        } else {
            Ok(Self { pid, generation })
        }
    }
}

/// Process identity provider used by session ownership checks.
pub trait ProcessIdentityProvider {
    /// Return the current process identity.
    fn current(&self) -> Result<ProcessIdentity, SysboostError>;
}

/// Portable current-process adapter. Linux may later add a start-time token.
#[derive(Clone, Copy, Debug, Default)]
pub struct CurrentProcess;

impl ProcessIdentityProvider for CurrentProcess {
    fn current(&self) -> Result<ProcessIdentity, SysboostError> {
        ProcessIdentity::new(std::process::id(), 0)
    }
}

/// Fixed process identity for tests and protocol fixtures.
#[derive(Clone, Copy, Debug)]
pub struct FixedProcessIdentity {
    identity: ProcessIdentity,
}

impl FixedProcessIdentity {
    /// Construct a fixed provider.
    pub const fn new(identity: ProcessIdentity) -> Self {
        Self { identity }
    }
}

impl ProcessIdentityProvider for FixedProcessIdentity {
    fn current(&self) -> Result<ProcessIdentity, SysboostError> {
        Ok(self.identity)
    }
}
