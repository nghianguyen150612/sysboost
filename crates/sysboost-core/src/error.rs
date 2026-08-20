//! Structured error taxonomy for fail-closed operations.

use core::fmt;

use crate::ids::{BackendId, CapabilityId, MutationId, SessionId, TargetId};

/// Transaction stage at which an error occurred.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Stage {
    /// Capability enumeration.
    Detect,
    /// Pure plan construction.
    Plan,
    /// Original state capture.
    Snapshot,
    /// Journal creation and flushing.
    DurableIntent,
    /// Typed backend application.
    Apply,
    /// Postcondition readback.
    Verify,
    /// Reverse restore.
    Restore,
    /// Journal/session recovery.
    Recovery,
    /// Controller/helper protocol.
    Transport,
    /// Configuration parsing and merging.
    Config,
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Detect => "detect",
            Self::Plan => "plan",
            Self::Snapshot => "snapshot",
            Self::DurableIntent => "durable_intent",
            Self::Apply => "apply",
            Self::Verify => "verify",
            Self::Restore => "restore",
            Self::Recovery => "recovery",
            Self::Transport => "transport",
            Self::Config => "config",
        };
        f.write_str(value)
    }
}

/// Stable public error category.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ErrorCode {
    /// Invalid configuration.
    ConfigError,
    /// Capability evidence is unavailable or stale.
    CapabilityError,
    /// The registered backend does not implement the operation.
    Unsupported,
    /// Peer or policy authorization failed.
    AuthorizationError,
    /// Target identity or scope is invalid.
    TargetError,
    /// Plan validation failed.
    PlanningError,
    /// A complete preimage could not be captured.
    SnapshotError,
    /// Durable intent could not be persisted.
    DurabilityError,
    /// Protocol or process communication failed.
    TransportError,
    /// A typed operation failed.
    ApplyError,
    /// Readback did not meet its postcondition.
    VerificationError,
    /// An external writer changed a target.
    RestoreConflict,
    /// Restore or readback of the original failed.
    RestoreError,
    /// Journal integrity or state sequence is invalid.
    JournalCorrupt,
    /// An internal safety invariant was violated.
    InvariantViolation,
    /// An input was malformed at a boundary.
    InvalidInput,
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::ConfigError => "config_error",
            Self::CapabilityError => "capability_error",
            Self::Unsupported => "unsupported",
            Self::AuthorizationError => "authorization_error",
            Self::TargetError => "target_error",
            Self::PlanningError => "planning_error",
            Self::SnapshotError => "snapshot_error",
            Self::DurabilityError => "durability_error",
            Self::TransportError => "transport_error",
            Self::ApplyError => "apply_error",
            Self::VerificationError => "verification_error",
            Self::RestoreConflict => "restore_conflict",
            Self::RestoreError => "restore_error",
            Self::JournalCorrupt => "journal_corrupt",
            Self::InvariantViolation => "invariant_violation",
            Self::InvalidInput => "invalid_input",
        };
        f.write_str(value)
    }
}

/// Whether retrying without changing state is safe.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Retryability {
    /// Retrying could repeat an unsafe action.
    Never,
    /// A bounded retry is safe.
    Retry,
    /// Retry only after journal/target recovery.
    AfterRecovery,
    /// The operation status is uncertain.
    Unknown,
}

/// Structured identifiers attached to an error without exposing raw paths.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ErrorContext {
    /// Transaction stage.
    pub stage: Option<Stage>,
    /// Session identifier.
    pub session_id: Option<SessionId>,
    /// Mutation identifier.
    pub mutation_id: Option<MutationId>,
    /// Backend identifier.
    pub backend_id: Option<BackendId>,
    /// Capability identifier.
    pub capability_id: Option<CapabilityId>,
    /// Opaque target identifier.
    pub target_id: Option<TargetId>,
}

/// Domain error with stable category and useful context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SysboostError {
    /// Stable category.
    pub code: ErrorCode,
    /// Human-readable explanation that contains no secret/raw-path payload.
    pub message: String,
    /// Structured operation context.
    pub context: Box<ErrorContext>,
    /// Retry guidance.
    pub retryability: Retryability,
}

impl SysboostError {
    /// Construct a fail-closed error with non-retryable default guidance.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            context: Box::new(ErrorContext::default()),
            retryability: Retryability::Never,
        }
    }

    /// Attach a stage.
    pub fn with_stage(mut self, stage: Stage) -> Self {
        self.context.stage = Some(stage);
        self
    }

    /// Attach a session.
    pub fn with_session(mut self, session_id: SessionId) -> Self {
        self.context.session_id = Some(session_id);
        self
    }

    /// Attach a mutation.
    pub fn with_mutation(mut self, mutation_id: MutationId) -> Self {
        self.context.mutation_id = Some(mutation_id);
        self
    }

    /// Attach a backend.
    pub fn with_backend(mut self, backend_id: BackendId) -> Self {
        self.context.backend_id = Some(backend_id);
        self
    }

    /// Attach a capability.
    pub fn with_capability(mut self, capability_id: CapabilityId) -> Self {
        self.context.capability_id = Some(capability_id);
        self
    }

    /// Attach an opaque target.
    pub fn with_target(mut self, target_id: TargetId) -> Self {
        self.context.target_id = Some(target_id);
        self
    }

    /// Set retry guidance.
    pub fn retryable(mut self, retryability: Retryability) -> Self {
        self.retryability = retryability;
        self
    }
}

impl fmt::Display for SysboostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)?;
        if let Some(stage) = self.context.stage {
            write!(f, " stage={stage}")?;
        }
        if let Some(session_id) = self.context.session_id {
            write!(f, " session={session_id}")?;
        }
        if let Some(mutation_id) = self.context.mutation_id {
            write!(f, " mutation={mutation_id}")?;
        }
        if let Some(backend_id) = &self.context.backend_id {
            write!(f, " backend={backend_id}")?;
        }
        if let Some(capability_id) = &self.context.capability_id {
            write!(f, " capability={capability_id}")?;
        }
        if let Some(target_id) = &self.context.target_id {
            write!(f, " target={target_id}")?;
        }
        Ok(())
    }
}

impl std::error::Error for SysboostError {}
