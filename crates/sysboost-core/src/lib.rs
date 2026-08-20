#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Linux-independent domain contracts for sysboost.
//!
//! This crate intentionally contains no host I/O. It models capabilities,
//! typed mutation plans, session state, error context, and structured log
//! events so those pieces can be tested without a Linux machine or privilege.

pub mod capability;
pub mod error;
pub mod ids;
pub mod logging;
pub mod mutation;
pub mod plan;
pub mod session;
pub mod time;

pub use capability::{
    CapabilityDescriptor, CapabilityEvidence, CapabilityInventory, CapabilityState, EqualityKind,
    EvidenceSource, FeatureClass, OperationDescriptor, PrivilegeRequirement, RiskClass, TargetKind,
};
pub use error::{ErrorCode, ErrorContext, Retryability, Stage, SysboostError};
pub use ids::{
    BackendId, CapabilityId, IdentifierError, MutationId, OperationId, PlanId, SessionId, TargetId,
};
pub use logging::{LogEvent, LogField, LogLevel, LogSink, LogValue, MemoryLogSink};
pub use mutation::{
    ApplyReceipt, ApprovedSysctlKey, ApprovedSysctlValue, BoundedBytes, CgroupId, CpuPeriod,
    CpuPolicyId, CpuQuota, CpuSet, CpuWeight, EnergyPreference, FrequencyKHz, GovernorId, GpuId,
    GpuProfile, IrqId, MutationKind, PlannedMutation, PowerMilliwatts, RestoreMode, RestoreReceipt,
    RollbackContract, Snapshot, StateFingerprint, TargetIdentity, TypedValue,
};
pub use plan::{Plan, PlanRequest, Planner, Policy, PolicyMode, PolicyRequest};
pub use session::{Session, SessionHeader, SessionState, TransitionRecord};
pub use time::Timestamp;
