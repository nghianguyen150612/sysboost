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
pub mod planner;
pub mod session;
pub mod time;
pub mod transaction;

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
    ApplyReceipt, ApprovedSysctlKey, ApprovedSysctlValue, BoundedBytes, CgroupGroupKind, CgroupId,
    CgroupName, CpuBoostState, CpuPeriod, CpuPolicyId, CpuQuota, CpuSet, CpuWeight,
    EnergyPreference, FrequencyKHz, GovernorId, GpuId, GpuProfile, IoPriority, IoPriorityClass,
    IoWeight, IrqId, MutationKind, NiceValue, PlannedMutation, PlatformProfileId, PowerMilliwatts,
    ProcessId, RestoreMode, RestoreReceipt, RollbackContract, Snapshot, StateFingerprint,
    TargetIdentity, TypedValue, UclampValue,
};
pub use plan::{Plan, PlanRequest, Planner, Policy, PolicyMode, PolicyRequest};
pub use planner::{
    fingerprint_for_value, render_dry_run, Aggressiveness, ControlId, CurrentState,
    CurrentStateFact, CurrentValue, ExperimentalStatus, Feature, HumanPlanRenderer, ObservedText,
    OperationCatalog, OperationContract, PerformanceIntent, PlanAction, PlanItem, PlanRenderer,
    PlanValue, PlannerInput, PlannerPolicy, PolicyProposal, PolicyResolution, PolicyResolver,
    PolicySource, PreserveRule, Profile, ProfileIntent, RestoreContract, SnapshotContract,
    TypedPlanner, TypedTarget, VerificationContract,
};
pub use session::{Session, SessionHeader, SessionState, TransitionRecord};
pub use time::Timestamp;
pub use transaction::{
    FailureRecord, OperationRecord, OperationState, SessionRecord, VerificationResult,
    MAX_SESSION_RECORD_BYTES, STATE_FORMAT_VERSION,
};
