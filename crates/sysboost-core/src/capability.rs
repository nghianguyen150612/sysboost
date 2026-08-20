//! Capability evidence and backend-independent descriptors.

use crate::ids::{BackendId, CapabilityId, OperationId, TargetId};
use crate::time::Timestamp;

/// Stable semantic capability names reserved by the architecture.
pub mod ids {
    /// CPU policy minimum frequency.
    pub const CPU_POLICY_FREQUENCY_MIN: &str = "cpu.policy.frequency.min";
    /// CPU policy maximum frequency.
    pub const CPU_POLICY_FREQUENCY_MAX: &str = "cpu.policy.frequency.max";
    /// CPU policy governor.
    pub const CPU_POLICY_GOVERNOR: &str = "cpu.policy.governor";
    /// CPU energy-performance preference.
    pub const CPU_POLICY_ENERGY_PREFERENCE: &str = "cpu.policy.energy_preference";
    /// Cgroup CPU weight.
    pub const CGROUP_CPU_WEIGHT: &str = "cgroup.cpu.weight";
    /// Cgroup CPU quota and period.
    pub const CGROUP_CPU_MAX: &str = "cgroup.cpu.max";
    /// Cgroup effective CPU set.
    pub const CGROUP_CPUSET_CPUS: &str = "cgroup.cpuset.cpus";
    /// GPU performance profile.
    pub const GPU_PERFORMANCE_PROFILE: &str = "gpu.performance.profile";
    /// GPU power limit.
    pub const GPU_POWER_LIMIT: &str = "gpu.power.limit";
    /// IRQ affinity.
    pub const IRQ_AFFINITY: &str = "irq.affinity";
    /// Reviewed runtime sysctl family.
    pub const KERNEL_SYSCTL_RUNTIME: &str = "kernel.sysctl.runtime";
}

/// Runtime availability state of a capability.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CapabilityState {
    /// Readable, writable, reversible, and verified.
    Available,
    /// Readable but not admitted for mutation.
    ReadOnly,
    /// The host does not expose the interface.
    Unsupported,
    /// Evidence was insufficient or contradictory.
    Indeterminate,
    /// The interface exists but policy/permissions deny it.
    Denied,
}

/// Product safety class for a feature family.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FeatureClass {
    /// Reviewed runtime operation with an exact rollback contract.
    RuntimeMutable,
    /// Runtime operation that needs additional host-specific gates.
    Conditional,
    /// Disabled by default and separately reviewed.
    Experimental,
    /// Never mutated by the runtime utility.
    BootOnlyReportOnly,
}

/// Equality semantics used for verification and restore.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EqualityKind {
    /// Original bytes must match.
    ByteExact,
    /// A typed scalar must match.
    ScalarExact,
    /// A normalized set must match.
    SetExact,
}

/// Privilege needed by a capability.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PrivilegeRequirement {
    /// No privilege beyond the caller's normal read access.
    None,
    /// Read-only inspection is possible, but mutation is not admitted.
    ReadOnly,
    /// The typed helper is required for mutation.
    PrivilegedMutation,
}

/// Coarse blast-radius class used by policy.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RiskClass {
    /// A narrowly scoped value with local impact.
    Low,
    /// A policy or cgroup value affecting a group of work.
    Medium,
    /// A system-wide or device-wide value.
    High,
    /// An experimental operation with broad or uncertain effects.
    Critical,
}

/// Target category understood by a backend.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TargetKind {
    /// CPUFreq policy target.
    CpuPolicy,
    /// Existing cgroup target.
    Cgroup,
    /// GPU device target.
    Gpu,
    /// IRQ target.
    Irq,
    /// Explicitly reviewed sysctl target.
    Sysctl,
}

/// Source category for positive or negative capability evidence.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EvidenceSource {
    /// sysfs observation.
    Sysfs,
    /// procfs observation.
    Procfs,
    /// cgroup v1 observation.
    CgroupV1,
    /// cgroup v2 observation.
    CgroupV2,
    /// Device-specific observation.
    Device,
    /// Permission/peer observation.
    Permission,
    /// Deterministic test evidence.
    Synthetic,
}

/// A bounded piece of evidence explaining a capability state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityEvidence {
    /// Evidence source family.
    pub source: EvidenceSource,
    /// Human-readable, non-secret explanation.
    pub detail: String,
}

/// One operation a backend advertises for a capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationDescriptor {
    /// Stable operation ID.
    pub id: OperationId,
    /// Required privilege.
    pub privilege: PrivilegeRequirement,
    /// Verification equality.
    pub equality: EqualityKind,
    /// Safety classification.
    pub classification: FeatureClass,
}

/// Capability descriptor registered by a backend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityDescriptor {
    /// Semantic capability ID.
    pub id: CapabilityId,
    /// Owning compiled-in backend.
    pub backend: BackendId,
    /// Target category.
    pub target_kind: TargetKind,
    /// Fresh evidence state.
    pub state: CapabilityState,
    /// Typed operations supported by the backend.
    pub operations: Vec<OperationDescriptor>,
    /// Privilege boundary.
    pub privilege: PrivilegeRequirement,
    /// Declared restoration equality.
    pub equality: EqualityKind,
    /// Blast-radius classification.
    pub risk: RiskClass,
    /// Product maturity class.
    pub classification: FeatureClass,
    /// Evidence supporting the state.
    pub evidence: Vec<CapabilityEvidence>,
}

/// Host capability inventory bound to a detection timestamp.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityInventory {
    /// Observation time from an injected clock.
    pub observed_at: Timestamp,
    /// Per-capability evidence.
    pub capabilities: Vec<CapabilityDescriptor>,
}

/// Return a stable target selector for a capability observation without
/// exposing a filesystem path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityTarget {
    /// Semantic capability ID.
    pub capability: CapabilityId,
    /// Opaque target identity.
    pub target: TargetId,
}
