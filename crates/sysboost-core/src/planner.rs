//! Pure profile resolution and typed plan construction.
//!
//! This module deliberately consumes already-collected facts.  It has no
//! filesystem, process, command, Linux, or privilege dependencies.  A
//! [`TypedPlanner`] converts a profile and evidence into explainable decision
//! items; only items classified as [`PlanAction::Mutation`] are copied into
//! the transaction-facing mutation list.

use core::fmt;
use core::fmt::Write as _;
use core::str::FromStr;
use std::collections::{BTreeMap, BTreeSet};

use crate::capability::{
    ids as capability_ids, CapabilityDescriptor, CapabilityEvidence, CapabilityInventory,
    CapabilityState, EqualityKind, FeatureClass, RiskClass, TargetKind,
};
use crate::error::{ErrorCode, Stage, SysboostError};
use crate::ids::{BackendId, CapabilityId, MutationId, OperationId, PlanId, TargetId};
use crate::mutation::{
    ApprovedSysctlKey, CgroupGroupKind, CgroupId, CpuBoostState, CpuPolicyId, EnergyPreference,
    GovernorId, GpuId, GpuProfile, IrqId, MutationKind, PlannedMutation, PlatformProfileId,
    ProcessId, RestoreMode, StateFingerprint, TargetIdentity, TypedValue, UclampValue,
};
use crate::plan::{Plan, Policy, PolicyMode, PolicyRequest};
use crate::time::Timestamp;

/// The three supported high-level policy profiles.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Profile {
    /// Prefer useful performance while leaving risky or unsupported features
    /// unchanged.
    Balanced,
    /// Prefer performance-oriented values for reviewed runtime operations.
    Performance,
    /// Prefer the most aggressive reviewed intent, subject to every safety
    /// gate and explicit opt-in.
    Extreme,
}

impl Profile {
    /// Parse a profile name without retaining a free-form string.
    pub fn parse(value: &str) -> Result<Self, SysboostError> {
        value.parse()
    }

    /// Return the abstract intent represented by this profile.
    pub const fn intent(self) -> ProfileIntent {
        match self {
            Self::Balanced => ProfileIntent {
                profile: Self::Balanced,
                governor: PerformanceIntent::Balanced,
                energy_preference: PerformanceIntent::Balanced,
                aggressiveness: Aggressiveness::Conservative,
            },
            Self::Performance => ProfileIntent {
                profile: Self::Performance,
                governor: PerformanceIntent::Performance,
                energy_preference: PerformanceIntent::Performance,
                aggressiveness: Aggressiveness::Standard,
            },
            Self::Extreme => ProfileIntent {
                profile: Self::Extreme,
                governor: PerformanceIntent::Performance,
                energy_preference: PerformanceIntent::Performance,
                aggressiveness: Aggressiveness::Aggressive,
            },
        }
    }
}

impl fmt::Display for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Balanced => "balanced",
            Self::Performance => "performance",
            Self::Extreme => "extreme",
        })
    }
}

impl FromStr for Profile {
    type Err = SysboostError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "balanced" => Ok(Self::Balanced),
            "performance" => Ok(Self::Performance),
            "extreme" => Ok(Self::Extreme),
            _ => Err(SysboostError::new(
                ErrorCode::ConfigError,
                "profile must be balanced, performance, or extreme",
            )
            .with_stage(Stage::Config)),
        }
    }
}

/// Abstract preference used by a profile before capability resolution.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PerformanceIntent {
    /// Prefer a balanced value when the interface exposes one.
    Balanced,
    /// Prefer a performance value when the interface exposes one.
    Performance,
}

/// Coarse aggressiveness intent.  It is not a write list or a kernel value.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Aggressiveness {
    /// Avoid optional changes.
    Conservative,
    /// Use reviewed first-class runtime changes.
    Standard,
    /// Consider explicitly opted-in experimental candidates.
    Aggressive,
}

/// Capability-independent intent derived from a [`Profile`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProfileIntent {
    /// Profile that produced this intent.
    pub profile: Profile,
    /// Abstract CPU governor preference.
    pub governor: PerformanceIntent,
    /// Abstract CPU energy preference.
    pub energy_preference: PerformanceIntent,
    /// Abstract aggressiveness level.
    pub aggressiveness: Aggressiveness,
}

/// A closed feature family used by preserve and opt-in policy rules.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Feature {
    /// CPU frequency governor.
    CpuGovernor,
    /// CPU frequency bounds.
    CpuFrequency,
    /// CPU energy-performance preference.
    CpuEnergyPreference,
    /// CPU boost/turbo state.
    CpuBoost,
    /// Platform/firmware performance profile.
    PlatformProfile,
    /// Existing cgroup CPU controls.
    CgroupCpu,
    /// CPU placement and topology-sensitive policies.
    CpuPlacement,
    /// GPU performance controls.
    GpuTuning,
    /// IRQ affinity policy.
    IrqTuning,
    /// Scheduler and workload policy.
    SchedulerTuning,
    /// Memory/VM controls.
    MemoryVm,
    /// Transparent huge pages.
    TransparentHugePages,
    /// A future reviewed capability family not yet named by the profile
    /// vocabulary.
    Custom(CapabilityId),
}

impl Feature {
    /// Infer a feature family from a stable capability identifier.
    pub fn from_capability(capability: &CapabilityId) -> Self {
        match capability.as_str() {
            capability_ids::CPU_POLICY_GOVERNOR => Self::CpuGovernor,
            capability_ids::CPU_POLICY_FREQUENCY_MIN | capability_ids::CPU_POLICY_FREQUENCY_MAX => {
                Self::CpuFrequency
            }
            capability_ids::CPU_POLICY_ENERGY_PREFERENCE => Self::CpuEnergyPreference,
            capability_ids::CPU_BOOST => Self::CpuBoost,
            capability_ids::PLATFORM_PROFILE => Self::PlatformProfile,
            capability_ids::CGROUP_CPU_WEIGHT
            | capability_ids::CGROUP_CPU_MAX
            | capability_ids::CGROUP_CPUSET_CPUS
            | capability_ids::CGROUP_UCLAMP
            | capability_ids::CGROUP_IO_WEIGHT
            | capability_ids::CGROUP_WORKLOAD
            | capability_ids::CGROUP_BACKGROUND => Self::CgroupCpu,
            capability_ids::GPU_PERFORMANCE_PROFILE | capability_ids::GPU_POWER_LIMIT => {
                Self::GpuTuning
            }
            capability_ids::IRQ_AFFINITY => Self::IrqTuning,
            capability_ids::KERNEL_SYSCTL_RUNTIME | capability_ids::MEMORY_THP => Self::MemoryVm,
            capability_ids::SCHEDULER
            | capability_ids::PROCESS_PLACEMENT
            | capability_ids::PROCESS_NICE
            | capability_ids::PROCESS_IOPRIO
            | capability_ids::CHILD_SUPERVISION => Self::SchedulerTuning,
            "cpu.topology" | "cpu.capacity" => Self::CpuPlacement,
            _ => Self::Custom(capability.clone()),
        }
    }

    /// Whether this family is experimental by default.
    pub fn is_experimental(&self) -> bool {
        matches!(
            self,
            Self::GpuTuning | Self::IrqTuning | Self::SchedulerTuning
        )
    }
}

impl fmt::Display for Feature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CpuGovernor => f.write_str("CPU governor"),
            Self::CpuFrequency => f.write_str("CPU frequency"),
            Self::CpuEnergyPreference => f.write_str("CPU EPP"),
            Self::CpuBoost => f.write_str("CPU boost/turbo"),
            Self::PlatformProfile => f.write_str("platform profile"),
            Self::CgroupCpu => f.write_str("cgroup CPU policy"),
            Self::CpuPlacement => f.write_str("CPU placement"),
            Self::GpuTuning => f.write_str("GPU tuning"),
            Self::IrqTuning => f.write_str("IRQ tuning"),
            Self::SchedulerTuning => f.write_str("scheduler/workload policy"),
            Self::MemoryVm => f.write_str("memory/VM policy"),
            Self::TransparentHugePages => f.write_str("THP"),
            Self::Custom(capability) => write!(f, "custom capability {}", capability),
        }
    }
}

/// Source precedence for explicit policy proposals.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PolicySource {
    /// The profile's abstract default.
    Profile,
    /// Invocation-level selection, already constrained by trusted config.
    Invocation,
    /// User configuration.
    User,
    /// Administrator/system configuration.
    System,
}

impl PolicySource {
    const fn precedence(self) -> u8 {
        match self {
            Self::Profile => 0,
            Self::Invocation => 1,
            Self::User => 2,
            Self::System => 3,
        }
    }
}

/// A preserve rule that suppresses a profile or lower-level mutation intent.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PreserveRule {
    /// Feature family to preserve.
    pub feature: Feature,
    /// Optional exact target; `None` preserves the entire family.
    pub target: Option<TargetId>,
    /// Explainable reason retained in the plan.
    pub reason: String,
}

impl PreserveRule {
    /// Construct a family-wide preserve rule.
    pub fn family(feature: Feature, reason: impl Into<String>) -> Self {
        Self {
            feature,
            target: None,
            reason: reason.into(),
        }
    }

    /// Construct a target-specific preserve rule.
    pub fn target(feature: Feature, target: TargetId, reason: impl Into<String>) -> Self {
        Self {
            feature,
            target: Some(target),
            reason: reason.into(),
        }
    }
}

/// A typed proposal with an explicit trust/source precedence.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PolicyProposal {
    /// Source that supplied the proposal.
    pub source: PolicySource,
    /// Closed typed request.
    pub request: PolicyRequest,
}

impl PolicyProposal {
    /// Construct a proposal.
    pub fn new(source: PolicySource, request: PolicyRequest) -> Self {
        Self { source, request }
    }
}

/// Effective planner policy after configuration trust resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannerPolicy {
    /// Selected high-level profile.
    pub profile: Profile,
    /// Report-only or mutation-admitting mode.
    pub mode: PolicyMode,
    /// Highest risk admitted by trusted policy.
    pub max_risk: RiskClass,
    /// Whether experimental features are permitted at all.
    pub allow_experimental: bool,
    /// Default requiredness for future parser-created requests.
    pub required_default: bool,
    /// Positive session timeout retained for the transaction boundary.
    pub session_timeout_ms: u64,
    /// Higher-precedence preservation rules.
    pub preserves: Vec<PreserveRule>,
    /// Explicit feature opt-ins.
    pub explicit_opt_ins: BTreeSet<Feature>,
    /// Explicit desired-value proposals.
    pub proposals: Vec<PolicyProposal>,
}

impl PlannerPolicy {
    /// Construct a mutation-admitting policy for a profile with experimental
    /// features disabled until the caller opts in.
    pub fn for_profile(profile: Profile) -> Self {
        Self {
            profile,
            mode: PolicyMode::Boost,
            max_risk: RiskClass::Critical,
            allow_experimental: false,
            required_default: false,
            session_timeout_ms: 30_000,
            preserves: Vec::new(),
            explicit_opt_ins: BTreeSet::new(),
            proposals: Vec::new(),
        }
    }

    /// Convert the existing trusted configuration policy into planner input.
    pub fn from_policy(profile: Profile, policy: &Policy) -> Self {
        let mut result = Self {
            profile,
            mode: policy.mode,
            max_risk: policy.max_risk,
            allow_experimental: policy.allow_experimental,
            required_default: policy.required_default,
            session_timeout_ms: policy.session_timeout_ms,
            preserves: Vec::new(),
            explicit_opt_ins: BTreeSet::new(),
            proposals: Vec::new(),
        };
        result.proposals.extend(
            policy
                .requests
                .iter()
                .cloned()
                .map(|request| PolicyProposal::new(PolicySource::Invocation, request)),
        );
        result
    }

    /// Return a report-only policy for a profile.
    pub fn report(profile: Profile) -> Self {
        let mut result = Self::for_profile(profile);
        result.mode = PolicyMode::Report;
        result
    }

    /// Add a family-wide preserve rule.
    pub fn preserve(mut self, feature: Feature, reason: impl Into<String>) -> Self {
        self.preserves.push(PreserveRule::family(feature, reason));
        self
    }

    /// Add a target-specific preserve rule.
    pub fn preserve_target(
        mut self,
        feature: Feature,
        target: TargetId,
        reason: impl Into<String>,
    ) -> Self {
        self.preserves
            .push(PreserveRule::target(feature, target, reason));
        self
    }

    /// Explicitly allow a feature family that requires opt-in.
    pub fn opt_in(mut self, feature: Feature) -> Self {
        self.explicit_opt_ins.insert(feature);
        self
    }

    /// Set the experimental permission gate.
    pub const fn with_experimental_permission(mut self, allowed: bool) -> Self {
        self.allow_experimental = allowed;
        self
    }

    /// Set report/boost mode.
    pub const fn with_mode(mut self, mode: PolicyMode) -> Self {
        self.mode = mode;
        self
    }

    /// Set the maximum risk admitted by policy.
    pub const fn with_max_risk(mut self, risk: RiskClass) -> Self {
        self.max_risk = risk;
        self
    }

    /// Add an invocation-level proposal.
    pub fn request(mut self, request: PolicyRequest) -> Self {
        self.proposals
            .push(PolicyProposal::new(PolicySource::Invocation, request));
        self
    }

    /// Add a proposal with an explicit precedence source.
    pub fn proposal(mut self, source: PolicySource, request: PolicyRequest) -> Self {
        self.proposals.push(PolicyProposal::new(source, request));
        self
    }

    fn is_preserved(&self, feature: &Feature, target: Option<&TargetId>) -> Option<&str> {
        self.preserves.iter().find_map(|rule| {
            if &rule.feature != feature {
                return None;
            }
            match (&rule.target, target) {
                (None, _) => Some(rule.reason.as_str()),
                (Some(rule_target), Some(actual)) if rule_target == actual => {
                    Some(rule.reason.as_str())
                }
                _ => None,
            }
        })
    }

    fn is_opted_in(&self, feature: &Feature) -> bool {
        self.explicit_opt_ins.contains(feature)
    }
}

/// Opaque but bounded text observed on a report-only interface.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ObservedText(String);

impl ObservedText {
    /// Validate and retain a current-state text value.
    pub fn new(value: impl Into<String>) -> Result<Self, SysboostError> {
        let value = value.into();
        if value.is_empty() || value.len() > 1024 || value.bytes().any(|byte| byte == 0) {
            return Err(SysboostError::new(
                ErrorCode::InvalidInput,
                "observed text is empty, oversized, or contains NUL",
            ));
        }
        Ok(Self(value))
    }

    /// Borrow the normalized text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ObservedText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Typed interface/control family used in plan explanations.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ControlId {
    /// CPU governor control.
    CpuGovernor,
    /// CPU energy-performance preference control.
    CpuEnergyPreference,
    /// CPU frequency bounds control.
    CpuFrequency,
    /// CPU boost/turbo control.
    CpuBoost,
    /// Platform performance profile control.
    PlatformProfile,
    /// Cgroup CPU weight control.
    CgroupCpuWeight,
    /// Cgroup CPU quota/period control.
    CgroupCpuMax,
    /// Cgroup CPU placement control.
    CgroupCpuset,
    /// Cgroup I/O weight control.
    CgroupIoWeight,
    /// Managed workload cgroup lifecycle.
    CgroupWorkload,
    /// Managed conservative background cgroup lifecycle.
    CgroupBackground,
    /// GPU performance profile control.
    GpuPerformanceProfile,
    /// GPU power limit control.
    GpuPowerLimit,
    /// IRQ affinity control.
    IrqAffinity,
    /// Scheduler/workload control family.
    SchedulerWorkload,
    /// Explicit process cgroup placement control.
    ProcessPlacement,
    /// Explicit process nice control.
    ProcessNice,
    /// Explicit process I/O-priority control.
    ProcessIoPriority,
    /// Cgroup utilization-clamp control.
    CgroupUclamp,
    /// Cgroup utilization-clamp minimum control.
    CgroupUclampMin,
    /// Cgroup utilization-clamp maximum control.
    CgroupUclampMax,
    /// Transparent huge-page control.
    TransparentHugePages,
    /// Runtime memory/VM policy family.
    MemoryVm,
    /// A report-only control not yet admitted to the closed operation set.
    ReportOnly,
}

impl fmt::Display for ControlId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CpuGovernor => "CPU governor",
            Self::CpuEnergyPreference => "CPU EPP",
            Self::CpuFrequency => "CPU frequency",
            Self::CpuBoost => "CPU boost/turbo",
            Self::PlatformProfile => "platform profile",
            Self::CgroupCpuWeight => "cgroup CPU weight",
            Self::CgroupCpuMax => "cgroup CPU quota",
            Self::CgroupCpuset => "cgroup CPU placement",
            Self::CgroupIoWeight => "cgroup I/O weight",
            Self::CgroupWorkload => "workload cgroup",
            Self::CgroupBackground => "conservative background cgroup",
            Self::GpuPerformanceProfile => "GPU performance profile",
            Self::GpuPowerLimit => "GPU power limit",
            Self::IrqAffinity => "IRQ affinity",
            Self::SchedulerWorkload => "scheduler/workload policy",
            Self::ProcessPlacement => "process cgroup placement",
            Self::ProcessNice => "process nice",
            Self::ProcessIoPriority => "process I/O priority",
            Self::CgroupUclamp => "cgroup uclamp",
            Self::CgroupUclampMin => "cgroup uclamp minimum",
            Self::CgroupUclampMax => "cgroup uclamp maximum",
            Self::TransparentHugePages => "THP",
            Self::MemoryVm => "memory/VM policy",
            Self::ReportOnly => "report-only control",
        })
    }
}

/// A current or proposed value that is either a closed typed value or a
/// bounded report-only observation.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum PlanValue {
    /// A value belonging to the closed mutation vocabulary.
    Typed(TypedValue),
    /// A value retained for an interface without an approved mutation type.
    Text(ObservedText),
}

impl fmt::Display for PlanValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&render_value(self))
    }
}

/// Whether a current-state fact is known or deliberately indeterminate.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum CurrentValue {
    /// A typed or bounded current value.
    Known(PlanValue),
    /// The adapter saw the target but could not safely interpret its value.
    Unknown(String),
}

/// A typed target reference supplied by discovery rather than parsed by the
/// planner from an opaque target string.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum TypedTarget {
    /// CPUFreq policy.
    CpuPolicy(CpuPolicyId),
    /// Host-wide CPU control target.
    CpuSystem,
    /// Existing cgroup.
    Cgroup(CgroupId),
    /// Explicit process identity.
    Process(ProcessId),
    /// GPU device.
    Gpu(GpuId),
    /// IRQ number.
    Irq(IrqId),
    /// Approved sysctl target, whose key is already closed and typed.
    Sysctl(ApprovedSysctlKey),
}

/// One immutable current-state fact consumed by the planner.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CurrentStateFact {
    /// Stable capability identity.
    pub capability: CapabilityId,
    /// Opaque target identity used for plan grouping.
    pub target: TargetId,
    /// Typed interface/control family.
    pub control: ControlId,
    /// Current value or an explicit indeterminate reason.
    pub value: CurrentValue,
    /// Current-state fingerprint used as a future apply precondition.
    pub fingerprint: Option<StateFingerprint>,
    /// Stable target identity evidence, when the adapter can prove it.
    pub target_identity: Option<TargetIdentity>,
    /// Values the interface explicitly advertised as supported.
    pub supported_values: Vec<PlanValue>,
    /// Evidence specific to this current-state observation.
    pub evidence: Vec<CapabilityEvidence>,
    /// Typed target required to construct a closed mutation kind.
    pub typed_target: Option<TypedTarget>,
}

impl CurrentStateFact {
    /// Construct a known current-state fact.
    pub fn known(
        capability: CapabilityId,
        target: TargetId,
        control: ControlId,
        value: PlanValue,
        fingerprint: StateFingerprint,
    ) -> Self {
        Self {
            capability,
            target,
            control,
            value: CurrentValue::Known(value),
            fingerprint: Some(fingerprint),
            target_identity: None,
            supported_values: Vec::new(),
            evidence: Vec::new(),
            typed_target: None,
        }
    }

    /// Construct an indeterminate current-state fact.
    pub fn unknown(
        capability: CapabilityId,
        target: TargetId,
        control: ControlId,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            capability,
            target,
            control,
            value: CurrentValue::Unknown(reason.into()),
            fingerprint: None,
            target_identity: None,
            supported_values: Vec::new(),
            evidence: Vec::new(),
            typed_target: None,
        }
    }

    /// Add advertised supported values to a known fact.
    pub fn with_supported_values(mut self, values: Vec<PlanValue>) -> Self {
        self.supported_values = values;
        self
    }

    /// Attach stable target identity evidence.
    pub const fn with_target_identity(mut self, identity: TargetIdentity) -> Self {
        self.target_identity = Some(identity);
        self
    }

    /// Attach identity evidence only when the adapter proved it.
    pub const fn with_optional_target_identity(mut self, identity: Option<TargetIdentity>) -> Self {
        self.target_identity = identity;
        self
    }

    /// Attach the typed target reference used to build a closed operation.
    pub fn with_typed_target(mut self, target: TypedTarget) -> Self {
        self.typed_target = Some(target);
        self
    }

    /// Attach read-only evidence for this observation.
    pub fn with_evidence(mut self, evidence: Vec<CapabilityEvidence>) -> Self {
        self.evidence = evidence;
        self
    }
}

/// Complete current-state input to the pure planner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentState {
    /// Observation timestamp.
    pub observed_at: Timestamp,
    /// Canonical current-state facts.
    pub facts: Vec<CurrentStateFact>,
}

impl CurrentState {
    /// Construct and canonicalize current-state facts.
    pub fn new(
        observed_at: Timestamp,
        mut facts: Vec<CurrentStateFact>,
    ) -> Result<Self, SysboostError> {
        facts.sort_by(|left, right| {
            left.capability
                .cmp(&right.capability)
                .then_with(|| left.target.cmp(&right.target))
                .then_with(|| left.control.cmp(&right.control))
        });
        for index in 1..facts.len() {
            let previous = &facts[index - 1];
            let current = &facts[index];
            if previous.capability == current.capability
                && previous.target == current.target
                && previous.control == current.control
                && previous != current
            {
                return Err(SysboostError::new(
                    ErrorCode::PlanningError,
                    "current-state inventory contains contradictory duplicate facts",
                )
                .with_stage(Stage::Plan)
                .with_capability(current.capability.clone())
                .with_target(current.target.clone()));
            }
        }
        facts.dedup();
        Ok(Self { observed_at, facts })
    }

    /// Construct an empty current-state input.
    pub const fn empty(observed_at: Timestamp) -> Self {
        Self {
            observed_at,
            facts: Vec::new(),
        }
    }
}

/// Snapshot admission metadata for one operation family.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SnapshotContract {
    /// Whether a complete original state is defined.
    pub defined: bool,
    /// Whether the typed original value is representable.
    pub typed_preimage: bool,
    /// Whether raw bytes are also retained by the future backend.
    pub raw_preimage: bool,
    /// Equality semantics for the captured state.
    pub equality: EqualityKind,
}

impl SnapshotContract {
    /// Contract marker for an entry that is not executable.
    pub const fn not_applicable() -> Self {
        Self {
            defined: false,
            typed_preimage: false,
            raw_preimage: false,
            equality: EqualityKind::ByteExact,
        }
    }

    /// Whether this contract can admit snapshotting.
    pub const fn is_complete(self) -> bool {
        self.defined && self.typed_preimage
    }
}

/// Restore admission metadata for one operation family.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RestoreContract {
    /// Whether restore semantics are defined.
    pub defined: bool,
    /// Compare-and-restore mode when defined.
    pub mode: Option<RestoreMode>,
    /// Equality used to prove the original value after restore.
    pub equality: EqualityKind,
}

impl RestoreContract {
    /// Contract marker for an entry that is not executable.
    pub const fn not_applicable() -> Self {
        Self {
            defined: false,
            mode: None,
            equality: EqualityKind::ByteExact,
        }
    }

    /// Whether restore semantics can admit a future mutation.
    pub const fn is_complete(self) -> bool {
        self.defined && self.mode.is_some()
    }
}

/// Verification admission metadata for one operation family.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct VerificationContract {
    /// Whether a verification rule is defined.
    pub defined: bool,
    /// Whether verification performs a bounded readback.
    pub readback: bool,
    /// Equality used by the readback verifier.
    pub equality: EqualityKind,
}

impl VerificationContract {
    /// Contract marker for an entry that is not executable.
    pub const fn not_applicable() -> Self {
        Self {
            defined: false,
            readback: false,
            equality: EqualityKind::ByteExact,
        }
    }

    /// Whether readback verification can admit a future mutation.
    pub const fn is_complete(self) -> bool {
        self.defined && self.readback
    }
}

/// Declarative admission contract for a compiled-in typed backend operation.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct OperationContract {
    /// Stable operation identifier.
    pub operation: OperationId,
    /// Capability owned by this operation.
    pub capability: CapabilityId,
    /// Compiled-in backend owner.
    pub backend: BackendId,
    /// Target category admitted by the backend.
    pub target_kind: TargetKind,
    /// Human-facing operation family.
    pub control: ControlId,
    /// Equality used throughout snapshot, verify, and restore.
    pub equality: EqualityKind,
    /// Risk classification.
    pub risk: RiskClass,
    /// Product feature class.
    pub classification: FeatureClass,
    /// Whether the operation requires a feature-specific explicit opt-in.
    pub explicit_opt_in: bool,
    /// Whether a stable target identity is required before mutation.
    pub target_identity_required: bool,
    /// Whether a known current state is required before mutation.
    pub current_state_required: bool,
    /// Operation families that must be applied first on the same target.
    pub dependencies: Vec<OperationId>,
    /// Snapshot contract.
    pub snapshot: SnapshotContract,
    /// Restore contract.
    pub restore: RestoreContract,
    /// Verification contract.
    pub verification: VerificationContract,
}

impl OperationContract {
    /// Construct a complete compare-and-restore contract for a reviewed typed
    /// operation.  This declares a future backend contract; it performs no I/O
    /// and does not implement mutation.
    #[allow(clippy::too_many_arguments)]
    pub fn complete(
        operation: OperationId,
        capability: CapabilityId,
        backend: BackendId,
        target_kind: TargetKind,
        control: ControlId,
        equality: EqualityKind,
        risk: RiskClass,
        classification: FeatureClass,
        explicit_opt_in: bool,
    ) -> Self {
        Self {
            operation,
            capability,
            backend,
            target_kind,
            control,
            equality,
            risk,
            classification,
            explicit_opt_in,
            target_identity_required: true,
            current_state_required: true,
            dependencies: Vec::new(),
            snapshot: SnapshotContract {
                defined: true,
                typed_preimage: true,
                raw_preimage: false,
                equality,
            },
            restore: RestoreContract {
                defined: true,
                mode: Some(RestoreMode::CompareAndRestore),
                equality,
            },
            verification: VerificationContract {
                defined: true,
                readback: true,
                equality,
            },
        }
    }

    /// Validate the internal integrity of a declarative backend contract.
    pub fn validate(&self) -> Result<(), SysboostError> {
        if self.snapshot.equality != self.equality
            || self.restore.equality != self.equality
            || self.verification.equality != self.equality
        {
            return Err(SysboostError::new(
                ErrorCode::PlanningError,
                "operation contract uses inconsistent equality semantics",
            )
            .with_stage(Stage::Plan)
            .with_capability(self.capability.clone()));
        }
        if self
            .dependencies
            .iter()
            .any(|dependency| dependency == &self.operation)
        {
            return Err(SysboostError::new(
                ErrorCode::PlanningError,
                "operation contract depends on itself",
            )
            .with_stage(Stage::Plan)
            .with_capability(self.capability.clone()));
        }
        let mut dependencies = self.dependencies.clone();
        dependencies.sort();
        dependencies.dedup();
        if dependencies.len() != self.dependencies.len() {
            return Err(SysboostError::new(
                ErrorCode::PlanningError,
                "operation contract contains a duplicate dependency",
            )
            .with_stage(Stage::Plan)
            .with_capability(self.capability.clone()));
        }
        Ok(())
    }

    /// Whether all snapshot, restore, verification, and target gates exist.
    pub const fn is_complete(&self) -> bool {
        self.snapshot.is_complete()
            && self.restore.is_complete()
            && self.verification.is_complete()
            && self.target_identity_required
            && self.current_state_required
    }
}

/// Deterministic collection of approved operation contracts.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OperationCatalog {
    contracts: Vec<OperationContract>,
}

impl OperationCatalog {
    /// Construct a catalog and canonicalize contract order.  Completeness is
    /// checked when an operation is proposed so an unused future contract can
    /// remain visible as an invalid test fixture without becoming executable.
    pub fn new(mut contracts: Vec<OperationContract>) -> Self {
        contracts.sort_by(|left, right| {
            left.operation
                .cmp(&right.operation)
                .then_with(|| left.backend.cmp(&right.backend))
                .then_with(|| left.capability.cmp(&right.capability))
        });
        Self { contracts }
    }

    /// Construct an empty catalog.
    pub const fn empty() -> Self {
        Self {
            contracts: Vec::new(),
        }
    }

    /// Return all contracts in canonical order.
    pub fn contracts(&self) -> &[OperationContract] {
        &self.contracts
    }

    /// Validate operation ownership and contract structure.
    pub fn validate(&self) -> Result<(), SysboostError> {
        for contract in &self.contracts {
            contract.validate()?;
        }
        for index in 1..self.contracts.len() {
            if self.contracts[index - 1].operation == self.contracts[index].operation {
                return Err(SysboostError::new(
                    ErrorCode::InvariantViolation,
                    "operation catalog contains duplicate operation ownership",
                )
                .with_stage(Stage::Plan)
                .with_backend(self.contracts[index].backend.clone()));
            }
        }
        Ok(())
    }

    fn find(
        &self,
        capability: &CapabilityId,
        operation: &OperationId,
    ) -> Option<&OperationContract> {
        self.contracts
            .iter()
            .find(|contract| &contract.capability == capability && &contract.operation == operation)
    }
}

/// Classification of one visible plan decision.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PlanAction {
    /// A typed, future-executable mutation was admitted.
    Mutation,
    /// Current state already equals the resolved target.
    NoOp,
    /// The interface or reviewed operation is not supported.
    Unsupported,
    /// Policy intentionally leaves the current state unchanged.
    Preserved,
    /// A feature-specific opt-in is missing.
    ExplicitOptInRequired,
    /// Experimental permission is disabled.
    ExperimentalDisabled,
    /// A trusted policy restriction prevented the proposal.
    DeniedByPolicy,
    /// Read access was denied by the capability layer.
    CapabilityDenied,
    /// Evidence was incomplete or contradictory.
    Indeterminate,
}

impl PlanAction {
    /// Whether this action belongs in the executable mutation set.
    pub const fn is_executable(self) -> bool {
        matches!(self, Self::Mutation)
    }
}

impl fmt::Display for PlanAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Mutation => "change",
            Self::NoOp => "no-op",
            Self::Unsupported => "unsupported",
            Self::Preserved => "preserved",
            Self::ExplicitOptInRequired => "explicit opt-in required",
            Self::ExperimentalDisabled => "experimental disabled",
            Self::DeniedByPolicy => "denied by policy",
            Self::CapabilityDenied => "capability denied",
            Self::Indeterminate => "indeterminate",
        })
    }
}

/// Experimental gating state carried into plan rendering and audit output.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ExperimentalStatus {
    /// The operation is not experimental.
    NotExperimental,
    /// Experimental permission is disabled.
    Disabled,
    /// Permission exists but the feature-specific opt-in is absent.
    OptInRequired,
    /// Permission and feature opt-in were both supplied.
    Enabled,
}

impl fmt::Display for ExperimentalStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotExperimental => "not-experimental",
            Self::Disabled => "disabled",
            Self::OptInRequired => "opt-in-required",
            Self::Enabled => "enabled",
        })
    }
}

/// One explainable policy decision, including optional executable mutation
/// data and all future transaction admission metadata.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PlanItem {
    /// Stable capability identity.
    pub capability: CapabilityId,
    /// Stable typed operation family identifier.
    pub operation: OperationId,
    /// Compiled-in backend owner when known.
    pub backend: Option<BackendId>,
    /// Opaque target identity, absent only for aggregate unsupported entries.
    pub target: Option<TargetId>,
    /// Human-facing interface/control family.
    pub control: ControlId,
    /// Current value when known.
    pub current: Option<PlanValue>,
    /// Desired value when the policy defines one.
    pub desired: Option<PlanValue>,
    /// Action classification.
    pub action: PlanAction,
    /// Feature safety class.
    pub feature: Feature,
    /// Product maturity classification.
    pub feature_class: FeatureClass,
    /// Blast-radius classification.
    pub risk: RiskClass,
    /// Whether a feature-specific opt-in is part of admission.
    pub explicit_opt_in_required: bool,
    /// Experimental permission state.
    pub experimental: ExperimentalStatus,
    /// Evidence supporting applicability.
    pub evidence: Vec<CapabilityEvidence>,
    /// Explainable policy and capability rationale.
    pub rationale: String,
    /// Structured skip/no-op reason when applicable.
    pub reason: Option<String>,
    /// Stable target identity evidence, when known.
    pub target_identity: Option<TargetIdentity>,
    /// Expected snapshot contract.
    pub snapshot: SnapshotContract,
    /// Expected restore contract.
    pub restore: RestoreContract,
    /// Expected verification contract.
    pub verification: VerificationContract,
    /// Dependencies in executable mutation ID form.
    pub dependencies: Vec<MutationId>,
    /// Closed transaction mutation, present only for `Mutation` actions.
    pub mutation: Option<PlannedMutation>,
}

impl PlanItem {
    /// Validate the relationship between decision metadata and a mutation.
    pub fn validate(&self) -> Result<(), SysboostError> {
        if !self.action.is_executable() {
            if self.mutation.is_some() {
                return Err(SysboostError::new(
                    ErrorCode::PlanningError,
                    "non-mutation plan item contains executable mutation data",
                )
                .with_stage(Stage::Plan));
            }
            return Ok(());
        }

        let Some(mutation) = self.mutation.as_ref() else {
            return Err(SysboostError::new(
                ErrorCode::PlanningError,
                "mutation plan item has no typed mutation payload",
            )
            .with_stage(Stage::Plan));
        };
        if self.backend.is_none()
            || self.target.is_none()
            || self.target_identity.is_none()
            || self.current.is_none()
            || self.desired.is_none()
            || self.evidence.is_empty()
        {
            return Err(SysboostError::new(
                ErrorCode::PlanningError,
                "mutation plan item is missing target, state, identity, or evidence metadata",
            )
            .with_stage(Stage::Plan)
            .with_mutation(mutation.mutation_id));
        }
        if !self.snapshot.is_complete()
            || !self.restore.is_complete()
            || !self.verification.is_complete()
        {
            return Err(SysboostError::new(
                ErrorCode::PlanningError,
                "mutation plan item lacks a complete snapshot/restore/verification contract",
            )
            .with_stage(Stage::Plan)
            .with_mutation(mutation.mutation_id));
        }
        if self.operation != mutation.kind.operation_id()
            || self.capability != mutation.capability
            || self.target.as_ref() != Some(&mutation.target)
            || self.desired != Some(PlanValue::Typed(mutation.desired.clone()))
            || self.dependencies != mutation.dependencies
            || self.snapshot.equality != mutation.equality
            || self.restore.equality != mutation.equality
            || self.verification.equality != mutation.equality
        {
            return Err(SysboostError::new(
                ErrorCode::PlanningError,
                "plan item metadata disagrees with its typed mutation",
            )
            .with_stage(Stage::Plan)
            .with_mutation(mutation.mutation_id));
        }
        Ok(())
    }
}

/// Pure planner input.  All facts are supplied by discovery/current-state
/// adapters; the planner itself performs no host probing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannerInput {
    /// Effective profile and policy options.
    pub policy: PlannerPolicy,
    /// Capability evidence inventory.
    pub inventory: CapabilityInventory,
    /// Current values and precondition fingerprints.
    pub current_state: CurrentState,
}

/// Result of policy resolution before digesting it into a transaction plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyResolution {
    /// Profile used for resolution.
    pub profile: Profile,
    /// Canonically ordered decisions.
    pub items: Vec<PlanItem>,
}

/// Pure policy resolver backed by a reviewed operation catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyResolver {
    /// Declarative backend operation contracts.
    pub catalog: OperationCatalog,
}

impl PolicyResolver {
    /// Construct a resolver.
    pub fn new(catalog: OperationCatalog) -> Self {
        Self { catalog }
    }

    /// Resolve policy and evidence into a complete explainable decision set.
    pub fn resolve(&self, input: &PlannerInput) -> Result<PolicyResolution, SysboostError> {
        validate_policy(&input.policy)?;
        self.catalog.validate()?;
        let proposals = select_proposals(&input.policy.proposals)?;
        let descriptors = DescriptorIndex::new(&input.inventory);
        let mut candidates = BTreeMap::<CandidateKey, Candidate>::new();

        for (order, spec) in feature_specs().into_iter().enumerate() {
            let capability = spec.capability.clone();
            let operation = spec.operation.clone();
            let facts = input
                .current_state
                .facts
                .iter()
                .filter(|fact| fact.capability == capability && fact.control == spec.control)
                .collect::<Vec<_>>();
            let explicit_targets = proposals
                .values()
                .filter(|proposal| {
                    proposal.request.capability == capability
                        && proposal.request.operation.operation_id() == operation
                })
                .map(|proposal| proposal.request.target.clone());
            let mut targets = facts
                .iter()
                .map(|fact| Some(fact.target.clone()))
                .chain(explicit_targets.map(Some))
                .collect::<Vec<_>>();
            if targets.is_empty() {
                targets.push(None);
            }
            targets.sort();
            targets.dedup();

            for target in targets {
                let fact = target
                    .as_ref()
                    .and_then(|target| facts.iter().find(|fact| &fact.target == target).copied());
                let proposal = proposal_for(&proposals, &capability, &operation, target.as_ref());
                let candidate = self.resolve_spec(
                    &input.policy,
                    &descriptors,
                    &spec,
                    order as u16,
                    target,
                    fact,
                    proposal,
                )?;
                insert_candidate(&mut candidates, candidate)?;
            }
        }

        for proposal in proposals.values() {
            if feature_specs().iter().any(|spec| {
                spec.capability == proposal.request.capability
                    && spec.operation == proposal.request.operation.operation_id()
            }) {
                continue;
            }
            let candidate = self.resolve_custom(
                &input.policy,
                &descriptors,
                proposal,
                &input.current_state,
                feature_specs().len() as u16,
            )?;
            insert_candidate(&mut candidates, candidate)?;
        }

        finalize_candidates(&input.policy, candidates)
    }

    #[allow(clippy::too_many_arguments)]
    fn resolve_spec(
        &self,
        policy: &PlannerPolicy,
        descriptors: &DescriptorIndex<'_>,
        spec: &FeatureSpec,
        order: u16,
        target: Option<TargetId>,
        fact: Option<&CurrentStateFact>,
        proposal: Option<&PolicyProposal>,
    ) -> Result<Candidate, SysboostError> {
        let required =
            proposal.is_some_and(|proposal| proposal.request.required || policy.required_default);
        let candidate =
            self.resolve_spec_inner(policy, descriptors, spec, order, target, fact, proposal)?;
        if required
            && !matches!(
                candidate.item.action,
                PlanAction::Mutation | PlanAction::NoOp
            )
        {
            let mut error = SysboostError::new(
                ErrorCode::PlanningError,
                "required policy request could not be admitted",
            )
            .with_stage(Stage::Plan)
            .with_capability(candidate.item.capability);
            if let Some(target) = candidate.item.target {
                error = error.with_target(target);
            }
            return Err(error);
        }
        Ok(candidate)
    }

    #[allow(clippy::too_many_arguments)]
    fn resolve_spec_inner(
        &self,
        policy: &PlannerPolicy,
        descriptors: &DescriptorIndex<'_>,
        spec: &FeatureSpec,
        order: u16,
        target: Option<TargetId>,
        fact: Option<&CurrentStateFact>,
        proposal: Option<&PolicyProposal>,
    ) -> Result<Candidate, SysboostError> {
        let capability = spec.capability.clone();
        let operation = spec.operation.clone();
        let descriptor = descriptors.select(&capability);
        let feature = spec.feature.clone();
        let current = fact.and_then(|fact| match &fact.value {
            CurrentValue::Known(value) => Some(value.clone()),
            CurrentValue::Unknown(_) => None,
        });
        let target_identity = fact.and_then(|fact| fact.target_identity);
        let mut evidence = descriptor
            .map(|descriptor| descriptor.evidence.clone())
            .unwrap_or_default();
        if let Some(fact) = fact {
            evidence.extend(fact.evidence.clone());
        }
        canonicalize_evidence(&mut evidence);
        let class = descriptor
            .map(|descriptor| descriptor.classification)
            .unwrap_or(spec.classification);
        let risk = descriptor
            .map(|descriptor| descriptor.risk)
            .unwrap_or(spec.risk);
        let explicit_required = spec.explicit_opt_in;
        let experimental = if class == FeatureClass::Experimental || feature.is_experimental() {
            if !policy.allow_experimental {
                ExperimentalStatus::Disabled
            } else if explicit_required && !policy.is_opted_in(&feature) {
                ExperimentalStatus::OptInRequired
            } else {
                ExperimentalStatus::Enabled
            }
        } else {
            ExperimentalStatus::NotExperimental
        };

        if let Some(reason) = policy.is_preserved(&feature, target.as_ref()) {
            return Ok(Candidate::non_mutating(
                order,
                capability,
                operation,
                descriptor.map(|value| value.backend.clone()),
                target,
                spec.control,
                current,
                None,
                PlanAction::Preserved,
                feature,
                class,
                risk,
                explicit_required,
                experimental,
                evidence,
                "policy preserve override takes precedence over profile intent",
                Some(reason.to_owned()),
                target_identity,
            ));
        }

        let (desired, desired_unavailable_reason) = if let Some(proposal) = proposal {
            (
                Some(PlanValue::Typed(proposal.request.operation.typed_value())),
                None,
            )
        } else {
            profile_desired(policy.profile, spec, fact)
        };

        let descriptor_action = match descriptor.map(|descriptor| descriptor.state) {
            None => Some((
                PlanAction::Unsupported,
                "capability evidence was not present in the inventory",
            )),
            Some(CapabilityState::Unsupported) => Some((
                PlanAction::Unsupported,
                "runtime interface was not detected",
            )),
            Some(CapabilityState::Denied) => Some((
                PlanAction::CapabilityDenied,
                "capability evidence was permission denied",
            )),
            Some(CapabilityState::Indeterminate) => Some((
                PlanAction::Indeterminate,
                "capability evidence was malformed or incomplete",
            )),
            Some(CapabilityState::ReadOnly)
                if desired.is_some() && current.as_ref() != desired.as_ref() =>
            {
                Some((
                    PlanAction::Unsupported,
                    "interface is readable but no mutation operation is admitted",
                ))
            }
            Some(CapabilityState::Available) | Some(CapabilityState::ReadOnly) => None,
        };

        if let Some((action, reason)) = descriptor_action {
            return Ok(Candidate::non_mutating(
                order,
                capability,
                operation,
                descriptor.map(|value| value.backend.clone()),
                target,
                spec.control,
                current,
                desired,
                action,
                feature,
                class,
                risk,
                explicit_required,
                experimental,
                evidence,
                reason,
                Some(reason.to_owned()),
                target_identity,
            ));
        }

        if let Some(reason) = desired_unavailable_reason {
            return Ok(Candidate::non_mutating(
                order,
                capability,
                operation,
                descriptor.map(|value| value.backend.clone()),
                target,
                spec.control,
                current,
                desired,
                PlanAction::Unsupported,
                feature,
                class,
                risk,
                explicit_required,
                experimental,
                evidence,
                reason,
                Some(reason.to_owned()),
                target_identity,
            ));
        }

        if desired.is_none() {
            let (action, reason) = if experimental == ExperimentalStatus::Disabled {
                (
                    PlanAction::ExperimentalDisabled,
                    "experimental permission is disabled by effective policy",
                )
            } else if spec.extreme_candidate
                && policy.profile == Profile::Extreme
                && experimental == ExperimentalStatus::OptInRequired
            {
                (
                    PlanAction::ExplicitOptInRequired,
                    "extreme profile considers this experimental family only after explicit opt-in",
                )
            } else {
                (
                    PlanAction::Preserved,
                    "profile has no executable target for this capability family",
                )
            };
            return Ok(Candidate::non_mutating(
                order,
                capability,
                operation,
                descriptor.map(|value| value.backend.clone()),
                target,
                spec.control,
                current,
                desired,
                action,
                feature,
                class,
                risk,
                explicit_required,
                experimental,
                evidence,
                reason,
                Some(reason.to_owned()),
                target_identity,
            ));
        }

        if current.as_ref() == desired.as_ref() {
            return Ok(Candidate::non_mutating(
                order,
                capability,
                operation,
                descriptor.map(|value| value.backend.clone()),
                target,
                spec.control,
                current,
                desired,
                PlanAction::NoOp,
                feature,
                class,
                risk,
                explicit_required,
                experimental,
                evidence,
                "current value already equals the resolved profile target",
                Some("no mutation is required".to_owned()),
                target_identity,
            ));
        }

        self.resolve_mutation(
            policy,
            descriptors,
            spec,
            order,
            target,
            fact,
            proposal,
            desired.expect("desired value was checked above"),
            current,
            target_identity,
            evidence,
            feature,
            class,
            risk,
            explicit_required,
            experimental,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn resolve_mutation(
        &self,
        policy: &PlannerPolicy,
        descriptors: &DescriptorIndex<'_>,
        spec: &FeatureSpec,
        order: u16,
        target: Option<TargetId>,
        fact: Option<&CurrentStateFact>,
        proposal: Option<&PolicyProposal>,
        desired: PlanValue,
        current: Option<PlanValue>,
        target_identity: Option<TargetIdentity>,
        evidence: Vec<CapabilityEvidence>,
        feature: Feature,
        class: FeatureClass,
        risk: RiskClass,
        explicit_required: bool,
        experimental: ExperimentalStatus,
    ) -> Result<Candidate, SysboostError> {
        let capability = spec.capability.clone();
        let operation = spec.operation.clone();
        let descriptor = descriptors
            .select(&capability)
            .expect("descriptor state was checked before resolve_mutation");

        if policy.mode == PolicyMode::Report {
            return Ok(Candidate::non_mutating(
                order,
                capability,
                operation,
                Some(descriptor.backend.clone()),
                target,
                spec.control,
                current,
                Some(desired),
                PlanAction::DeniedByPolicy,
                feature,
                class,
                risk,
                explicit_required,
                experimental,
                evidence,
                "report mode prohibits mutation admission",
                Some("select an explicit mutation-admitting policy mode".to_owned()),
                target_identity,
            ));
        }

        let contract = self.catalog.find(&capability, &operation);

        if experimental == ExperimentalStatus::Disabled {
            return Ok(Candidate::non_mutating(
                order,
                capability,
                operation,
                Some(descriptor.backend.clone()),
                target,
                spec.control,
                current,
                Some(desired),
                PlanAction::ExperimentalDisabled,
                feature,
                class,
                risk,
                explicit_required,
                experimental,
                evidence,
                "experimental permission is disabled by effective policy",
                Some("enable the trusted experimental policy permission".to_owned()),
                target_identity,
            ));
        }
        if experimental == ExperimentalStatus::OptInRequired {
            return Ok(Candidate::non_mutating(
                order,
                capability,
                operation,
                Some(descriptor.backend.clone()),
                target,
                spec.control,
                current,
                Some(desired),
                PlanAction::ExplicitOptInRequired,
                feature,
                class,
                risk,
                explicit_required,
                experimental,
                evidence,
                "experimental capability is supported but its feature opt-in is absent",
                Some("supply the feature-specific opt-in".to_owned()),
                target_identity,
            ));
        }
        let Some(contract) = contract else {
            return Ok(Candidate::non_mutating(
                order,
                capability,
                operation,
                Some(descriptor.backend.clone()),
                target,
                spec.control,
                fact.and_then(|value| match &value.value {
                    CurrentValue::Known(value) => Some(value.clone()),
                    CurrentValue::Unknown(_) => None,
                }),
                Some(desired),
                PlanAction::Unsupported,
                feature,
                class,
                risk,
                explicit_required,
                experimental,
                evidence,
                "no approved typed backend operation contract is registered",
                Some("operation remains report-only until a reviewed contract exists".to_owned()),
                target_identity,
            ));
        };
        contract.validate()?;
        if contract.explicit_opt_in && !policy.is_opted_in(&feature) {
            return Ok(Candidate::non_mutating(
                order,
                capability,
                operation,
                Some(contract.backend.clone()),
                target,
                spec.control,
                current,
                Some(desired),
                PlanAction::ExplicitOptInRequired,
                feature,
                contract.classification,
                contract.risk,
                true,
                if contract.classification == FeatureClass::Experimental {
                    ExperimentalStatus::OptInRequired
                } else {
                    experimental
                },
                evidence,
                "backend contract requires an explicit feature opt-in",
                Some("supply the feature-specific opt-in".to_owned()),
                target_identity,
            ));
        }
        if !contract.is_complete() {
            return Err(SysboostError::new(
                ErrorCode::PlanningError,
                "a proposed mutation has an incomplete snapshot/restore/verification contract",
            )
            .with_stage(Stage::Plan)
            .with_capability(capability)
            .with_backend(contract.backend.clone()));
        }
        if contract.backend != descriptor.backend
            || contract.target_kind != descriptor.target_kind
            || contract.control != spec.control
            || contract.equality != descriptor.equality
            || contract.classification != descriptor.classification
            || !descriptor
                .operations
                .iter()
                .any(|operation_descriptor| operation_descriptor.id == operation)
        {
            return Err(SysboostError::new(
                ErrorCode::InvariantViolation,
                "capability evidence and backend operation contract disagree",
            )
            .with_stage(Stage::Plan)
            .with_capability(capability)
            .with_backend(contract.backend.clone()));
        }
        if contract.risk > policy.max_risk {
            return Ok(Candidate::non_mutating(
                order,
                capability,
                operation,
                Some(contract.backend.clone()),
                target,
                spec.control,
                current,
                Some(desired),
                PlanAction::DeniedByPolicy,
                feature,
                contract.classification,
                contract.risk,
                explicit_required || contract.explicit_opt_in,
                experimental,
                evidence,
                "effective policy risk ceiling denies this operation",
                Some("raise the trusted risk ceiling".to_owned()),
                target_identity,
            ));
        }
        let Some(fact) = fact else {
            return Ok(Candidate::non_mutating(
                order,
                capability,
                operation,
                Some(contract.backend.clone()),
                target,
                spec.control,
                current,
                Some(desired),
                PlanAction::Indeterminate,
                feature,
                contract.classification,
                contract.risk,
                explicit_required || contract.explicit_opt_in,
                experimental,
                evidence,
                "current state is required but was not supplied by discovery",
                Some("re-detect current state before planning a mutation".to_owned()),
                target_identity,
            ));
        };
        let CurrentValue::Known(PlanValue::Typed(current_typed)) = &fact.value else {
            return Ok(Candidate::non_mutating(
                order,
                capability,
                operation,
                Some(contract.backend.clone()),
                target,
                spec.control,
                current,
                Some(desired),
                PlanAction::Indeterminate,
                feature,
                contract.classification,
                contract.risk,
                explicit_required || contract.explicit_opt_in,
                experimental,
                evidence,
                "current state is not a typed value admitted by the operation",
                Some("retain the feature as report-only until parsing is complete".to_owned()),
                target_identity,
            ));
        };
        let PlanValue::Typed(desired_typed) = desired.clone() else {
            return Ok(Candidate::non_mutating(
                order,
                capability,
                operation,
                Some(contract.backend.clone()),
                target,
                spec.control,
                Some(PlanValue::Typed(current_typed.clone())),
                Some(desired),
                PlanAction::Unsupported,
                feature,
                contract.classification,
                contract.risk,
                explicit_required || contract.explicit_opt_in,
                experimental,
                evidence,
                "the requested target is not represented by a closed typed operation",
                Some("use an approved typed operation instead of a raw interface value".to_owned()),
                target_identity,
            ));
        };
        let Some(target) = target else {
            return Ok(Candidate::non_mutating(
                order,
                capability,
                operation,
                Some(contract.backend.clone()),
                None,
                spec.control,
                Some(PlanValue::Typed(current_typed.clone())),
                Some(PlanValue::Typed(desired_typed)),
                PlanAction::Indeterminate,
                feature,
                contract.classification,
                contract.risk,
                explicit_required || contract.explicit_opt_in,
                experimental,
                evidence,
                "mutation target identity is ambiguous",
                Some("bind the operation to an enumerated target".to_owned()),
                target_identity,
            ));
        };
        let Some(target_identity) = target_identity else {
            return Ok(Candidate::non_mutating(
                order,
                capability,
                operation,
                Some(contract.backend.clone()),
                Some(target),
                spec.control,
                Some(PlanValue::Typed(current_typed.clone())),
                Some(PlanValue::Typed(desired_typed)),
                PlanAction::Indeterminate,
                feature,
                contract.classification,
                contract.risk,
                explicit_required || contract.explicit_opt_in,
                experimental,
                evidence,
                "target identity evidence is incomplete",
                Some("re-detect the target identity before mutation admission".to_owned()),
                None,
            ));
        };
        let Some(precondition) = fact.fingerprint else {
            return Ok(Candidate::non_mutating(
                order,
                capability,
                operation,
                Some(contract.backend.clone()),
                Some(target),
                spec.control,
                Some(PlanValue::Typed(current_typed.clone())),
                Some(PlanValue::Typed(desired_typed)),
                PlanAction::Indeterminate,
                feature,
                contract.classification,
                contract.risk,
                explicit_required || contract.explicit_opt_in,
                experimental,
                evidence,
                "current-state fingerprint is missing",
                Some("capture a backend-owned precondition before planning".to_owned()),
                Some(target_identity),
            ));
        };
        let Some(kind) = proposal
            .map(|proposal| proposal.request.operation.clone())
            .or_else(|| default_kind(spec.control, fact, desired_typed.clone()))
        else {
            return Ok(Candidate::non_mutating(
                order,
                capability,
                operation,
                Some(contract.backend.clone()),
                Some(target),
                spec.control,
                Some(PlanValue::Typed(current_typed.clone())),
                Some(PlanValue::Typed(desired_typed)),
                PlanAction::Indeterminate,
                feature,
                contract.classification,
                contract.risk,
                explicit_required || contract.explicit_opt_in,
                experimental,
                evidence,
                "typed target information is missing for the closed operation",
                Some("pass a typed target reference from discovery".to_owned()),
                Some(target_identity),
            ));
        };
        if kind.typed_value() != desired_typed {
            return Err(SysboostError::new(
                ErrorCode::PlanningError,
                "resolved desired value does not match the closed operation",
            )
            .with_stage(Stage::Plan));
        }
        let mutation = MutationDraft {
            capability: capability.clone(),
            target: target.clone(),
            kind,
            desired: desired_typed.clone(),
            precondition,
            equality: contract.equality,
            target_identity,
            dependencies: contract.dependencies.clone(),
        };
        Ok(Candidate::mutation(
            order,
            capability,
            operation,
            contract,
            target,
            spec.control,
            Some(PlanValue::Typed(current_typed.clone())),
            Some(PlanValue::Typed(desired_typed)),
            feature,
            evidence,
            mutation,
        ))
    }

    fn resolve_custom(
        &self,
        policy: &PlannerPolicy,
        descriptors: &DescriptorIndex<'_>,
        proposal: &PolicyProposal,
        current_state: &CurrentState,
        order: u16,
    ) -> Result<Candidate, SysboostError> {
        let request = &proposal.request;
        let feature = Feature::from_capability(&request.capability);
        let (control, target_kind) = operation_shape(&request.operation);
        let spec = FeatureSpec {
            feature: feature.clone(),
            capability: request.capability.clone(),
            operation: request.operation.operation_id(),
            control,
            risk: if feature.is_experimental() {
                RiskClass::Critical
            } else {
                RiskClass::Medium
            },
            classification: if feature.is_experimental() {
                FeatureClass::Experimental
            } else {
                FeatureClass::Conditional
            },
            explicit_opt_in: feature.is_experimental(),
            extreme_candidate: false,
            profile_target: ProfileTarget::None,
        };
        let descriptor = descriptors.select(&request.capability);
        if let Some(descriptor) = descriptor {
            if descriptor.target_kind != target_kind {
                return Err(SysboostError::new(
                    ErrorCode::InvariantViolation,
                    "explicit operation target kind disagrees with capability evidence",
                )
                .with_stage(Stage::Plan)
                .with_capability(request.capability.clone()));
            }
        }
        let fact = current_state.facts.iter().find(|fact| {
            fact.capability == request.capability
                && fact.target == request.target
                && fact.control == control
        });
        self.resolve_spec(
            policy,
            descriptors,
            &spec,
            order,
            Some(request.target.clone()),
            fact,
            Some(proposal),
        )
    }
}

/// Pure planner facade that produces digested transaction plans.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypedPlanner {
    /// Pure policy resolver.
    pub resolver: PolicyResolver,
}

impl TypedPlanner {
    /// Construct a planner from reviewed operation contracts.
    pub fn new(catalog: OperationCatalog) -> Self {
        Self {
            resolver: PolicyResolver::new(catalog),
        }
    }

    /// Resolve a complete typed plan without performing host I/O.
    pub fn build(&self, input: &PlannerInput) -> Result<Plan, SysboostError> {
        let resolution = self.resolver.resolve(input)?;
        let policy_digest = digest_policy(&input.policy);
        let capability_digest = digest_inventory(&input.inventory);
        let plan_digest = digest_resolution(&resolution, policy_digest, capability_digest);
        let id_bytes: [u8; 16] = plan_digest[..16]
            .try_into()
            .expect("fixed digest prefix has 16 bytes");
        Plan::from_items(
            PlanId::from_bytes(id_bytes),
            plan_digest,
            policy_digest,
            capability_digest,
            resolution.profile,
            resolution.items,
        )
    }
}

impl crate::plan::Planner for TypedPlanner {
    fn build(&self, request: &crate::plan::PlanRequest) -> Result<Plan, SysboostError> {
        let policy = PlannerPolicy::from_policy(Profile::Balanced, &request.policy);
        self.build(&PlannerInput {
            policy,
            inventory: request.inventory.clone(),
            current_state: CurrentState::empty(request.inventory.observed_at),
        })
    }
}

#[derive(Clone)]
struct FeatureSpec {
    feature: Feature,
    capability: CapabilityId,
    operation: OperationId,
    control: ControlId,
    risk: RiskClass,
    classification: FeatureClass,
    explicit_opt_in: bool,
    extreme_candidate: bool,
    profile_target: ProfileTarget,
}

#[derive(Clone, Copy)]
enum ProfileTarget {
    Governor,
    EnergyPreference,
    PlatformPerformance,
    GpuPerformance,
    None,
}

fn feature_specs() -> Vec<FeatureSpec> {
    vec![
        FeatureSpec {
            feature: Feature::CpuGovernor,
            capability: capability_id(capability_ids::CPU_POLICY_GOVERNOR),
            operation: operation_id("cpu.governor"),
            control: ControlId::CpuGovernor,
            risk: RiskClass::Low,
            classification: FeatureClass::RuntimeMutable,
            explicit_opt_in: false,
            extreme_candidate: false,
            profile_target: ProfileTarget::Governor,
        },
        FeatureSpec {
            feature: Feature::CpuEnergyPreference,
            capability: capability_id(capability_ids::CPU_POLICY_ENERGY_PREFERENCE),
            operation: operation_id("cpu.energy_preference"),
            control: ControlId::CpuEnergyPreference,
            risk: RiskClass::Low,
            classification: FeatureClass::RuntimeMutable,
            explicit_opt_in: false,
            extreme_candidate: false,
            profile_target: ProfileTarget::EnergyPreference,
        },
        FeatureSpec {
            feature: Feature::CpuFrequency,
            capability: capability_id(capability_ids::CPU_POLICY_FREQUENCY_MAX),
            operation: operation_id("cpu.frequency"),
            control: ControlId::CpuFrequency,
            risk: RiskClass::Medium,
            classification: FeatureClass::RuntimeMutable,
            explicit_opt_in: false,
            extreme_candidate: false,
            profile_target: ProfileTarget::None,
        },
        FeatureSpec {
            feature: Feature::CpuPlacement,
            capability: capability_id(capability_ids::CPU_TOPOLOGY),
            operation: operation_id("report.cpu.topology"),
            control: ControlId::ReportOnly,
            risk: RiskClass::Low,
            classification: FeatureClass::BootOnlyReportOnly,
            explicit_opt_in: false,
            extreme_candidate: false,
            profile_target: ProfileTarget::None,
        },
        FeatureSpec {
            feature: Feature::CpuBoost,
            capability: capability_id(capability_ids::CPU_BOOST),
            operation: operation_id("cpu.boost"),
            control: ControlId::CpuBoost,
            risk: RiskClass::Medium,
            classification: FeatureClass::RuntimeMutable,
            explicit_opt_in: false,
            extreme_candidate: false,
            profile_target: ProfileTarget::None,
        },
        FeatureSpec {
            feature: Feature::PlatformProfile,
            capability: capability_id(capability_ids::PLATFORM_PROFILE),
            operation: operation_id("platform.profile"),
            control: ControlId::PlatformProfile,
            risk: RiskClass::Medium,
            classification: FeatureClass::Conditional,
            explicit_opt_in: false,
            extreme_candidate: false,
            profile_target: ProfileTarget::PlatformPerformance,
        },
        FeatureSpec {
            feature: Feature::CgroupCpu,
            capability: capability_id(capability_ids::CGROUP_CPU_WEIGHT),
            operation: operation_id("cgroup.cpu.weight"),
            control: ControlId::CgroupCpuWeight,
            risk: RiskClass::Medium,
            classification: FeatureClass::RuntimeMutable,
            explicit_opt_in: false,
            extreme_candidate: false,
            profile_target: ProfileTarget::None,
        },
        FeatureSpec {
            feature: Feature::CgroupCpu,
            capability: capability_id(capability_ids::CGROUP_CPU_MAX),
            operation: operation_id("cgroup.cpu.max"),
            control: ControlId::CgroupCpuMax,
            risk: RiskClass::Medium,
            classification: FeatureClass::RuntimeMutable,
            explicit_opt_in: false,
            extreme_candidate: false,
            profile_target: ProfileTarget::None,
        },
        FeatureSpec {
            feature: Feature::CgroupCpu,
            capability: capability_id(capability_ids::CGROUP_CPUSET_CPUS),
            operation: operation_id("cgroup.cpuset.cpus"),
            control: ControlId::CgroupCpuset,
            risk: RiskClass::Medium,
            classification: FeatureClass::Conditional,
            explicit_opt_in: false,
            extreme_candidate: false,
            profile_target: ProfileTarget::None,
        },
        FeatureSpec {
            feature: Feature::GpuTuning,
            capability: capability_id(capability_ids::GPU_PERFORMANCE_PROFILE),
            operation: operation_id("gpu.performance.profile"),
            control: ControlId::GpuPerformanceProfile,
            risk: RiskClass::Critical,
            classification: FeatureClass::Experimental,
            explicit_opt_in: true,
            extreme_candidate: true,
            profile_target: ProfileTarget::GpuPerformance,
        },
        FeatureSpec {
            feature: Feature::GpuTuning,
            capability: capability_id(capability_ids::GPU_POWER_LIMIT),
            operation: operation_id("gpu.power.limit"),
            control: ControlId::GpuPowerLimit,
            risk: RiskClass::Critical,
            classification: FeatureClass::Experimental,
            explicit_opt_in: true,
            extreme_candidate: true,
            profile_target: ProfileTarget::None,
        },
        FeatureSpec {
            feature: Feature::IrqTuning,
            capability: capability_id(capability_ids::IRQ_AFFINITY),
            operation: operation_id("irq.affinity"),
            control: ControlId::IrqAffinity,
            risk: RiskClass::Critical,
            classification: FeatureClass::Experimental,
            explicit_opt_in: true,
            extreme_candidate: true,
            profile_target: ProfileTarget::None,
        },
        FeatureSpec {
            feature: Feature::SchedulerTuning,
            capability: capability_id(capability_ids::SCHEDULER),
            operation: operation_id("report.scheduler.workload"),
            control: ControlId::SchedulerWorkload,
            risk: RiskClass::Critical,
            classification: FeatureClass::Experimental,
            explicit_opt_in: true,
            extreme_candidate: true,
            profile_target: ProfileTarget::None,
        },
        FeatureSpec {
            feature: Feature::CgroupCpu,
            capability: capability_id(capability_ids::CGROUP_UCLAMP),
            operation: operation_id("report.cgroup.uclamp"),
            control: ControlId::CgroupUclamp,
            risk: RiskClass::Medium,
            classification: FeatureClass::Conditional,
            explicit_opt_in: false,
            extreme_candidate: false,
            profile_target: ProfileTarget::None,
        },
        FeatureSpec {
            feature: Feature::TransparentHugePages,
            capability: capability_id(capability_ids::MEMORY_THP),
            operation: operation_id("report.memory.thp"),
            control: ControlId::TransparentHugePages,
            risk: RiskClass::Medium,
            classification: FeatureClass::Conditional,
            explicit_opt_in: false,
            extreme_candidate: false,
            profile_target: ProfileTarget::None,
        },
        FeatureSpec {
            feature: Feature::MemoryVm,
            capability: capability_id(capability_ids::KERNEL_SYSCTL_RUNTIME),
            operation: operation_id("kernel.sysctl.runtime"),
            control: ControlId::MemoryVm,
            risk: RiskClass::High,
            classification: FeatureClass::Conditional,
            explicit_opt_in: false,
            extreme_candidate: false,
            profile_target: ProfileTarget::None,
        },
    ]
}

fn profile_desired(
    profile: Profile,
    spec: &FeatureSpec,
    fact: Option<&CurrentStateFact>,
) -> (Option<PlanValue>, Option<&'static str>) {
    match spec.profile_target {
        ProfileTarget::Governor => {
            let intent = profile.intent().governor;
            let candidates: &[&str] = match intent {
                PerformanceIntent::Balanced => &["schedutil", "ondemand"],
                PerformanceIntent::Performance => &["performance"],
            };
            match choose_governor(fact, candidates) {
                Some(value) => (Some(value), None),
                None if fact.is_some() => (
                    None,
                    Some("profile target is not among the values advertised by the interface"),
                ),
                None => (None, None),
            }
        }
        ProfileTarget::EnergyPreference => {
            let intent = profile.intent().energy_preference;
            let candidates: &[EnergyPreference] = match intent {
                PerformanceIntent::Balanced => &[
                    EnergyPreference::BalancePerformance,
                    EnergyPreference::BalancePower,
                ],
                PerformanceIntent::Performance => &[EnergyPreference::Performance],
            };
            match choose_energy_preference(fact, candidates) {
                Some(value) => (Some(value), None),
                None if fact.is_some() => (
                    None,
                    Some("profile EPP target is not among the values advertised by the interface"),
                ),
                None => (None, None),
            }
        }
        ProfileTarget::PlatformPerformance if profile != Profile::Balanced => {
            match choose_platform_profile(fact, "performance") {
                Some(value) => (Some(value), None),
                None if fact.is_some() => (
                    None,
                    Some("platform performance profile is not advertised by the interface"),
                ),
                None => (None, None),
            }
        }
        ProfileTarget::GpuPerformance if profile == Profile::Extreme => (
            Some(PlanValue::Typed(TypedValue::GpuPerformanceProfile(
                GpuProfile::Performance,
            ))),
            None,
        ),
        _ => (None, None),
    }
}

fn choose_governor(fact: Option<&CurrentStateFact>, candidates: &[&str]) -> Option<PlanValue> {
    let values = fact?.supported_values.as_slice();
    for candidate in candidates {
        let governor = GovernorId::new(*candidate).expect("static governor is valid");
        let value = PlanValue::Typed(TypedValue::Governor(governor));
        if values.is_empty() || values.contains(&value) {
            return Some(value);
        }
    }
    None
}

fn choose_energy_preference(
    fact: Option<&CurrentStateFact>,
    candidates: &[EnergyPreference],
) -> Option<PlanValue> {
    let values = fact?.supported_values.as_slice();
    for candidate in candidates {
        let value = PlanValue::Typed(TypedValue::EnergyPreference(*candidate));
        if values.is_empty() || values.contains(&value) {
            return Some(value);
        }
    }
    None
}

fn choose_platform_profile(fact: Option<&CurrentStateFact>, desired: &str) -> Option<PlanValue> {
    let profile = PlatformProfileId::new(desired).expect("static platform profile is valid");
    let value = PlanValue::Typed(TypedValue::PlatformProfile(profile));
    if fact
        .map(|fact| fact.supported_values.is_empty() || fact.supported_values.contains(&value))
        .unwrap_or(false)
    {
        Some(value)
    } else {
        None
    }
}

fn default_kind(
    control: ControlId,
    fact: &CurrentStateFact,
    desired: TypedValue,
) -> Option<MutationKind> {
    let target = fact.typed_target.as_ref()?;
    match (control, target, desired) {
        (
            ControlId::CpuGovernor,
            TypedTarget::CpuPolicy(policy),
            TypedValue::Governor(governor),
        ) => Some(MutationKind::CpuGovernor {
            policy: *policy,
            governor,
        }),
        (
            ControlId::CpuEnergyPreference,
            TypedTarget::CpuPolicy(policy),
            TypedValue::EnergyPreference(value),
        ) => Some(MutationKind::CpuEnergyPreference {
            policy: *policy,
            value,
        }),
        (ControlId::CpuBoost, TypedTarget::CpuSystem, TypedValue::CpuBoost(state)) => {
            Some(MutationKind::CpuBoost { state })
        }
        (
            ControlId::PlatformProfile,
            TypedTarget::CpuSystem,
            TypedValue::PlatformProfile(profile),
        ) => Some(MutationKind::PlatformProfile { profile }),
        (
            ControlId::CgroupCpuWeight,
            TypedTarget::Cgroup(cgroup),
            TypedValue::CgroupCpuWeight(weight),
        ) => Some(MutationKind::CgroupCpuWeight {
            cgroup: cgroup.clone(),
            weight,
        }),
        (
            ControlId::CgroupCpuMax,
            TypedTarget::Cgroup(cgroup),
            TypedValue::CgroupCpuMax { quota, period },
        ) => Some(MutationKind::CgroupCpuMax {
            cgroup: cgroup.clone(),
            quota,
            period,
        }),
        (ControlId::CgroupCpuset, TypedTarget::Cgroup(cgroup), TypedValue::CgroupCpuset(cpus)) => {
            Some(MutationKind::CgroupCpuset {
                cgroup: cgroup.clone(),
                cpus: cpus.clone(),
            })
        }
        (ControlId::CgroupUclamp, TypedTarget::Cgroup(cgroup), TypedValue::CgroupUclamp(value)) => {
            Some(MutationKind::CgroupUclampMin {
                cgroup: cgroup.clone(),
                value,
            })
        }
        (
            ControlId::CgroupUclampMin,
            TypedTarget::Cgroup(cgroup),
            TypedValue::CgroupUclamp(value),
        ) => Some(MutationKind::CgroupUclampMin {
            cgroup: cgroup.clone(),
            value,
        }),
        (
            ControlId::CgroupUclampMax,
            TypedTarget::Cgroup(cgroup),
            TypedValue::CgroupUclamp(value),
        ) => Some(MutationKind::CgroupUclampMax {
            cgroup: cgroup.clone(),
            value,
        }),
        (
            ControlId::CgroupIoWeight,
            TypedTarget::Cgroup(cgroup),
            TypedValue::CgroupIoWeight(weight),
        ) => Some(MutationKind::CgroupIoWeight {
            cgroup: cgroup.clone(),
            weight,
        }),
        (ControlId::SchedulerWorkload, TypedTarget::Process(process), TypedValue::Nice(nice)) => {
            Some(MutationKind::ProcessNice {
                process: *process,
                nice,
            })
        }
        (ControlId::ProcessNice, TypedTarget::Process(process), TypedValue::Nice(nice)) => {
            Some(MutationKind::ProcessNice {
                process: *process,
                nice,
            })
        }
        (
            ControlId::SchedulerWorkload,
            TypedTarget::Process(process),
            TypedValue::IoPriority(priority),
        ) => Some(MutationKind::ProcessIoPriority {
            process: *process,
            priority,
        }),
        (
            ControlId::ProcessIoPriority,
            TypedTarget::Process(process),
            TypedValue::IoPriority(priority),
        ) => Some(MutationKind::ProcessIoPriority {
            process: *process,
            priority,
        }),
        (
            ControlId::SchedulerWorkload,
            TypedTarget::Process(process),
            TypedValue::ProcessPlacement(cgroup),
        ) => Some(MutationKind::ProcessPlacement {
            process: *process,
            cgroup: cgroup.clone(),
        }),
        (
            ControlId::ProcessPlacement,
            TypedTarget::Process(process),
            TypedValue::ProcessPlacement(cgroup),
        ) => Some(MutationKind::ProcessPlacement {
            process: *process,
            cgroup: cgroup.clone(),
        }),
        (
            ControlId::CgroupWorkload,
            TypedTarget::Cgroup(parent),
            TypedValue::CgroupLifecycle {
                kind: CgroupGroupKind::Workload,
                name,
                present: true,
            },
        ) => Some(MutationKind::CgroupWorkload {
            parent: parent.clone(),
            name: name.clone(),
        }),
        (
            ControlId::CgroupBackground,
            TypedTarget::Cgroup(parent),
            TypedValue::CgroupLifecycle {
                kind: CgroupGroupKind::ConservativeBackground,
                name,
                present: true,
            },
        ) => Some(MutationKind::CgroupBackground {
            parent: parent.clone(),
            name: name.clone(),
        }),
        (
            ControlId::GpuPerformanceProfile,
            TypedTarget::Gpu(device),
            TypedValue::GpuPerformanceProfile(profile),
        ) => Some(MutationKind::GpuPerformanceProfile {
            device: *device,
            profile,
        }),
        _ => None,
    }
}

fn operation_shape(kind: &MutationKind) -> (ControlId, TargetKind) {
    match kind {
        MutationKind::CpuFrequency { .. } => (ControlId::CpuFrequency, TargetKind::CpuPolicy),
        MutationKind::CpuGovernor { .. } => (ControlId::CpuGovernor, TargetKind::CpuPolicy),
        MutationKind::CpuEnergyPreference { .. } => {
            (ControlId::CpuEnergyPreference, TargetKind::CpuPolicy)
        }
        MutationKind::CpuBoost { .. } => (ControlId::CpuBoost, TargetKind::CpuSystem),
        MutationKind::PlatformProfile { .. } => (ControlId::PlatformProfile, TargetKind::CpuSystem),
        MutationKind::CgroupCpuWeight { .. } => (ControlId::CgroupCpuWeight, TargetKind::Cgroup),
        MutationKind::CgroupCpuMax { .. } => (ControlId::CgroupCpuMax, TargetKind::Cgroup),
        MutationKind::CgroupCpuset { .. } => (ControlId::CgroupCpuset, TargetKind::Cgroup),
        MutationKind::CgroupIoWeight { .. } => (ControlId::CgroupIoWeight, TargetKind::Cgroup),
        MutationKind::CgroupUclampMin { .. } => (ControlId::CgroupUclampMin, TargetKind::Cgroup),
        MutationKind::CgroupUclampMax { .. } => (ControlId::CgroupUclampMax, TargetKind::Cgroup),
        MutationKind::CgroupWorkload { .. } => (ControlId::CgroupWorkload, TargetKind::Cgroup),
        MutationKind::CgroupBackground { .. } => (ControlId::CgroupBackground, TargetKind::Cgroup),
        MutationKind::ProcessPlacement { .. } => (ControlId::ProcessPlacement, TargetKind::Process),
        MutationKind::ProcessNice { .. } => (ControlId::ProcessNice, TargetKind::Process),
        MutationKind::ProcessIoPriority { .. } => {
            (ControlId::ProcessIoPriority, TargetKind::Process)
        }
        MutationKind::GpuPerformanceProfile { .. } => {
            (ControlId::GpuPerformanceProfile, TargetKind::Gpu)
        }
        MutationKind::GpuPowerLimit { .. } => (ControlId::GpuPowerLimit, TargetKind::Gpu),
        MutationKind::IrqAffinity { .. } => (ControlId::IrqAffinity, TargetKind::Irq),
        MutationKind::RuntimeSysctl { .. } => (ControlId::MemoryVm, TargetKind::Sysctl),
    }
}

fn capability_id(value: &str) -> CapabilityId {
    CapabilityId::new(value.to_owned()).expect("static capability IDs are valid")
}

fn operation_id(value: &str) -> OperationId {
    OperationId::new(value.to_owned()).expect("static operation IDs are valid")
}

fn validate_policy(policy: &PlannerPolicy) -> Result<(), SysboostError> {
    if policy.session_timeout_ms == 0 {
        return Err(SysboostError::new(
            ErrorCode::ConfigError,
            "planner policy requires a positive session timeout",
        )
        .with_stage(Stage::Config));
    }
    Ok(())
}

fn select_proposals(
    proposals: &[PolicyProposal],
) -> Result<BTreeMap<CandidateKey, PolicyProposal>, SysboostError> {
    let mut selected = BTreeMap::new();
    let mut ordered = proposals.to_vec();
    ordered.sort_by(|left, right| {
        proposal_key(&left.request)
            .cmp(&proposal_key(&right.request))
            .then_with(|| right.source.precedence().cmp(&left.source.precedence()))
    });
    for proposal in ordered {
        validate_request(&proposal.request)?;
        let key = CandidateKey::new(
            proposal.request.capability.clone(),
            proposal.request.target.clone(),
            proposal.request.operation.operation_id(),
            0,
        );
        match selected.get(&key) {
            None => {
                selected.insert(key, proposal);
            }
            Some(existing) if existing.request.operation == proposal.request.operation => {}
            Some(existing) if existing.source.precedence() > proposal.source.precedence() => {}
            Some(existing) if existing.source.precedence() < proposal.source.precedence() => {
                selected.insert(key, proposal);
            }
            Some(_) => {
                return Err(SysboostError::new(
                    ErrorCode::PlanningError,
                    "equal-precedence policy sources propose incompatible values",
                )
                .with_stage(Stage::Plan));
            }
        }
    }
    Ok(selected)
}

fn validate_request(request: &PolicyRequest) -> Result<(), SysboostError> {
    let (control, _) = operation_shape(&request.operation);
    let expected = match &request.operation {
        MutationKind::CpuFrequency { .. } => capability_ids::CPU_POLICY_FREQUENCY_MAX,
        MutationKind::CpuGovernor { .. } => capability_ids::CPU_POLICY_GOVERNOR,
        MutationKind::CpuEnergyPreference { .. } => capability_ids::CPU_POLICY_ENERGY_PREFERENCE,
        MutationKind::CpuBoost { .. } => capability_ids::CPU_BOOST,
        MutationKind::PlatformProfile { .. } => capability_ids::PLATFORM_PROFILE,
        MutationKind::CgroupCpuWeight { .. } => capability_ids::CGROUP_CPU_WEIGHT,
        MutationKind::CgroupCpuMax { .. } => capability_ids::CGROUP_CPU_MAX,
        MutationKind::CgroupCpuset { .. } => capability_ids::CGROUP_CPUSET_CPUS,
        MutationKind::CgroupIoWeight { .. } => capability_ids::CGROUP_IO_WEIGHT,
        MutationKind::CgroupUclampMin { .. } | MutationKind::CgroupUclampMax { .. } => {
            capability_ids::CGROUP_UCLAMP
        }
        MutationKind::CgroupWorkload { .. } => capability_ids::CGROUP_WORKLOAD,
        MutationKind::CgroupBackground { .. } => capability_ids::CGROUP_BACKGROUND,
        MutationKind::ProcessPlacement { .. } => capability_ids::PROCESS_PLACEMENT,
        MutationKind::ProcessNice { .. } => capability_ids::PROCESS_NICE,
        MutationKind::ProcessIoPriority { .. } => capability_ids::PROCESS_IOPRIO,
        MutationKind::GpuPerformanceProfile { .. } => capability_ids::GPU_PERFORMANCE_PROFILE,
        MutationKind::GpuPowerLimit { .. } => capability_ids::GPU_POWER_LIMIT,
        MutationKind::IrqAffinity { .. } => capability_ids::IRQ_AFFINITY,
        MutationKind::RuntimeSysctl { .. } => capability_ids::KERNEL_SYSCTL_RUNTIME,
    };
    if request.capability.as_str() != expected {
        return Err(SysboostError::new(
            ErrorCode::PlanningError,
            format!("explicit request capability does not match its {control} operation"),
        )
        .with_stage(Stage::Plan)
        .with_capability(request.capability.clone())
        .with_target(request.target.clone()));
    }
    Ok(())
}

fn proposal_key(request: &PolicyRequest) -> (CapabilityId, TargetId, OperationId) {
    (
        request.capability.clone(),
        request.target.clone(),
        request.operation.operation_id(),
    )
}

fn proposal_for<'a>(
    proposals: &'a BTreeMap<CandidateKey, PolicyProposal>,
    capability: &CapabilityId,
    operation: &OperationId,
    target: Option<&TargetId>,
) -> Option<&'a PolicyProposal> {
    target.and_then(|target| {
        proposals.get(&CandidateKey::new(
            capability.clone(),
            target.clone(),
            operation.clone(),
            0,
        ))
    })
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct CandidateKey {
    capability: CapabilityId,
    target: Option<TargetId>,
    operation: OperationId,
    order: u16,
}

impl CandidateKey {
    fn new(capability: CapabilityId, target: TargetId, operation: OperationId, order: u16) -> Self {
        Self {
            capability,
            target: Some(target),
            operation,
            order,
        }
    }

    fn aggregate(capability: CapabilityId, operation: OperationId, order: u16) -> Self {
        Self {
            capability,
            target: None,
            operation,
            order,
        }
    }
}

#[derive(Clone, Debug)]
struct Candidate {
    key: CandidateKey,
    item: PlanItem,
    mutation: Option<MutationDraft>,
    dependencies: Vec<OperationId>,
}

#[derive(Clone, Debug)]
struct MutationDraft {
    capability: CapabilityId,
    target: TargetId,
    kind: MutationKind,
    desired: TypedValue,
    precondition: StateFingerprint,
    equality: EqualityKind,
    target_identity: TargetIdentity,
    dependencies: Vec<OperationId>,
}

impl Candidate {
    #[allow(clippy::too_many_arguments)]
    fn non_mutating(
        order: u16,
        capability: CapabilityId,
        operation: OperationId,
        backend: Option<BackendId>,
        target: Option<TargetId>,
        control: ControlId,
        current: Option<PlanValue>,
        desired: Option<PlanValue>,
        action: PlanAction,
        feature: Feature,
        feature_class: FeatureClass,
        risk: RiskClass,
        explicit_opt_in_required: bool,
        experimental: ExperimentalStatus,
        evidence: Vec<CapabilityEvidence>,
        rationale: &str,
        reason: Option<String>,
        target_identity: Option<TargetIdentity>,
    ) -> Self {
        let key = match &target {
            Some(target) => {
                CandidateKey::new(capability.clone(), target.clone(), operation.clone(), order)
            }
            None => CandidateKey::aggregate(capability.clone(), operation.clone(), order),
        };
        Self {
            key,
            item: PlanItem {
                capability,
                operation,
                backend,
                target,
                control,
                current,
                desired,
                action,
                feature,
                feature_class,
                risk,
                explicit_opt_in_required,
                experimental,
                evidence,
                rationale: rationale.to_owned(),
                reason,
                target_identity,
                snapshot: SnapshotContract::not_applicable(),
                restore: RestoreContract::not_applicable(),
                verification: VerificationContract::not_applicable(),
                dependencies: Vec::new(),
                mutation: None,
            },
            mutation: None,
            dependencies: Vec::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn mutation(
        order: u16,
        capability: CapabilityId,
        operation: OperationId,
        contract: &OperationContract,
        target: TargetId,
        control: ControlId,
        current: Option<PlanValue>,
        desired: Option<PlanValue>,
        feature: Feature,
        evidence: Vec<CapabilityEvidence>,
        mutation: MutationDraft,
    ) -> Self {
        let key = CandidateKey::new(capability.clone(), target.clone(), operation.clone(), order);
        Self {
            key,
            item: PlanItem {
                capability,
                operation,
                backend: Some(contract.backend.clone()),
                target: Some(target),
                control,
                current,
                desired,
                action: PlanAction::Mutation,
                feature,
                feature_class: contract.classification,
                risk: contract.risk,
                explicit_opt_in_required: contract.explicit_opt_in,
                experimental: if contract.classification == FeatureClass::Experimental {
                    ExperimentalStatus::Enabled
                } else {
                    ExperimentalStatus::NotExperimental
                },
                evidence,
                rationale:
                    "typed operation is supported, policy-admitted, and reversible by contract"
                        .to_owned(),
                reason: None,
                target_identity: Some(mutation.target_identity),
                snapshot: contract.snapshot,
                restore: contract.restore,
                verification: contract.verification,
                dependencies: Vec::new(),
                mutation: None,
            },
            dependencies: mutation.dependencies.clone(),
            mutation: Some(mutation),
        }
    }
}

fn insert_candidate(
    candidates: &mut BTreeMap<CandidateKey, Candidate>,
    candidate: Candidate,
) -> Result<(), SysboostError> {
    if let Some(existing) = candidates.get(&candidate.key) {
        if existing.item.action == PlanAction::Mutation
            && candidate.item.action == PlanAction::Mutation
            && existing.item.desired != candidate.item.desired
        {
            return Err(SysboostError::new(
                ErrorCode::PlanningError,
                "duplicate target/control proposals have incompatible desired values",
            )
            .with_stage(Stage::Plan)
            .with_capability(candidate.item.capability.clone())
            .with_target(
                candidate
                    .item
                    .target
                    .clone()
                    .expect("candidate key has target"),
            ));
        }
        if existing.item != candidate.item {
            return Err(SysboostError::new(
                ErrorCode::PlanningError,
                "duplicate plan keys carry contradictory decisions",
            )
            .with_stage(Stage::Plan)
            .with_capability(candidate.item.capability.clone()));
        }
        return Ok(());
    }
    candidates.insert(candidate.key.clone(), candidate);
    Ok(())
}

fn finalize_candidates(
    policy: &PlannerPolicy,
    candidates: BTreeMap<CandidateKey, Candidate>,
) -> Result<PolicyResolution, SysboostError> {
    let mut candidates = candidates.into_values().collect::<Vec<_>>();
    let mut mutation_indices = candidates
        .iter()
        .enumerate()
        .filter_map(|(index, candidate)| candidate.mutation.as_ref().map(|_| index))
        .collect::<Vec<_>>();
    mutation_indices.sort_by(|left, right| candidates[*left].key.cmp(&candidates[*right].key));

    let mut dependencies = BTreeMap::<usize, Vec<usize>>::new();
    for &index in &mutation_indices {
        let candidate = &candidates[index];
        let Some(target) = candidate.item.target.as_ref() else {
            continue;
        };
        for dependency in &candidate.dependencies {
            let matching = candidates
                .iter()
                .enumerate()
                .find(|(_, dependency_candidate)| {
                    dependency_candidate.item.target.as_ref() == Some(target)
                        && dependency_candidate.item.operation == *dependency
                });
            let Some((matching_index, matching_candidate)) = matching else {
                return Err(SysboostError::new(
                    ErrorCode::PlanningError,
                    "planned operation depends on a missing executable operation",
                )
                .with_stage(Stage::Plan)
                .with_capability(candidate.item.capability.clone())
                .with_target(target.clone()));
            };
            if !matching_candidate.item.action.is_executable() {
                if matches!(
                    matching_candidate.item.action,
                    PlanAction::NoOp | PlanAction::Preserved
                ) {
                    continue;
                }
                return Err(SysboostError::new(
                    ErrorCode::PlanningError,
                    "planned operation depends on an operation that was not admitted",
                )
                .with_stage(Stage::Plan)
                .with_capability(candidate.item.capability.clone())
                .with_target(target.clone()));
            }
            if matching_index == index {
                return Err(SysboostError::new(
                    ErrorCode::PlanningError,
                    "planned operation depends on itself",
                )
                .with_stage(Stage::Plan));
            }
            dependencies.entry(index).or_default().push(matching_index);
        }
    }

    let mut indegree = BTreeMap::<usize, usize>::new();
    for &index in &mutation_indices {
        indegree.insert(index, dependencies.get(&index).map_or(0, Vec::len));
    }
    let mut ready = BTreeSet::<(CandidateKey, usize)>::new();
    for (&index, &degree) in &indegree {
        if degree == 0 {
            ready.insert((candidates[index].key.clone(), index));
        }
    }
    let mut ordered_indices = Vec::with_capacity(mutation_indices.len());
    while let Some((_, index)) = ready.pop_first() {
        ordered_indices.push(index);
        for (&dependent, required) in &dependencies {
            if required.contains(&index) {
                let degree = indegree
                    .get_mut(&dependent)
                    .expect("dependency node is in indegree map");
                *degree -= 1;
                if *degree == 0 {
                    ready.insert((candidates[dependent].key.clone(), dependent));
                }
            }
        }
    }
    if ordered_indices.len() != mutation_indices.len() {
        return Err(SysboostError::new(
            ErrorCode::PlanningError,
            "planned operation dependencies contain a cycle",
        )
        .with_stage(Stage::Plan));
    }

    let mut mutation_ids = BTreeMap::<usize, MutationId>::new();
    for (position, index) in ordered_indices.iter().copied().enumerate() {
        mutation_ids.insert(index, MutationId::new((position + 1) as u32));
    }
    for index in ordered_indices.iter().copied() {
        let candidate = &mut candidates[index];
        let draft = candidate
            .mutation
            .take()
            .expect("mutation index was selected from mutation candidates");
        let dependency_ids = dependencies
            .get(&index)
            .into_iter()
            .flatten()
            .map(|dependency_index| {
                mutation_ids
                    .get(dependency_index)
                    .copied()
                    .expect("dependency ID was assigned before finalization")
            })
            .collect::<Vec<_>>();
        let mutation = PlannedMutation::new(
            mutation_ids[&index],
            draft.capability.clone(),
            draft.target.clone(),
            draft.kind,
            draft.desired,
            draft.precondition,
            draft.equality,
            dependency_ids.clone(),
        )?;
        candidate.item.dependencies = dependency_ids;
        candidate.item.mutation = Some(mutation);
        candidate.item.target_identity = Some(draft.target_identity);
    }

    candidates.sort_by(|left, right| {
        left.key
            .cmp(&right.key)
            .then_with(|| left.item.action.cmp(&right.item.action))
    });
    let items = candidates
        .into_iter()
        .map(|candidate| candidate.item)
        .collect();
    Ok(PolicyResolution {
        profile: policy.profile,
        items,
    })
}

struct DescriptorIndex<'a> {
    descriptors: Vec<&'a CapabilityDescriptor>,
}

impl<'a> DescriptorIndex<'a> {
    fn new(inventory: &'a CapabilityInventory) -> Self {
        let mut descriptors = inventory.capabilities.iter().collect::<Vec<_>>();
        descriptors.sort_by(|left, right| {
            left.id
                .cmp(&right.id)
                .then_with(|| descriptor_rank(left.state).cmp(&descriptor_rank(right.state)))
                .then_with(|| left.backend.cmp(&right.backend))
        });
        Self { descriptors }
    }

    fn select(&self, capability: &CapabilityId) -> Option<&CapabilityDescriptor> {
        self.descriptors
            .iter()
            .copied()
            .filter(|descriptor| &descriptor.id == capability)
            .min_by(|left, right| {
                descriptor_rank(left.state)
                    .cmp(&descriptor_rank(right.state))
                    .then_with(|| left.backend.cmp(&right.backend))
            })
    }
}

fn descriptor_rank(state: CapabilityState) -> u8 {
    match state {
        CapabilityState::Available => 0,
        CapabilityState::ReadOnly => 1,
        CapabilityState::Denied => 2,
        CapabilityState::Indeterminate => 3,
        CapabilityState::Unsupported => 4,
    }
}

fn canonicalize_evidence(evidence: &mut Vec<CapabilityEvidence>) {
    evidence.sort_by(|left, right| {
        format!("{:?}", left.source)
            .cmp(&format!("{:?}", right.source))
            .then_with(|| left.detail.cmp(&right.detail))
    });
    evidence.dedup();
}

fn fingerprint_for_bytes(bytes: &[u8]) -> StateFingerprint {
    StateFingerprint::from_bytes(stable_digest(bytes))
}

/// Derive a deterministic fingerprint for a fixture/current observation.
pub fn fingerprint_for_value(value: &PlanValue) -> StateFingerprint {
    fingerprint_for_bytes(value.to_string().as_bytes())
}

fn digest_policy(policy: &PlannerPolicy) -> [u8; 32] {
    let mut writer = DigestWriter::new();
    writer.str(&policy.profile.to_string());
    writer.u8(match policy.mode {
        PolicyMode::Report => 0,
        PolicyMode::Boost => 1,
    });
    writer.u8(risk_tag(policy.max_risk));
    writer.bool(policy.allow_experimental);
    writer.bool(policy.required_default);
    writer.u64(policy.session_timeout_ms);
    for feature in &policy.explicit_opt_ins {
        writer.str(&feature.to_string());
    }
    let mut preserves = policy.preserves.clone();
    preserves.sort_by(|left, right| {
        left.feature
            .cmp(&right.feature)
            .then_with(|| left.target.cmp(&right.target))
            .then_with(|| left.reason.cmp(&right.reason))
    });
    for preserve in preserves {
        writer.str(&preserve.feature.to_string());
        writer.option_str(preserve.target.as_ref().map(TargetId::as_str));
        writer.str(&preserve.reason);
    }
    let mut proposals = policy.proposals.clone();
    proposals.sort_by(|left, right| {
        proposal_key(&left.request)
            .cmp(&proposal_key(&right.request))
            .then_with(|| left.source.cmp(&right.source))
    });
    for proposal in proposals {
        writer.u8(proposal.source.precedence());
        writer.str(proposal.request.capability.as_str());
        writer.str(proposal.request.target.as_str());
        writer.bool(proposal.request.required);
        write_kind(&mut writer, &proposal.request.operation);
    }
    writer.finish()
}

fn digest_inventory(inventory: &CapabilityInventory) -> [u8; 32] {
    let mut writer = DigestWriter::new();
    writer.u64(inventory.observed_at.as_unix_millis() as u64);
    let mut descriptors = inventory.capabilities.clone();
    descriptors.sort_by(|left, right| {
        left.id
            .cmp(&right.id)
            .then_with(|| left.backend.cmp(&right.backend))
            .then_with(|| descriptor_rank(left.state).cmp(&descriptor_rank(right.state)))
    });
    for descriptor in descriptors {
        writer.str(descriptor.id.as_str());
        writer.str(descriptor.backend.as_str());
        writer.u8(target_kind_tag(descriptor.target_kind));
        writer.u8(descriptor_rank(descriptor.state));
        writer.u8(equality_tag(descriptor.equality));
        writer.u8(risk_tag(descriptor.risk));
        writer.u8(feature_class_tag(descriptor.classification));
        let mut operations = descriptor.operations.clone();
        operations.sort_by(|left, right| left.id.cmp(&right.id));
        for operation in operations {
            writer.str(operation.id.as_str());
            writer.u8(equality_tag(operation.equality));
            writer.u8(feature_class_tag(operation.classification));
        }
        let mut evidence = descriptor.evidence.clone();
        canonicalize_evidence(&mut evidence);
        for evidence in evidence {
            writer.str(&format!("{:?}", evidence.source));
            writer.str(&evidence.detail);
        }
    }
    writer.finish()
}

fn digest_resolution(
    resolution: &PolicyResolution,
    policy_digest: [u8; 32],
    capability_digest: [u8; 32],
) -> [u8; 32] {
    let mut writer = DigestWriter::new();
    writer.str(&resolution.profile.to_string());
    writer.bytes(&policy_digest);
    writer.bytes(&capability_digest);
    for item in &resolution.items {
        writer.str(item.capability.as_str());
        writer.str(item.operation.as_str());
        writer.option_str(item.backend.as_ref().map(BackendId::as_str));
        writer.option_str(item.target.as_ref().map(TargetId::as_str));
        writer.u8(item.control as u8);
        writer.u8(item.action as u8);
        writer.str(&item.feature.to_string());
        writer.u8(feature_class_tag(item.feature_class));
        writer.u8(risk_tag(item.risk));
        writer.u8(item.experimental as u8);
        writer.bool(item.explicit_opt_in_required);
        writer.option_str(
            item.current
                .as_ref()
                .map(|value| value.to_string())
                .as_deref(),
        );
        writer.option_str(
            item.desired
                .as_ref()
                .map(|value| value.to_string())
                .as_deref(),
        );
        writer.str(&item.rationale);
        writer.option_str(item.reason.as_deref());
        for dependency in &item.dependencies {
            writer.u32(dependency.get());
        }
        if let Some(mutation) = &item.mutation {
            writer.u32(mutation.mutation_id.get());
            writer.bytes(mutation.precondition.as_bytes());
            write_kind(&mut writer, &mutation.kind);
        }
    }
    writer.finish()
}

struct DigestWriter {
    bytes: Vec<u8>,
}

impl DigestWriter {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn bool(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn bytes(&mut self, value: &[u8]) {
        self.u64(value.len() as u64);
        self.bytes.extend_from_slice(value);
    }

    fn str(&mut self, value: &str) {
        self.bytes(value.as_bytes());
    }

    fn option_str(&mut self, value: Option<&str>) {
        match value {
            Some(value) => {
                self.bool(true);
                self.str(value);
            }
            None => self.bool(false),
        }
    }

    fn finish(self) -> [u8; 32] {
        stable_digest(&self.bytes)
    }
}

fn stable_digest(bytes: &[u8]) -> [u8; 32] {
    let mut lanes = [
        0xcbf29ce484222325_u64,
        0x84222325cbf29ce4_u64,
        0x9e3779b185ebca87_u64,
        0xd6e8feb86659fd93_u64,
    ];
    for (index, byte) in bytes.iter().copied().enumerate() {
        let lane = index % lanes.len();
        lanes[lane] ^= u64::from(byte);
        lanes[lane] = lanes[lane].wrapping_mul(0x100000001b3);
        lanes[lane] ^= lanes[lane].rotate_left(27);
        lanes[lane] = lanes[lane].wrapping_add((index as u64).wrapping_mul(0x9e37));
    }
    let mut output = [0_u8; 32];
    for (index, lane) in lanes.iter().enumerate() {
        output[index * 8..index * 8 + 8].copy_from_slice(&lane.to_be_bytes());
    }
    output
}

fn target_kind_tag(kind: TargetKind) -> u8 {
    match kind {
        TargetKind::CpuPolicy => 0,
        TargetKind::CpuSystem => 1,
        TargetKind::Cgroup => 2,
        TargetKind::Process => 3,
        TargetKind::Gpu => 4,
        TargetKind::Irq => 5,
        TargetKind::Sysctl => 6,
    }
}

fn equality_tag(kind: EqualityKind) -> u8 {
    match kind {
        EqualityKind::ByteExact => 0,
        EqualityKind::ScalarExact => 1,
        EqualityKind::SetExact => 2,
    }
}

fn feature_class_tag(classification: FeatureClass) -> u8 {
    match classification {
        FeatureClass::RuntimeMutable => 0,
        FeatureClass::Conditional => 1,
        FeatureClass::Experimental => 2,
        FeatureClass::BootOnlyReportOnly => 3,
    }
}

fn risk_tag(risk: RiskClass) -> u8 {
    match risk {
        RiskClass::Low => 0,
        RiskClass::Medium => 1,
        RiskClass::High => 2,
        RiskClass::Critical => 3,
    }
}

fn write_kind(writer: &mut DigestWriter, kind: &MutationKind) {
    writer.str(kind.operation_id().as_str());
    writer.str(&format!("{kind:?}"));
}

/// Renderer for an already-resolved plan.  It has no access to policy or
/// discovery inputs and therefore cannot perform detection or make decisions.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct HumanPlanRenderer;

/// Rendering port for deterministic dry-run output.
pub trait PlanRenderer {
    /// Render a complete plan without changing it or probing the host.
    fn render(&self, plan: &Plan) -> String;
}

impl PlanRenderer for HumanPlanRenderer {
    fn render(&self, plan: &Plan) -> String {
        render_dry_run(plan)
    }
}

/// Render a plan in stable human-readable form.
pub fn render_dry_run(plan: &Plan) -> String {
    let mut output = String::new();
    match plan.profile {
        Some(profile) => {
            let _ = writeln!(&mut output, "Profile: {profile}");
        }
        None => output.push_str("Profile: unspecified\n"),
    }
    for item in &plan.items {
        output.push('\n');
        let _ = writeln!(&mut output, "{}", item.control);
        if let Some(target) = &item.target {
            let _ = writeln!(&mut output, "  target: {target}");
        } else {
            output.push_str("  target: aggregate/unknown\n");
        }
        if let Some(current) = &item.current {
            let _ = writeln!(&mut output, "  current: {}", render_value(current));
        }
        if let Some(desired) = &item.desired {
            let _ = writeln!(&mut output, "  proposed: {}", render_value(desired));
        }
        let _ = writeln!(&mut output, "  action: {}", item.action);
        let _ = writeln!(&mut output, "  risk: {}", render_risk(item.risk));
        let _ = writeln!(&mut output, "  feature: {}", item.feature);
        if item.feature_class == FeatureClass::Experimental {
            let _ = writeln!(&mut output, "  experimental: {}", item.experimental);
        }
        if let Some(reason) = &item.reason {
            let _ = writeln!(&mut output, "  reason: {reason}");
        }
        if item.action.is_executable() {
            let rollback = render_rollback(item.control, item.restore);
            let _ = writeln!(&mut output, "  rollback: {rollback}");
            let _ = writeln!(
                &mut output,
                "  verify: bounded readback ({})",
                render_equality(item.verification.equality)
            );
        }
        let _ = writeln!(&mut output, "  rationale: {}", item.rationale);
    }
    output
}

fn render_value(value: &PlanValue) -> String {
    match value {
        PlanValue::Text(value) => value.as_str().to_owned(),
        PlanValue::Typed(value) => match value {
            TypedValue::Governor(value) => value.as_str().to_owned(),
            TypedValue::EnergyPreference(value) => render_energy(*value).to_owned(),
            TypedValue::CpuBoost(value) => match value {
                CpuBoostState::Enabled => "enabled".to_owned(),
                CpuBoostState::Disabled => "disabled".to_owned(),
            },
            TypedValue::PlatformProfile(value) => value.as_str().to_owned(),
            TypedValue::GpuPerformanceProfile(value) => render_gpu_profile(*value).to_owned(),
            TypedValue::GpuPowerLimit(value) => format!("{} mW", value.get()),
            TypedValue::IrqAffinity(value) | TypedValue::CgroupCpuset(value) => value
                .as_slice()
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(","),
            TypedValue::CpuFrequency { min_khz, max_khz } => format!(
                "min={} kHz max={} kHz",
                min_khz
                    .map(|value| value.get())
                    .map_or_else(|| "preserve".to_owned(), |value| value.to_string()),
                max_khz
                    .map(|value| value.get())
                    .map_or_else(|| "preserve".to_owned(), |value| value.to_string())
            ),
            TypedValue::CgroupCpuWeight(value) => value.get().to_string(),
            TypedValue::CgroupCpuMax { quota, period } => {
                let quota = match quota {
                    crate::mutation::CpuQuota::Max => "max".to_owned(),
                    crate::mutation::CpuQuota::Micros(value) => value.to_string(),
                };
                format!("{quota} / {} us", period.get())
            }
            TypedValue::CgroupIoWeight(value) => value.get().to_string(),
            TypedValue::CgroupUclamp(value) => render_uclamp(*value),
            TypedValue::CgroupLifecycle {
                kind,
                name,
                present,
            } => format!("{kind:?}:{}:{}", name.as_str(), present),
            TypedValue::ProcessPlacement(cgroup) => {
                format!("cgroup:{}", cgroup.handle.as_str())
            }
            TypedValue::Nice(value) => value.get().to_string(),
            TypedValue::IoPriority(value) => {
                format!("{:?}:{}", value.class(), value.level())
            }
            TypedValue::RuntimeSysctl { key, value } => {
                format!("{key:?}={}", value.get())
            }
        },
    }
}

fn render_uclamp(value: UclampValue) -> String {
    match value {
        UclampValue::Value(value) => value.to_string(),
        UclampValue::Max => "max".to_owned(),
    }
}

fn render_energy(value: EnergyPreference) -> &'static str {
    match value {
        EnergyPreference::Performance => "performance",
        EnergyPreference::BalancePerformance => "balance_performance",
        EnergyPreference::BalancePower => "balance_power",
        EnergyPreference::Power => "power",
    }
}

fn render_gpu_profile(value: GpuProfile) -> &'static str {
    match value {
        GpuProfile::Performance => "performance",
        GpuProfile::Balanced => "balanced",
        GpuProfile::PowerSave => "powersave",
    }
}

fn render_risk(value: RiskClass) -> &'static str {
    match value {
        RiskClass::Low => "low",
        RiskClass::Medium => "medium",
        RiskClass::High => "high",
        RiskClass::Critical => "critical",
    }
}

fn render_rollback(control: ControlId, contract: RestoreContract) -> String {
    let value = match contract.mode {
        Some(RestoreMode::CompareAndRestore) => "compare-and-restore",
        None => "not defined",
    };
    format!(
        "{value} original {control} ({})",
        render_equality(contract.equality)
    )
}

fn render_equality(value: EqualityKind) -> &'static str {
    match value {
        EqualityKind::ByteExact => "byte-exact",
        EqualityKind::ScalarExact => "scalar-exact",
        EqualityKind::SetExact => "set-exact",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{
        CapabilityDescriptor, CapabilityEvidence, EvidenceSource, OperationDescriptor,
        PrivilegeRequirement,
    };
    use crate::mutation::CpuSet;

    const BACKEND: &str = "fixture.cpu";

    fn descriptor(
        capability: &str,
        operation: &str,
        target_kind: TargetKind,
        class: FeatureClass,
        risk: RiskClass,
        equality: EqualityKind,
        backend: &str,
    ) -> CapabilityDescriptor {
        CapabilityDescriptor {
            id: capability_id(capability),
            backend: BackendId::new(backend).expect("valid fixture backend"),
            target_kind,
            state: CapabilityState::Available,
            operations: vec![OperationDescriptor {
                id: operation_id(operation),
                privilege: PrivilegeRequirement::PrivilegedMutation,
                equality,
                classification: class,
            }],
            privilege: PrivilegeRequirement::PrivilegedMutation,
            equality,
            risk,
            classification: class,
            evidence: vec![CapabilityEvidence {
                source: EvidenceSource::Synthetic,
                detail: format!("fixture exposes {capability}"),
            }],
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn complete_contract(
        capability: &str,
        operation: &str,
        control: ControlId,
        target_kind: TargetKind,
        class: FeatureClass,
        risk: RiskClass,
        backend: &str,
        explicit_opt_in: bool,
    ) -> OperationContract {
        OperationContract::complete(
            operation_id(operation),
            capability_id(capability),
            BackendId::new(backend).expect("valid fixture backend"),
            target_kind,
            control,
            EqualityKind::ScalarExact,
            risk,
            class,
            explicit_opt_in,
        )
    }

    fn cpu_inventory() -> CapabilityInventory {
        CapabilityInventory {
            observed_at: Timestamp::from_unix_millis(10),
            capabilities: vec![
                descriptor(
                    capability_ids::CPU_POLICY_GOVERNOR,
                    "cpu.governor",
                    TargetKind::CpuPolicy,
                    FeatureClass::RuntimeMutable,
                    RiskClass::Low,
                    EqualityKind::ScalarExact,
                    BACKEND,
                ),
                descriptor(
                    capability_ids::CPU_POLICY_ENERGY_PREFERENCE,
                    "cpu.energy_preference",
                    TargetKind::CpuPolicy,
                    FeatureClass::RuntimeMutable,
                    RiskClass::Low,
                    EqualityKind::ScalarExact,
                    BACKEND,
                ),
            ],
        }
    }

    fn cpu_current(governor: &str, epp: EnergyPreference) -> CurrentState {
        let cpu_target = TargetId::new("cpu.policy.0").expect("valid CPU target");
        let cpu_identity = TargetIdentity::from_bytes([7; 16]);
        let governor = GovernorId::new(governor).expect("valid fixture governor");
        let governor_value = PlanValue::Typed(TypedValue::Governor(governor));
        let epp_value = PlanValue::Typed(TypedValue::EnergyPreference(epp));
        CurrentState::new(
            Timestamp::from_unix_millis(10),
            vec![
                CurrentStateFact::known(
                    capability_id(capability_ids::CPU_POLICY_GOVERNOR),
                    cpu_target.clone(),
                    ControlId::CpuGovernor,
                    governor_value.clone(),
                    fingerprint_for_value(&governor_value),
                )
                .with_supported_values(vec![
                    PlanValue::Typed(TypedValue::Governor(
                        GovernorId::new("schedutil").expect("valid governor"),
                    )),
                    PlanValue::Typed(TypedValue::Governor(
                        GovernorId::new("performance").expect("valid governor"),
                    )),
                ])
                .with_target_identity(cpu_identity)
                .with_typed_target(TypedTarget::CpuPolicy(CpuPolicyId::new(0))),
                CurrentStateFact::known(
                    capability_id(capability_ids::CPU_POLICY_ENERGY_PREFERENCE),
                    cpu_target,
                    ControlId::CpuEnergyPreference,
                    epp_value.clone(),
                    fingerprint_for_value(&epp_value),
                )
                .with_supported_values(vec![
                    PlanValue::Typed(TypedValue::EnergyPreference(
                        EnergyPreference::BalancePerformance,
                    )),
                    PlanValue::Typed(TypedValue::EnergyPreference(EnergyPreference::Performance)),
                ])
                .with_target_identity(cpu_identity)
                .with_typed_target(TypedTarget::CpuPolicy(CpuPolicyId::new(0))),
            ],
        )
        .expect("fixture current state is consistent")
    }

    fn cpu_planner() -> TypedPlanner {
        let mut epp = complete_contract(
            capability_ids::CPU_POLICY_ENERGY_PREFERENCE,
            "cpu.energy_preference",
            ControlId::CpuEnergyPreference,
            TargetKind::CpuPolicy,
            FeatureClass::RuntimeMutable,
            RiskClass::Low,
            BACKEND,
            false,
        );
        epp.dependencies = vec![operation_id("cpu.governor")];
        TypedPlanner::new(OperationCatalog::new(vec![
            complete_contract(
                capability_ids::CPU_POLICY_GOVERNOR,
                "cpu.governor",
                ControlId::CpuGovernor,
                TargetKind::CpuPolicy,
                FeatureClass::RuntimeMutable,
                RiskClass::Low,
                BACKEND,
                false,
            ),
            epp,
        ]))
    }

    fn build_cpu(profile: Profile, inventory: CapabilityInventory, current: CurrentState) -> Plan {
        cpu_planner()
            .build(&PlannerInput {
                policy: PlannerPolicy::for_profile(profile),
                inventory,
                current_state: current,
            })
            .expect("fixture plan should be valid")
    }

    fn item(plan: &Plan, control: ControlId) -> &PlanItem {
        plan.items
            .iter()
            .find(|item| item.control == control && item.target.is_some())
            .expect("fixture item exists")
    }

    #[test]
    fn profiles_are_typed_and_parse_only_closed_values() {
        assert_eq!(Profile::parse("balanced").unwrap(), Profile::Balanced);
        assert_eq!(Profile::parse("performance").unwrap(), Profile::Performance);
        assert_eq!(Profile::parse("extreme").unwrap(), Profile::Extreme);
        assert!(Profile::parse("write-all-the-things").is_err());
        assert_ne!(Profile::Balanced.intent(), Profile::Performance.intent());
        assert_eq!(
            Profile::Performance.intent().governor,
            Profile::Extreme.intent().governor
        );
        assert_ne!(
            Profile::Performance.intent().aggressiveness,
            Profile::Extreme.intent().aggressiveness
        );
    }

    #[test]
    fn all_profiles_produce_explicit_deterministic_cpu_decisions() {
        let inventory = cpu_inventory();
        let current = cpu_current("schedutil", EnergyPreference::BalancePerformance);
        let balanced = build_cpu(Profile::Balanced, inventory.clone(), current.clone());
        let performance = build_cpu(Profile::Performance, inventory.clone(), current.clone());
        let extreme = build_cpu(Profile::Extreme, inventory, current);

        assert_eq!(balanced.profile, Some(Profile::Balanced));
        assert_eq!(performance.profile, Some(Profile::Performance));
        assert_eq!(extreme.profile, Some(Profile::Extreme));
        assert_eq!(
            item(&balanced, ControlId::CpuGovernor).action,
            PlanAction::NoOp
        );
        assert_eq!(
            item(&balanced, ControlId::CpuEnergyPreference).action,
            PlanAction::NoOp
        );
        assert_eq!(
            item(&performance, ControlId::CpuGovernor).action,
            PlanAction::Mutation
        );
        assert_eq!(
            item(&performance, ControlId::CpuEnergyPreference).action,
            PlanAction::Mutation
        );
        assert_eq!(
            item(&extreme, ControlId::CpuGovernor).desired,
            item(&performance, ControlId::CpuGovernor).desired
        );
        assert_eq!(
            item(&extreme, ControlId::CpuEnergyPreference).desired,
            item(&performance, ControlId::CpuEnergyPreference).desired
        );
        assert_ne!(balanced, performance);
        assert_ne!(performance, extreme);
    }

    #[test]
    fn performance_resolves_actual_fixture_values_into_mutations() {
        let plan = build_cpu(
            Profile::Performance,
            cpu_inventory(),
            cpu_current("schedutil", EnergyPreference::BalancePerformance),
        );
        let governor = item(&plan, ControlId::CpuGovernor);
        assert_eq!(governor.action, PlanAction::Mutation);
        assert_eq!(
            governor.desired.as_ref().unwrap().to_string(),
            "performance"
        );
        let epp = item(&plan, ControlId::CpuEnergyPreference);
        assert_eq!(epp.action, PlanAction::Mutation);
        assert_eq!(
            epp.mutation.as_ref().unwrap().rollback.mode,
            RestoreMode::CompareAndRestore
        );
        assert_eq!(
            epp.mutation.as_ref().unwrap().dependencies,
            vec![governor.mutation.as_ref().unwrap().mutation_id]
        );
        assert_eq!(plan.mutations.len(), 2);
    }

    #[test]
    fn identical_state_is_a_visible_noop_and_not_executable() {
        let plan = build_cpu(
            Profile::Performance,
            cpu_inventory(),
            cpu_current("performance", EnergyPreference::Performance),
        );
        let governor = item(&plan, ControlId::CpuGovernor);
        assert_eq!(governor.action, PlanAction::NoOp);
        assert!(governor.mutation.is_none());
        assert!(!plan.mutations.iter().any(|mutation| {
            mutation.capability.as_str() == capability_ids::CPU_POLICY_GOVERNOR
        }));
    }

    #[test]
    fn report_mode_never_emits_mutations_even_with_complete_contracts() {
        let plan = cpu_planner()
            .build(&PlannerInput {
                policy: PlannerPolicy::report(Profile::Performance),
                inventory: cpu_inventory(),
                current_state: cpu_current("schedutil", EnergyPreference::BalancePerformance),
            })
            .expect("report mode should retain denied decisions");
        assert_eq!(plan.mutations.len(), 0);
        assert!(plan.items.iter().any(|item| {
            item.control == ControlId::CpuGovernor && item.action == PlanAction::DeniedByPolicy
        }));
        assert!(plan.items.iter().any(|item| {
            item.control == ControlId::CpuEnergyPreference
                && item.action == PlanAction::DeniedByPolicy
        }));
    }

    #[test]
    fn missing_optional_capabilities_remain_explicit() {
        let plan = build_cpu(
            Profile::Performance,
            cpu_inventory(),
            cpu_current("performance", EnergyPreference::Performance),
        );
        let epp = item(&plan, ControlId::CpuEnergyPreference);
        assert_eq!(epp.action, PlanAction::NoOp);
        let platform = plan
            .items
            .iter()
            .find(|item| item.capability.as_str() == capability_ids::PLATFORM_PROFILE)
            .expect("platform decision is retained");
        assert_eq!(platform.action, PlanAction::Unsupported);
        let gpu = plan
            .items
            .iter()
            .find(|item| item.capability.as_str() == capability_ids::GPU_PERFORMANCE_PROFILE)
            .expect("GPU decision is retained");
        assert_eq!(gpu.action, PlanAction::Unsupported);
    }

    #[test]
    fn platform_profile_resolves_to_the_closed_typed_value_advertised_by_sysfs() {
        let target = TargetId::new("system.platform.profile").expect("valid platform target");
        let identity = TargetIdentity::from_bytes([8; 16]);
        let current = PlanValue::Typed(TypedValue::PlatformProfile(
            PlatformProfileId::new("balanced").expect("valid profile"),
        ));
        let performance = PlanValue::Typed(TypedValue::PlatformProfile(
            PlatformProfileId::new("performance").expect("valid profile"),
        ));
        let fact = CurrentStateFact::known(
            capability_id(capability_ids::PLATFORM_PROFILE),
            target,
            ControlId::PlatformProfile,
            current.clone(),
            fingerprint_for_value(&current),
        )
        .with_supported_values(vec![current, performance])
        .with_target_identity(identity)
        .with_typed_target(TypedTarget::CpuSystem);
        let inventory = CapabilityInventory {
            observed_at: Timestamp::from_unix_millis(10),
            capabilities: vec![descriptor(
                capability_ids::PLATFORM_PROFILE,
                "platform.profile",
                TargetKind::CpuSystem,
                FeatureClass::Conditional,
                RiskClass::Medium,
                EqualityKind::ScalarExact,
                BACKEND,
            )],
        };
        let planner = TypedPlanner::new(OperationCatalog::new(vec![complete_contract(
            capability_ids::PLATFORM_PROFILE,
            "platform.profile",
            ControlId::PlatformProfile,
            TargetKind::CpuSystem,
            FeatureClass::Conditional,
            RiskClass::Medium,
            BACKEND,
            false,
        )]));
        let plan = planner
            .build(&PlannerInput {
                policy: PlannerPolicy::for_profile(Profile::Performance),
                inventory,
                current_state: CurrentState::new(Timestamp::from_unix_millis(10), vec![fact])
                    .expect("platform current state is consistent"),
            })
            .expect("advertised platform profile is executable");
        let item = plan
            .items
            .iter()
            .find(|item| item.control == ControlId::PlatformProfile)
            .expect("platform profile decision is present");
        assert_eq!(item.action, PlanAction::Mutation);
        assert!(matches!(
            item.mutation.as_ref().map(|mutation| &mutation.kind),
            Some(MutationKind::PlatformProfile { profile })
                if profile.as_str() == "performance"
        ));
    }

    #[test]
    fn missing_epp_is_unsupported_but_does_not_fail_an_optional_plan() {
        let mut inventory = cpu_inventory();
        inventory.capabilities.retain(|descriptor| {
            descriptor.id.as_str() != capability_ids::CPU_POLICY_ENERGY_PREFERENCE
        });
        let plan = build_cpu(
            Profile::Performance,
            inventory,
            cpu_current("schedutil", EnergyPreference::BalancePerformance),
        );
        assert_eq!(
            item(&plan, ControlId::CpuEnergyPreference).action,
            PlanAction::Unsupported
        );
    }

    #[test]
    fn required_unavailable_request_rejects_the_plan() {
        let target = TargetId::new("cpu.policy.0").expect("valid target");
        let request = PolicyRequest::optional(
            capability_id(capability_ids::CPU_POLICY_ENERGY_PREFERENCE),
            target,
            MutationKind::CpuEnergyPreference {
                policy: CpuPolicyId::new(0),
                value: EnergyPreference::Performance,
            },
        )
        .required();
        let mut inventory = cpu_inventory();
        inventory.capabilities.retain(|descriptor| {
            descriptor.id.as_str() != capability_ids::CPU_POLICY_ENERGY_PREFERENCE
        });
        let error = cpu_planner()
            .build(&PlannerInput {
                policy: PlannerPolicy::for_profile(Profile::Performance).request(request),
                inventory,
                current_state: cpu_current("schedutil", EnergyPreference::BalancePerformance),
            })
            .expect_err("required unsupported operation must reject the plan");
        assert_eq!(error.code, ErrorCode::PlanningError);
    }

    #[test]
    fn preserve_override_beats_profile_intent() {
        let policy = PlannerPolicy::for_profile(Profile::Performance).preserve(
            Feature::CpuGovernor,
            "administrator preserves the selected governor",
        );
        let plan = cpu_planner()
            .build(&PlannerInput {
                policy,
                inventory: cpu_inventory(),
                current_state: cpu_current("schedutil", EnergyPreference::BalancePerformance),
            })
            .expect("preserve policy should remain valid");
        assert_eq!(
            item(&plan, ControlId::CpuGovernor).action,
            PlanAction::Preserved
        );
        assert!(plan.mutations.iter().all(|mutation| {
            mutation.capability.as_str() != capability_ids::CPU_POLICY_GOVERNOR
        }));
    }

    #[test]
    fn plan_rejects_duplicate_target_control_mutations() {
        let plan = build_cpu(
            Profile::Performance,
            cpu_inventory(),
            cpu_current("schedutil", EnergyPreference::BalancePerformance),
        );
        let first = item(&plan, ControlId::CpuGovernor).clone();
        let mut second = first.clone();
        let mut mutation = second.mutation.clone().expect("fixture mutation");
        mutation.mutation_id = MutationId::new(99);
        second.mutation = Some(mutation);
        let error = Plan::from_items(
            PlanId::from_bytes([11; 16]),
            [12; 32],
            [13; 32],
            [14; 32],
            Profile::Performance,
            vec![first, second],
        )
        .expect_err("one target/control cannot be mutated twice");
        assert_eq!(error.code, ErrorCode::PlanningError);
    }

    #[test]
    fn equal_precedence_conflict_is_rejected_deterministically() {
        let target = TargetId::new("cpu.policy.0").expect("valid target");
        let first = MutationKind::CpuGovernor {
            policy: CpuPolicyId::new(0),
            governor: GovernorId::new("performance").expect("valid governor"),
        };
        let second = MutationKind::CpuGovernor {
            policy: CpuPolicyId::new(0),
            governor: GovernorId::new("schedutil").expect("valid governor"),
        };
        let policy = PlannerPolicy::for_profile(Profile::Balanced)
            .proposal(
                PolicySource::User,
                PolicyRequest::optional(
                    capability_id(capability_ids::CPU_POLICY_GOVERNOR),
                    target.clone(),
                    first,
                ),
            )
            .proposal(
                PolicySource::User,
                PolicyRequest::optional(
                    capability_id(capability_ids::CPU_POLICY_GOVERNOR),
                    target,
                    second,
                ),
            );
        let error = cpu_planner()
            .build(&PlannerInput {
                policy,
                inventory: cpu_inventory(),
                current_state: cpu_current("schedutil", EnergyPreference::BalancePerformance),
            })
            .expect_err("equal-precedence values must not use iteration order");
        assert_eq!(error.code, ErrorCode::PlanningError);
    }

    #[test]
    fn insertion_order_does_not_change_plan_or_digest() {
        let inventory = cpu_inventory();
        let mut reversed_inventory = inventory.clone();
        reversed_inventory.capabilities.reverse();
        let current = cpu_current("schedutil", EnergyPreference::BalancePerformance);
        let mut reversed_current = current.clone();
        reversed_current.facts.reverse();
        let first = build_cpu(Profile::Performance, inventory, current);
        let second = build_cpu(Profile::Performance, reversed_inventory, reversed_current);
        assert_eq!(first, second);
    }

    #[test]
    fn incomplete_operation_contract_is_rejected_before_mutation() {
        let mut contract = complete_contract(
            capability_ids::CPU_POLICY_GOVERNOR,
            "cpu.governor",
            ControlId::CpuGovernor,
            TargetKind::CpuPolicy,
            FeatureClass::RuntimeMutable,
            RiskClass::Low,
            BACKEND,
            false,
        );
        contract.snapshot.typed_preimage = false;
        let planner = TypedPlanner::new(OperationCatalog::new(vec![contract]));
        let error = planner
            .build(&PlannerInput {
                policy: PlannerPolicy::for_profile(Profile::Performance),
                inventory: cpu_inventory(),
                current_state: cpu_current("schedutil", EnergyPreference::BalancePerformance),
            })
            .expect_err("incomplete restore contract must fail closed");
        assert_eq!(error.code, ErrorCode::PlanningError);
    }

    #[test]
    fn experimental_and_explicit_opt_in_states_are_distinct() {
        let gpu_capability = capability_ids::GPU_PERFORMANCE_PROFILE;
        let mut inventory = cpu_inventory();
        inventory.capabilities.push(descriptor(
            gpu_capability,
            "gpu.performance.profile",
            TargetKind::Gpu,
            FeatureClass::Experimental,
            RiskClass::Critical,
            EqualityKind::ScalarExact,
            "fixture.gpu",
        ));
        let gpu_target = TargetId::new("gpu.0").expect("valid GPU target");
        let current_gpu =
            PlanValue::Typed(TypedValue::GpuPerformanceProfile(GpuProfile::PowerSave));
        let mut current = cpu_current("performance", EnergyPreference::Performance);
        current.facts.push(
            CurrentStateFact::known(
                capability_id(gpu_capability),
                gpu_target,
                ControlId::GpuPerformanceProfile,
                current_gpu.clone(),
                fingerprint_for_value(&current_gpu),
            )
            .with_target_identity(TargetIdentity::from_bytes([8; 16]))
            .with_typed_target(TypedTarget::Gpu(GpuId::new(0))),
        );
        let mut contracts = cpu_planner().resolver.catalog.contracts().to_vec();
        contracts.push(complete_contract(
            gpu_capability,
            "gpu.performance.profile",
            ControlId::GpuPerformanceProfile,
            TargetKind::Gpu,
            FeatureClass::Experimental,
            RiskClass::Critical,
            "fixture.gpu",
            true,
        ));
        let planner = TypedPlanner::new(OperationCatalog::new(contracts));
        let disabled = planner
            .build(&PlannerInput {
                policy: PlannerPolicy::for_profile(Profile::Extreme),
                inventory: inventory.clone(),
                current_state: current.clone(),
            })
            .expect("disabled experimental feature remains reportable");
        assert_eq!(
            item_by_capability(&disabled, gpu_capability).action,
            PlanAction::ExperimentalDisabled
        );
        let enabled_without_opt_in = planner
            .build(&PlannerInput {
                policy: PlannerPolicy::for_profile(Profile::Extreme)
                    .with_experimental_permission(true),
                inventory: inventory.clone(),
                current_state: current.clone(),
            })
            .expect("missing opt-in remains reportable");
        assert_eq!(
            item_by_capability(&enabled_without_opt_in, gpu_capability).action,
            PlanAction::ExplicitOptInRequired
        );
        let enabled = planner
            .build(&PlannerInput {
                policy: PlannerPolicy::for_profile(Profile::Extreme)
                    .with_experimental_permission(true)
                    .opt_in(Feature::GpuTuning),
                inventory,
                current_state: current,
            })
            .expect("explicitly enabled experimental operation should be eligible");
        assert_eq!(
            item_by_capability(&enabled, gpu_capability).action,
            PlanAction::Mutation
        );
    }

    #[test]
    fn extreme_irq_requires_explicit_opt_in() {
        let capability = capability_ids::IRQ_AFFINITY;
        let inventory = CapabilityInventory {
            observed_at: Timestamp::from_unix_millis(1),
            capabilities: vec![descriptor(
                capability,
                "irq.affinity",
                TargetKind::Irq,
                FeatureClass::Experimental,
                RiskClass::Critical,
                EqualityKind::SetExact,
                "fixture.irq",
            )],
        };
        let target = TargetId::new("irq.7").expect("valid IRQ target");
        let current_value = PlanValue::Typed(TypedValue::IrqAffinity(
            CpuSet::new(vec![0]).expect("valid CPU set"),
        ));
        let current = CurrentState::new(
            Timestamp::from_unix_millis(1),
            vec![CurrentStateFact::known(
                capability_id(capability),
                target,
                ControlId::IrqAffinity,
                current_value.clone(),
                fingerprint_for_value(&current_value),
            )
            .with_target_identity(TargetIdentity::from_bytes([9; 16]))
            .with_typed_target(TypedTarget::Irq(IrqId::new(7)))],
        )
        .expect("valid IRQ current state");
        let planner = TypedPlanner::new(OperationCatalog::new(Vec::new()));
        let plan = planner
            .build(&PlannerInput {
                policy: PlannerPolicy::for_profile(Profile::Extreme)
                    .with_experimental_permission(true),
                inventory,
                current_state: current,
            })
            .expect("IRQ should remain a visible decision");
        assert_eq!(
            item_by_capability(&plan, capability).action,
            PlanAction::ExplicitOptInRequired
        );
    }

    #[test]
    fn dry_run_renderer_is_semantic_and_deterministic() {
        let plan = build_cpu(
            Profile::Performance,
            cpu_inventory(),
            cpu_current("schedutil", EnergyPreference::BalancePerformance),
        );
        let first = render_dry_run(&plan);
        let second = HumanPlanRenderer.render(&plan);
        assert_eq!(first, second);
        assert!(first.contains("Profile: performance"));
        assert!(first.contains("CPU governor"));
        assert!(first.contains("action: change"));
        assert!(first.contains("rollback: compare-and-restore"));
        assert!(first.contains("platform profile"));
    }

    fn item_by_capability<'a>(plan: &'a Plan, capability: &str) -> &'a PlanItem {
        plan.items
            .iter()
            .find(|item| item.capability.as_str() == capability)
            .expect("capability decision exists")
    }
}
