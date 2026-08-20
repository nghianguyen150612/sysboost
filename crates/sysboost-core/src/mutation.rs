//! Closed, typed mutation vocabulary and transaction preimages.

use crate::capability::EqualityKind;
use crate::error::{ErrorCode, Stage, SysboostError};
use crate::ids::{CapabilityId, MutationId, TargetId};
use crate::time::Timestamp;

/// Maximum raw preimage size retained by the initial journal contract.
pub const MAX_PREIMAGE_BYTES: usize = 4096;

/// A CPUFreq policy index discovered from the kernel.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CpuPolicyId(u32);

impl CpuPolicyId {
    /// Construct a policy ID.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Return the numeric policy ID.
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// A GPU index discovered by a reviewed backend.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GpuId(u32);

impl GpuId {
    /// Construct a GPU ID.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Return the numeric GPU ID.
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// An IRQ number discovered by a reviewed backend.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IrqId(u32);

impl IrqId {
    /// Construct an IRQ ID.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Return the numeric IRQ number.
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// An opaque existing cgroup identity. The relative handle is never a caller-
/// supplied privileged path; the Linux adapter resolves it after revalidation.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CgroupId {
    /// Cgroup mount identity.
    pub mount_id: u64,
    /// Inode identity where the host exposes one.
    pub inode: u64,
    /// Opaque adapter-owned handle.
    pub handle: TargetId,
}

impl CgroupId {
    /// Construct a cgroup identity from enumerated evidence.
    pub fn new(mount_id: u64, inode: u64, handle: TargetId) -> Self {
        Self {
            mount_id,
            inode,
            handle,
        }
    }
}

/// A governor name validated as a bounded semantic identifier.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GovernorId(String);

impl GovernorId {
    /// Construct a governor identifier returned by capability discovery.
    pub fn new(value: impl Into<String>) -> Result<Self, SysboostError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
        {
            return Err(SysboostError::new(
                ErrorCode::InvalidInput,
                "governor identifier is not a bounded semantic value",
            ));
        }
        Ok(Self(value))
    }

    /// Return the validated governor name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// CPU energy-performance preference vocabulary.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EnergyPreference {
    /// Favor performance.
    Performance,
    /// Balance toward performance.
    BalancePerformance,
    /// Balance toward power savings.
    BalancePower,
    /// Favor power savings.
    Power,
}

/// A strictly positive CPU frequency in kHz.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FrequencyKHz(u64);

impl FrequencyKHz {
    /// Construct a frequency.
    pub fn new(value: u64) -> Result<Self, SysboostError> {
        if value == 0 {
            Err(SysboostError::new(
                ErrorCode::InvalidInput,
                "frequency must be greater than zero",
            ))
        } else {
            Ok(Self(value))
        }
    }

    /// Return the frequency in kHz.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A bounded cgroup CPU weight in the Linux-defined range.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CpuWeight(u16);

impl CpuWeight {
    /// Lowest accepted Linux CPU weight.
    pub const MIN: u16 = 1;
    /// Highest accepted Linux CPU weight.
    pub const MAX: u16 = 10_000;

    /// Construct a bounded weight.
    pub fn new(value: u16) -> Result<Self, SysboostError> {
        if !(Self::MIN..=Self::MAX).contains(&value) {
            Err(SysboostError::new(
                ErrorCode::InvalidInput,
                "CPU weight is outside the accepted range",
            ))
        } else {
            Ok(Self(value))
        }
    }

    /// Return the numeric weight.
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// A bounded cgroup CPU quota period in microseconds.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CpuPeriod(u64);

impl CpuPeriod {
    /// Minimum period accepted by the domain contract.
    pub const MIN: u64 = 1_000;
    /// Maximum period accepted by the domain contract.
    pub const MAX: u64 = 1_000_000;

    /// Construct a bounded period.
    pub fn new(value: u64) -> Result<Self, SysboostError> {
        if !(Self::MIN..=Self::MAX).contains(&value) {
            Err(SysboostError::new(
                ErrorCode::InvalidInput,
                "CPU period is outside the accepted range",
            ))
        } else {
            Ok(Self(value))
        }
    }

    /// Return the period in microseconds.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A cgroup quota or the Linux `max` sentinel.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CpuQuota {
    /// No quota.
    Max,
    /// Quota in microseconds per period.
    Micros(u64),
}

impl CpuQuota {
    /// Construct a finite quota.
    pub fn micros(value: u64) -> Result<Self, SysboostError> {
        if value == 0 {
            Err(SysboostError::new(
                ErrorCode::InvalidInput,
                "finite CPU quota must be greater than zero",
            ))
        } else {
            Ok(Self::Micros(value))
        }
    }
}

/// A sorted, duplicate-free non-empty CPU set.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CpuSet(Vec<u32>);

impl CpuSet {
    /// Construct a canonical CPU set.
    pub fn new(mut cpus: Vec<u32>) -> Result<Self, SysboostError> {
        cpus.sort_unstable();
        cpus.dedup();
        if cpus.is_empty() {
            return Err(SysboostError::new(
                ErrorCode::InvalidInput,
                "CPU set must not be empty",
            ));
        }
        Ok(Self(cpus))
    }

    /// Return the canonical CPU list.
    pub fn as_slice(&self) -> &[u32] {
        &self.0
    }
}

/// Reviewed GPU performance profile vocabulary.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum GpuProfile {
    /// Maximum reviewed performance profile.
    Performance,
    /// Balanced profile.
    Balanced,
    /// Power-saving profile.
    PowerSave,
}

/// A strictly positive GPU power limit in milliwatts.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PowerMilliwatts(u32);

impl PowerMilliwatts {
    /// Construct a power limit.
    pub fn new(value: u32) -> Result<Self, SysboostError> {
        if value == 0 {
            Err(SysboostError::new(
                ErrorCode::InvalidInput,
                "power limit must be greater than zero",
            ))
        } else {
            Ok(Self(value))
        }
    }

    /// Return the limit in milliwatts.
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Closed key vocabulary for future runtime sysctl backends.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ApprovedSysctlKey {
    /// Reviewed scheduler util-clamping key family placeholder.
    SchedulerUtilClamping,
}

/// Bounded value for an approved sysctl key.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ApprovedSysctlValue(i64);

impl ApprovedSysctlValue {
    /// Construct a value for a reviewed key.
    pub const fn new(value: i64) -> Self {
        Self(value)
    }

    /// Return the numeric value.
    pub const fn get(self) -> i64 {
        self.0
    }
}

/// Bounded raw bytes retained as a mutation preimage.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct BoundedBytes(Vec<u8>);

impl BoundedBytes {
    /// Construct a preimage-sized byte vector.
    pub fn new(value: impl Into<Vec<u8>>) -> Result<Self, SysboostError> {
        let value = value.into();
        if value.len() > MAX_PREIMAGE_BYTES {
            return Err(SysboostError::new(
                ErrorCode::SnapshotError,
                "preimage exceeds the journal byte bound",
            )
            .with_stage(Stage::Snapshot));
        }
        Ok(Self(value))
    }

    /// Borrow the original bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

/// Digest supplied by a backend for precondition and ownership checks.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct StateFingerprint([u8; 32]);

impl StateFingerprint {
    /// Construct a fingerprint from backend-computed bytes.
    pub const fn from_bytes(value: [u8; 32]) -> Self {
        Self(value)
    }

    /// Return fingerprint bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Stable identity evidence for a target at snapshot time.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TargetIdentity([u8; 16]);

impl TargetIdentity {
    /// Construct identity evidence.
    pub const fn from_bytes(value: [u8; 16]) -> Self {
        Self(value)
    }

    /// Return identity bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Closed operation vocabulary. Experimental variants remain disabled until
/// a reviewed backend implements their complete contract.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum MutationKind {
    /// CPU policy frequency bounds.
    CpuFrequency {
        /// CPUFreq policy.
        policy: CpuPolicyId,
        /// Optional minimum.
        min_khz: Option<FrequencyKHz>,
        /// Optional maximum.
        max_khz: Option<FrequencyKHz>,
    },
    /// CPU policy governor.
    CpuGovernor {
        /// CPUFreq policy.
        policy: CpuPolicyId,
        /// Desired governor.
        governor: GovernorId,
    },
    /// CPU energy preference.
    CpuEnergyPreference {
        /// CPUFreq policy.
        policy: CpuPolicyId,
        /// Desired preference.
        value: EnergyPreference,
    },
    /// Existing cgroup CPU weight.
    CgroupCpuWeight {
        /// Cgroup target.
        cgroup: CgroupId,
        /// Desired weight.
        weight: CpuWeight,
    },
    /// Existing cgroup CPU quota and period.
    CgroupCpuMax {
        /// Cgroup target.
        cgroup: CgroupId,
        /// Desired quota.
        quota: CpuQuota,
        /// Desired period.
        period: CpuPeriod,
    },
    /// Existing cgroup effective CPU set.
    CgroupCpuset {
        /// Cgroup target.
        cgroup: CgroupId,
        /// Desired set.
        cpus: CpuSet,
    },
    /// Experimental GPU performance profile.
    GpuPerformanceProfile {
        /// GPU target.
        device: GpuId,
        /// Desired profile.
        profile: GpuProfile,
    },
    /// Experimental GPU power limit.
    GpuPowerLimit {
        /// GPU target.
        device: GpuId,
        /// Desired power limit.
        milliwatts: PowerMilliwatts,
    },
    /// Experimental IRQ affinity.
    IrqAffinity {
        /// IRQ target.
        irq: IrqId,
        /// Desired CPU set.
        cpus: CpuSet,
    },
    /// Conditional, explicitly reviewed sysctl operation.
    RuntimeSysctl {
        /// Approved key.
        key: ApprovedSysctlKey,
        /// Desired value.
        value: ApprovedSysctlValue,
    },
}

impl MutationKind {
    /// Return the stable operation ID for registry and audit use.
    pub fn operation_id(&self) -> crate::ids::OperationId {
        let value = match self {
            Self::CpuFrequency { .. } => "cpu.frequency",
            Self::CpuGovernor { .. } => "cpu.governor",
            Self::CpuEnergyPreference { .. } => "cpu.energy_preference",
            Self::CgroupCpuWeight { .. } => "cgroup.cpu.weight",
            Self::CgroupCpuMax { .. } => "cgroup.cpu.max",
            Self::CgroupCpuset { .. } => "cgroup.cpuset.cpus",
            Self::GpuPerformanceProfile { .. } => "gpu.performance.profile",
            Self::GpuPowerLimit { .. } => "gpu.power.limit",
            Self::IrqAffinity { .. } => "irq.affinity",
            Self::RuntimeSysctl { .. } => "kernel.sysctl.runtime",
        };
        crate::ids::OperationId::new(value).expect("static operation IDs are valid")
    }

    /// Derive the typed desired value represented by this operation.
    pub fn typed_value(&self) -> TypedValue {
        match self {
            Self::CpuFrequency {
                min_khz, max_khz, ..
            } => TypedValue::CpuFrequency {
                min_khz: *min_khz,
                max_khz: *max_khz,
            },
            Self::CpuGovernor { governor, .. } => TypedValue::Governor(governor.clone()),
            Self::CpuEnergyPreference { value, .. } => TypedValue::EnergyPreference(*value),
            Self::CgroupCpuWeight { weight, .. } => TypedValue::CgroupCpuWeight(*weight),
            Self::CgroupCpuMax { quota, period, .. } => TypedValue::CgroupCpuMax {
                quota: *quota,
                period: *period,
            },
            Self::CgroupCpuset { cpus, .. } => TypedValue::CgroupCpuset(cpus.clone()),
            Self::GpuPerformanceProfile { profile, .. } => {
                TypedValue::GpuPerformanceProfile(*profile)
            }
            Self::GpuPowerLimit { milliwatts, .. } => TypedValue::GpuPowerLimit(*milliwatts),
            Self::IrqAffinity { cpus, .. } => TypedValue::IrqAffinity(cpus.clone()),
            Self::RuntimeSysctl { key, value } => TypedValue::RuntimeSysctl {
                key: *key,
                value: *value,
            },
        }
    }

    fn validate(&self) -> Result<(), SysboostError> {
        if let Self::CpuFrequency {
            min_khz: Some(min),
            max_khz: Some(max),
            ..
        } = self
        {
            if min > max {
                return Err(SysboostError::new(
                    ErrorCode::PlanningError,
                    "CPU frequency minimum exceeds maximum",
                )
                .with_stage(Stage::Plan));
            }
        }
        Ok(())
    }
}

/// Typed payload corresponding to a [`MutationKind`].
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum TypedValue {
    /// CPU frequency bounds.
    CpuFrequency {
        /// Minimum.
        min_khz: Option<FrequencyKHz>,
        /// Maximum.
        max_khz: Option<FrequencyKHz>,
    },
    /// Governor value.
    Governor(GovernorId),
    /// Energy preference.
    EnergyPreference(EnergyPreference),
    /// Cgroup weight.
    CgroupCpuWeight(CpuWeight),
    /// Cgroup quota and period.
    CgroupCpuMax {
        /// Quota.
        quota: CpuQuota,
        /// Period.
        period: CpuPeriod,
    },
    /// Cgroup CPU set.
    CgroupCpuset(CpuSet),
    /// GPU profile.
    GpuPerformanceProfile(GpuProfile),
    /// GPU power limit.
    GpuPowerLimit(PowerMilliwatts),
    /// IRQ CPU set.
    IrqAffinity(CpuSet),
    /// Reviewed sysctl value.
    RuntimeSysctl {
        /// Key.
        key: ApprovedSysctlKey,
        /// Value.
        value: ApprovedSysctlValue,
    },
}

/// Restore policy carried by every planned mutation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RollbackContract {
    /// Equality used to compare the current value with the session-owned value.
    pub equality: EqualityKind,
    /// Normal automatic mode.
    pub mode: RestoreMode,
}

/// Automatic restore mode.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RestoreMode {
    /// Restore only when the current state still belongs to this session.
    CompareAndRestore,
}

/// One planned, target-scoped mutation unit.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PlannedMutation {
    /// Stable mutation ID within the plan.
    pub mutation_id: MutationId,
    /// Semantic capability.
    pub capability: CapabilityId,
    /// Opaque target identity.
    pub target: TargetId,
    /// Closed typed operation.
    pub kind: MutationKind,
    /// Typed desired value, checked against `kind`.
    pub desired: TypedValue,
    /// Observation that must still match before snapshot/apply.
    pub precondition: StateFingerprint,
    /// Equality used for verification.
    pub equality: EqualityKind,
    /// Earlier mutations that must complete first.
    pub dependencies: Vec<MutationId>,
    /// Restore behavior.
    pub rollback: RollbackContract,
}

impl PlannedMutation {
    /// Construct a validated planned mutation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mutation_id: MutationId,
        capability: CapabilityId,
        target: TargetId,
        kind: MutationKind,
        desired: TypedValue,
        precondition: StateFingerprint,
        equality: EqualityKind,
        dependencies: Vec<MutationId>,
    ) -> Result<Self, SysboostError> {
        kind.validate()?;
        if kind.typed_value() != desired {
            return Err(SysboostError::new(
                ErrorCode::PlanningError,
                "mutation kind and typed desired value disagree",
            )
            .with_stage(Stage::Plan)
            .with_mutation(mutation_id));
        }
        if dependencies.contains(&mutation_id) {
            return Err(SysboostError::new(
                ErrorCode::PlanningError,
                "mutation cannot depend on itself",
            )
            .with_stage(Stage::Plan)
            .with_mutation(mutation_id));
        }
        Ok(Self {
            mutation_id,
            capability,
            target,
            kind,
            desired,
            precondition,
            equality,
            dependencies,
            rollback: RollbackContract {
                equality,
                mode: RestoreMode::CompareAndRestore,
            },
        })
    }
}

/// Exact state captured before any apply.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Snapshot {
    /// Mutation it belongs to.
    pub mutation_id: MutationId,
    /// Opaque target.
    pub target: TargetId,
    /// Original bytes where supported.
    pub original_raw: BoundedBytes,
    /// Original typed interpretation.
    pub original_typed: TypedValue,
    /// Backend-computed original fingerprint.
    pub original_fingerprint: StateFingerprint,
    /// Equality contract.
    pub equality: EqualityKind,
    /// Target identity at capture.
    pub target_identity: TargetIdentity,
    /// Capture timestamp.
    pub captured_at: Timestamp,
}

/// Readback receipt after an apply.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ApplyReceipt {
    /// Mutation applied.
    pub mutation_id: MutationId,
    /// Fingerprint observed before apply.
    pub observed_precondition: StateFingerprint,
    /// Fingerprint proven after apply.
    pub observed_postcondition: StateFingerprint,
    /// Session-owned value used by compare-and-restore.
    pub ownership_fingerprint: StateFingerprint,
}

/// Readback receipt after a restore.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RestoreReceipt {
    /// Mutation restored.
    pub mutation_id: MutationId,
    /// Original fingerprint proven after restore.
    pub restored_fingerprint: StateFingerprint,
    /// Whether the backend proved the declared equality.
    pub verified: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::EqualityKind;
    use crate::error::ErrorCode;
    use crate::ids::{CapabilityId, MutationId, TargetId};

    #[test]
    fn typed_mutation_construction_preserves_operation_value() {
        let governor = GovernorId::new("performance").expect("valid governor");
        let kind = MutationKind::CpuGovernor {
            policy: CpuPolicyId::new(0),
            governor,
        };
        let desired = kind.typed_value();
        let mutation = PlannedMutation::new(
            MutationId::new(1),
            CapabilityId::new("cpu.policy.governor").expect("valid capability"),
            TargetId::new("cpu.policy.0").expect("valid target"),
            kind,
            desired,
            StateFingerprint::from_bytes([1; 32]),
            EqualityKind::ScalarExact,
            Vec::new(),
        )
        .expect("valid typed mutation");
        assert_eq!(mutation.mutation_id.get(), 1);
        assert_eq!(mutation.rollback.mode, RestoreMode::CompareAndRestore);
    }

    #[test]
    fn mutation_rejects_mismatched_desired_value() {
        let kind = MutationKind::CgroupCpuWeight {
            cgroup: CgroupId::new(1, 2, TargetId::new("group.service").expect("valid target")),
            weight: CpuWeight::new(100).expect("valid weight"),
        };
        let result = PlannedMutation::new(
            MutationId::new(1),
            CapabilityId::new("cgroup.cpu.weight").expect("valid capability"),
            TargetId::new("group.service").expect("valid target"),
            kind,
            TypedValue::CgroupCpuWeight(CpuWeight::new(200).expect("valid weight")),
            StateFingerprint::from_bytes([0; 32]),
            EqualityKind::ScalarExact,
            Vec::new(),
        );
        assert_eq!(result.unwrap_err().code, ErrorCode::PlanningError);
    }

    #[test]
    fn cpu_sets_are_canonicalized() {
        let set = CpuSet::new(vec![3, 1, 3, 2]).expect("non-empty set");
        assert_eq!(set.as_slice(), &[1, 2, 3]);
    }
}
