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

/// A process identity discovered from procfs.  The start-time component
/// prevents a recycled PID from being treated as the original workload.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProcessId {
    pid: u32,
    start_time_ticks: u64,
}

impl ProcessId {
    /// Construct a process identity from enumerated PID/start-time evidence.
    pub fn new(pid: u32, start_time_ticks: u64) -> Result<Self, SysboostError> {
        if pid == 0 || start_time_ticks == 0 {
            return Err(SysboostError::new(
                ErrorCode::InvalidInput,
                "process identity requires a positive PID and start time",
            ));
        }
        Ok(Self {
            pid,
            start_time_ticks,
        })
    }

    /// Return the numeric process ID.
    pub const fn pid(self) -> u32 {
        self.pid
    }

    /// Return the kernel start-time tick value.
    pub const fn start_time_ticks(self) -> u64 {
        self.start_time_ticks
    }

    /// Return the canonical opaque planner target for this process.
    pub fn target_id(self) -> TargetId {
        TargetId::new(format!("process.{}.{}", self.pid, self.start_time_ticks))
            .expect("validated process target is a valid identifier")
    }
}

/// A bounded Linux cgroup directory name.  It is a name, never a path.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CgroupName(String);

impl CgroupName {
    /// Construct one safe cgroup child name.
    pub fn new(value: impl Into<String>) -> Result<Self, SysboostError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 64
            || value == "."
            || value == ".."
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        {
            return Err(SysboostError::new(
                ErrorCode::InvalidInput,
                "cgroup name is not a bounded single component",
            ));
        }
        Ok(Self(value))
    }

    /// Return the validated child name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A Linux nice value.  Runtime control never requests real-time scheduling.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NiceValue(i8);

impl NiceValue {
    /// Lowest Linux nice value.
    pub const MIN: i8 = -20;
    /// Highest Linux nice value.
    pub const MAX: i8 = 19;

    /// Construct a bounded nice value.
    pub fn new(value: i8) -> Result<Self, SysboostError> {
        if !(Self::MIN..=Self::MAX).contains(&value) {
            return Err(SysboostError::new(
                ErrorCode::InvalidInput,
                "nice value is outside the Linux range",
            ));
        }
        Ok(Self(value))
    }

    /// Return the numeric nice value.
    pub const fn get(self) -> i8 {
        self.0
    }
}

/// The conservative I/O-priority classes accepted by workload control.
/// Realtime I/O priority is intentionally not part of the closed vocabulary.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialOrd, Ord, PartialEq)]
pub enum IoPriorityClass {
    /// Let the kernel select the default class.
    None,
    /// Best-effort I/O scheduling.
    BestEffort,
    /// Idle I/O scheduling.
    Idle,
}

/// A bounded Linux I/O priority.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IoPriority {
    class: IoPriorityClass,
    level: u8,
}

impl IoPriority {
    /// Construct a non-realtime I/O priority.
    pub fn new(class: IoPriorityClass, level: u8) -> Result<Self, SysboostError> {
        if level > 7 {
            return Err(SysboostError::new(
                ErrorCode::InvalidInput,
                "I/O priority level is outside the Linux range",
            ));
        }
        Ok(Self { class, level })
    }

    /// Return the I/O priority class.
    pub const fn class(self) -> IoPriorityClass {
        self.class
    }

    /// Return the I/O priority level.
    pub const fn level(self) -> u8 {
        self.level
    }
}

/// A cgroup v2 I/O weight in the Linux-defined range.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IoWeight(u16);

impl IoWeight {
    /// Lowest accepted I/O weight.
    pub const MIN: u16 = 1;
    /// Highest accepted I/O weight.
    pub const MAX: u16 = 10_000;

    /// Construct a bounded I/O weight.
    pub fn new(value: u16) -> Result<Self, SysboostError> {
        if !(Self::MIN..=Self::MAX).contains(&value) {
            return Err(SysboostError::new(
                ErrorCode::InvalidInput,
                "I/O weight is outside the accepted range",
            ));
        }
        Ok(Self(value))
    }

    /// Return the numeric I/O weight.
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// A Linux cgroup utilization-clamp value.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum UclampValue {
    /// A value in the kernel's 0..=1024 utilization scale.
    Value(u16),
    /// The cgroup `max` sentinel, valid for the maximum clamp.
    Max,
}

impl UclampValue {
    /// Construct a finite utilization clamp.
    pub fn new(value: u16) -> Result<Self, SysboostError> {
        if value > 1024 {
            return Err(SysboostError::new(
                ErrorCode::InvalidInput,
                "utilization clamp is outside the 0..=1024 range",
            ));
        }
        Ok(Self::Value(value))
    }

    /// Return the finite value, if this is not `max`.
    pub const fn get(self) -> Option<u16> {
        match self {
            Self::Value(value) => Some(value),
            Self::Max => None,
        }
    }
}

/// Explicit purpose of a managed cgroup.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CgroupGroupKind {
    /// Foreground workload group.
    Workload,
    /// Conservative background group.
    ConservativeBackground,
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

/// Closed CPU boost/turbo state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CpuBoostState {
    /// Allow the reviewed CPU boost/turbo interface to boost.
    Enabled,
    /// Disable the reviewed CPU boost/turbo interface.
    Disabled,
}

/// A platform performance-profile identifier returned by the kernel.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PlatformProfileId(String);

impl PlatformProfileId {
    /// Construct a bounded semantic platform-profile identifier.
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
                "platform profile identifier is not a bounded semantic value",
            ));
        }
        Ok(Self(value))
    }

    /// Return the validated platform-profile name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
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

    /// Return the number of logical CPUs in the set.
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Return whether the CPU set has no logical CPUs.
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Test membership in the canonical CPU set.
    pub fn contains(&self, cpu: u32) -> bool {
        self.0.binary_search(&cpu).is_ok()
    }

    /// Whether every CPU in this set is also present in `other`.
    pub fn is_subset_of(&self, other: &Self) -> bool {
        self.0.iter().all(|cpu| other.contains(*cpu))
    }

    /// Whether the two CPU sets share at least one logical CPU.
    pub fn intersects(&self, other: &Self) -> bool {
        self.0.iter().any(|cpu| other.contains(*cpu))
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
    /// Host-wide CPU boost/turbo state.
    CpuBoost {
        /// Desired boost state.
        state: CpuBoostState,
    },
    /// Host-wide ACPI/platform performance profile.
    PlatformProfile {
        /// Desired kernel-advertised profile.
        profile: PlatformProfileId,
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
    /// Existing cgroup I/O weight.
    CgroupIoWeight {
        /// Cgroup target.
        cgroup: CgroupId,
        /// Desired weight.
        weight: IoWeight,
    },
    /// Existing cgroup utilization-clamp minimum.
    CgroupUclampMin {
        /// Cgroup target.
        cgroup: CgroupId,
        /// Desired clamp.
        value: UclampValue,
    },
    /// Existing cgroup utilization-clamp maximum.
    CgroupUclampMax {
        /// Cgroup target.
        cgroup: CgroupId,
        /// Desired clamp.
        value: UclampValue,
    },
    /// Create and own a named foreground workload cgroup beneath a validated
    /// parent.  Restore removes it only after its owned workload is cleaned
    /// up and the group is proven empty.
    CgroupWorkload {
        /// Validated parent cgroup.
        parent: CgroupId,
        /// Single-component child name.
        name: CgroupName,
    },
    /// Create and own a named conservative background cgroup beneath a
    /// validated parent.
    CgroupBackground {
        /// Validated parent cgroup.
        parent: CgroupId,
        /// Single-component child name.
        name: CgroupName,
    },
    /// Change one explicitly identified process's cgroup placement.
    ProcessPlacement {
        /// Process identity including start time.
        process: ProcessId,
        /// Existing or transaction-owned destination cgroup.
        cgroup: CgroupId,
    },
    /// Change one explicitly identified process's nice value.
    ProcessNice {
        /// Process identity including start time.
        process: ProcessId,
        /// Desired nice value.
        nice: NiceValue,
    },
    /// Change one explicitly identified process's conservative I/O priority.
    ProcessIoPriority {
        /// Process identity including start time.
        process: ProcessId,
        /// Desired I/O priority.
        priority: IoPriority,
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
            Self::CpuBoost { .. } => "cpu.boost",
            Self::PlatformProfile { .. } => "platform.profile",
            Self::CgroupCpuWeight { .. } => "cgroup.cpu.weight",
            Self::CgroupCpuMax { .. } => "cgroup.cpu.max",
            Self::CgroupCpuset { .. } => "cgroup.cpuset.cpus",
            Self::CgroupIoWeight { .. } => "cgroup.io.weight",
            Self::CgroupUclampMin { .. } => "cgroup.uclamp.min",
            Self::CgroupUclampMax { .. } => "cgroup.uclamp.max",
            Self::CgroupWorkload { .. } => "cgroup.workload",
            Self::CgroupBackground { .. } => "cgroup.background",
            Self::ProcessPlacement { .. } => "scheduler.process.placement",
            Self::ProcessNice { .. } => "scheduler.nice",
            Self::ProcessIoPriority { .. } => "scheduler.ioprio",
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
            Self::CpuBoost { state } => TypedValue::CpuBoost(*state),
            Self::PlatformProfile { profile } => TypedValue::PlatformProfile(profile.clone()),
            Self::CgroupCpuWeight { weight, .. } => TypedValue::CgroupCpuWeight(*weight),
            Self::CgroupCpuMax { quota, period, .. } => TypedValue::CgroupCpuMax {
                quota: *quota,
                period: *period,
            },
            Self::CgroupCpuset { cpus, .. } => TypedValue::CgroupCpuset(cpus.clone()),
            Self::CgroupIoWeight { weight, .. } => TypedValue::CgroupIoWeight(*weight),
            Self::CgroupUclampMin { value, .. } | Self::CgroupUclampMax { value, .. } => {
                TypedValue::CgroupUclamp(*value)
            }
            Self::CgroupWorkload { name, .. } => TypedValue::CgroupLifecycle {
                kind: CgroupGroupKind::Workload,
                name: name.clone(),
                present: true,
            },
            Self::CgroupBackground { name, .. } => TypedValue::CgroupLifecycle {
                kind: CgroupGroupKind::ConservativeBackground,
                name: name.clone(),
                present: true,
            },
            Self::ProcessPlacement { cgroup, .. } => TypedValue::ProcessPlacement(cgroup.clone()),
            Self::ProcessNice { nice, .. } => TypedValue::Nice(*nice),
            Self::ProcessIoPriority { priority, .. } => TypedValue::IoPriority(*priority),
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
            min_khz: None,
            max_khz: None,
            ..
        } = self
        {
            return Err(SysboostError::new(
                ErrorCode::PlanningError,
                "CPU frequency mutation must select a minimum or maximum",
            )
            .with_stage(Stage::Plan));
        }
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
        if let Self::CgroupUclampMin {
            value: UclampValue::Max,
            ..
        } = self
        {
            return Err(SysboostError::new(
                ErrorCode::PlanningError,
                "cgroup uclamp.min cannot use the max sentinel",
            )
            .with_stage(Stage::Plan));
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
    /// CPU boost/turbo state.
    CpuBoost(CpuBoostState),
    /// Platform performance profile.
    PlatformProfile(PlatformProfileId),
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
    /// Cgroup I/O weight.
    CgroupIoWeight(IoWeight),
    /// Cgroup utilization clamp.
    CgroupUclamp(UclampValue),
    /// Managed cgroup lifecycle state.
    CgroupLifecycle {
        /// Purpose of the managed group.
        kind: CgroupGroupKind,
        /// Child name.
        name: CgroupName,
        /// Whether the group exists.
        present: bool,
    },
    /// Process cgroup placement.
    ProcessPlacement(CgroupId),
    /// Process nice value.
    Nice(NiceValue),
    /// Process I/O priority.
    IoPriority(IoPriority),
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
