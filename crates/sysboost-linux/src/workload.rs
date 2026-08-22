//! Reviewed scheduler and cgroup-v2 workload backend.
//!
//! The backend exposes only closed operations from `sysboost-core`.  Its
//! Linux adapter knows a fixed set of cgroup-v2 nodes and process syscalls;
//! there is no public path writer, raw cgroupfs API, shell command, service
//! stopper, or process-name classifier.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rustix::process::{getpriority_process, setpriority_process, Pid};
use sysboost_core::{
    fingerprint_for_value, ApplyReceipt, BackendId, BoundedBytes, CapabilityDescriptor,
    CapabilityEvidence, CapabilityId, CapabilityInventory, CapabilityState, CgroupGroupKind,
    CgroupId, CgroupName, ControlId, CpuPeriod, CpuQuota, CpuSet, CpuWeight, EqualityKind,
    ErrorCode, EvidenceSource, FeatureClass, IoPriority, IoPriorityClass, IoWeight, MutationKind,
    NiceValue, OperationCatalog, OperationContract, OperationDescriptor, OperationId, PlanValue,
    PlannedMutation, PrivilegeRequirement, ProcessId, RestoreReceipt, RiskClass, Snapshot, Stage,
    StateFingerprint, SysboostError, TargetId, TargetIdentity, TargetKind, Timestamp, TypedValue,
    UclampValue,
};
use sysboost_platform::{BackendDescriptor, BackendExecutionToken, Clock, MutationBackend};

/// Compiled-in workload backend identity.
pub const WORKLOAD_BACKEND_ID: &str = "linux.workload";

const ROOT_TARGET: &str = "cgroup.root";
const MAX_READ_BYTES: usize = 4096;

/// Closed cgroup-v2 node vocabulary exposed by the read-only inspection view.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum WorkloadNode {
    /// `cpu.weight`.
    CpuWeight,
    /// `cpu.max`.
    CpuMax,
    /// `cpuset.cpus`.
    CpusetCpus,
    /// `io.weight`.
    IoWeight,
    /// `cpu.uclamp.min`.
    UclampMin,
    /// `cpu.uclamp.max`.
    UclampMax,
}

impl WorkloadNode {
    fn controller(self) -> &'static str {
        match self {
            Self::CpuWeight | Self::CpuMax | Self::UclampMin | Self::UclampMax => "cpu",
            Self::CpusetCpus => "cpuset",
            Self::IoWeight => "io",
        }
    }

    fn filename(self) -> &'static str {
        match self {
            Self::CpuWeight => "cpu.weight",
            Self::CpuMax => "cpu.max",
            Self::CpusetCpus => "cpuset.cpus",
            Self::IoWeight => "io.weight",
            Self::UclampMin => "cpu.uclamp.min",
            Self::UclampMax => "cpu.uclamp.max",
        }
    }
}

/// One read-only target observed by the workload adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkloadTarget {
    /// Stable cgroup identity.
    pub identity: CgroupId,
    /// Adapter-owned relative location, never accepted from a wire request.
    pub relative_path: String,
}

/// Read-only inspection facade.  It deliberately has no write operation.
pub struct WorkloadInspection<'a> {
    io: &'a dyn WorkloadControlIo,
}

impl WorkloadInspection<'_> {
    /// Enumerate cgroups discovered by the backend.
    pub fn targets(&self) -> Result<Vec<WorkloadTarget>, SysboostError> {
        self.io.targets()
    }

    /// Read one closed cgroup-v2 node.
    pub fn read(&self, cgroup: &CgroupId, node: WorkloadNode) -> Result<Vec<u8>, SysboostError> {
        self.io.read_node(cgroup, node)
    }

    /// Read an explicitly identified process's current nice value.
    pub fn read_nice(&self, process: ProcessId) -> Result<NiceValue, SysboostError> {
        let observation = self.io.read_process(&MutationKind::ProcessNice {
            process,
            nice: NiceValue::new(0)?,
        })?;
        match observation.typed {
            TypedValue::Nice(value) => Ok(value),
            _ => Err(workload_error(
                ErrorCode::InvariantViolation,
                "workload inspection returned a non-nice process value",
            )),
        }
    }

    /// Read the current cgroup placement of an explicitly identified process.
    pub fn read_placement(&self, process: ProcessId) -> Result<CgroupId, SysboostError> {
        let observation = self.io.read_process(&MutationKind::ProcessPlacement {
            process,
            cgroup: CgroupId::new(
                0,
                0,
                TargetId::new(ROOT_TARGET).expect("static root target is valid"),
            ),
        })?;
        match observation.typed {
            TypedValue::ProcessPlacement(cgroup) => Ok(cgroup),
            _ => Err(workload_error(
                ErrorCode::InvariantViolation,
                "workload inspection returned a non-placement process value",
            )),
        }
    }

    /// Read the conservative I/O priority of an explicitly identified process.
    pub fn read_ioprio(&self, process: ProcessId) -> Result<IoPriority, SysboostError> {
        let observation = self.io.read_process(&MutationKind::ProcessIoPriority {
            process,
            priority: IoPriority::new(IoPriorityClass::None, 0)?,
        })?;
        match observation.typed {
            TypedValue::IoPriority(value) => Ok(value),
            _ => Err(workload_error(
                ErrorCode::InvariantViolation,
                "workload inspection returned a non-ioprio process value",
            )),
        }
    }
}

/// Scheduler/cgroup backend whose mutation methods require the transaction
/// execution token.  Use [`WorkloadBackend::io`] for read-only inspection.
pub struct WorkloadBackend {
    io: Box<dyn WorkloadControlIo>,
    descriptor: BackendDescriptor,
}

impl WorkloadBackend {
    /// Construct a backend over the host cgroup-v2 and procfs roots.
    pub fn production() -> Result<Self, SysboostError> {
        Ok(Self::new(Box::new(WorkloadSysfs::new(
            "/sys/fs/cgroup",
            "/proc",
        )?)))
    }

    /// Construct a deterministic backend over a fake hierarchy.
    pub fn from_fixture(fixture: CgroupFixture) -> Self {
        Self::new(Box::new(fixture))
    }

    fn new(io: Box<dyn WorkloadControlIo>) -> Self {
        Self {
            io,
            descriptor: workload_descriptor(),
        }
    }

    /// Borrow the read-only inspection facade.
    pub fn io(&self) -> WorkloadInspection<'_> {
        WorkloadInspection {
            io: self.io.as_ref(),
        }
    }

    fn expected_target(mutation: &PlannedMutation) -> Result<TargetId, SysboostError> {
        match &mutation.kind {
            MutationKind::CgroupCpuWeight { cgroup, .. }
            | MutationKind::CgroupCpuMax { cgroup, .. }
            | MutationKind::CgroupCpuset { cgroup, .. }
            | MutationKind::CgroupIoWeight { cgroup, .. }
            | MutationKind::CgroupUclampMin { cgroup, .. }
            | MutationKind::CgroupUclampMax { cgroup, .. } => Ok(cgroup.handle.clone()),
            MutationKind::CgroupWorkload { parent, .. }
            | MutationKind::CgroupBackground { parent, .. } => Ok(parent.handle.clone()),
            MutationKind::ProcessPlacement { process, .. }
            | MutationKind::ProcessNice { process, .. }
            | MutationKind::ProcessIoPriority { process, .. } => Ok(process.target_id()),
            _ => Err(unsupported("workload backend does not own this operation")),
        }
    }

    fn validate_observation(
        mutation: &PlannedMutation,
        observation: &WorkloadObservation,
        expected_target_identity: TargetIdentity,
    ) -> Result<(), SysboostError> {
        if observation.target_identity != expected_target_identity {
            return Err(target_error("workload target identity changed"));
        }
        if observation.fingerprint
            != fingerprint_for_value(&PlanValue::Typed(observation.typed.clone()))
        {
            return Err(target_error(
                "workload adapter returned an invalid fingerprint",
            ));
        }
        if observation.typed_shape_matches(mutation)
            && observation.fingerprint == mutation.precondition
        {
            Ok(())
        } else {
            Err(target_error(
                "workload target value or typed shape changed since planning",
            ))
        }
    }

    fn read(&self, mutation: &PlannedMutation) -> Result<WorkloadObservation, SysboostError> {
        match mutation.kind {
            MutationKind::ProcessNice { .. }
            | MutationKind::ProcessIoPriority { .. }
            | MutationKind::ProcessPlacement { .. } => self.io.read_process(&mutation.kind),
            _ => self.io.read_mutation(&mutation.kind),
        }
    }

    fn validate_canonical_target(
        &self,
        mutation: &PlannedMutation,
        expected_target_identity: TargetIdentity,
    ) -> Result<WorkloadObservation, SysboostError> {
        let expected = Self::expected_target(mutation)?;
        if mutation.target != expected {
            return Err(target_error(
                "workload target is not the canonical discovered target",
            ));
        }
        let observation = self.read(mutation)?;
        if observation.target_identity != expected_target_identity {
            return Err(target_error(
                "workload target identity does not match the plan",
            ));
        }
        self.io
            .validate_desired(&mutation.kind, &mutation.desired)?;
        Ok(observation)
    }

    fn snapshot_internal(
        &self,
        mutation: &PlannedMutation,
        now: Timestamp,
    ) -> Result<Snapshot, SysboostError> {
        let observation = self.read(mutation)?;
        Self::validate_observation(mutation, &observation, observation.target_identity)?;
        if observation.typed == mutation.desired {
            return Err(workload_error(
                ErrorCode::InvariantViolation,
                "workload mutation already equals its current value",
            ));
        }
        Ok(Snapshot {
            mutation_id: mutation.mutation_id,
            target: mutation.target.clone(),
            original_raw: observation.raw,
            original_typed: observation.typed,
            original_fingerprint: observation.fingerprint,
            equality: mutation.equality,
            target_identity: observation.target_identity,
            captured_at: now,
        })
    }

    fn apply_internal(
        &self,
        mutation: &PlannedMutation,
        snapshot: &Snapshot,
    ) -> Result<ApplyReceipt, SysboostError> {
        let current = self.read(mutation)?;
        if current.target_identity != snapshot.target_identity
            || current.fingerprint != mutation.precondition
        {
            return Err(target_error("workload target changed before apply"));
        }
        self.io
            .validate_desired(&mutation.kind, &mutation.desired)?;
        self.io.write_mutation(&mutation.kind, &mutation.desired)?;
        let after = self.read(mutation)?;
        let desired_fingerprint =
            fingerprint_for_value(&PlanValue::Typed(mutation.desired.clone()));
        if after.target_identity != snapshot.target_identity
            || after.fingerprint != desired_fingerprint
        {
            return Err(workload_error(
                ErrorCode::VerificationError,
                "workload apply readback did not prove the desired value",
            ));
        }
        Ok(ApplyReceipt {
            mutation_id: mutation.mutation_id,
            observed_precondition: current.fingerprint,
            observed_postcondition: after.fingerprint,
            ownership_fingerprint: after.fingerprint,
        })
    }

    fn verify_internal(
        &self,
        mutation: &PlannedMutation,
        expected_target_identity: TargetIdentity,
    ) -> Result<StateFingerprint, SysboostError> {
        let observation = self.read(mutation)?;
        if observation.target_identity != expected_target_identity {
            return Err(target_error(
                "workload target identity changed during verification",
            ));
        }
        Ok(observation.fingerprint)
    }

    fn restore_internal(
        &self,
        mutation: &PlannedMutation,
        snapshot: &Snapshot,
        expected_ownership: StateFingerprint,
    ) -> Result<RestoreReceipt, SysboostError> {
        let current = self.read(mutation)?;
        if current.target_identity != snapshot.target_identity {
            return Err(target_error(
                "workload target identity changed before restore",
            ));
        }
        if current.fingerprint != expected_ownership {
            return Err(workload_error(
                ErrorCode::RestoreConflict,
                "workload target changed outside this session; restore refused",
            ));
        }
        self.io
            .write_mutation(&mutation.kind, &snapshot.original_typed)?;
        let restored = self.read(mutation)?;
        if restored.target_identity != snapshot.target_identity
            || restored.fingerprint != snapshot.original_fingerprint
        {
            return Err(workload_error(
                ErrorCode::RestoreError,
                "workload restore readback did not prove the captured original",
            ));
        }
        Ok(RestoreReceipt {
            mutation_id: mutation.mutation_id,
            restored_fingerprint: restored.fingerprint,
            verified: true,
        })
    }
}

impl MutationBackend for WorkloadBackend {
    fn descriptor(&self) -> &BackendDescriptor {
        &self.descriptor
    }

    fn detect(&self, clock: &dyn Clock) -> Result<CapabilityInventory, SysboostError> {
        self.io.detect(clock)
    }

    fn snapshot(
        &self,
        _execution: &BackendExecutionToken,
        mutation: &PlannedMutation,
        now: Timestamp,
    ) -> Result<Snapshot, SysboostError> {
        self.snapshot_internal(mutation, now)
    }

    fn apply(
        &self,
        _execution: &BackendExecutionToken,
        mutation: &PlannedMutation,
        snapshot: &Snapshot,
    ) -> Result<ApplyReceipt, SysboostError> {
        self.apply_internal(mutation, snapshot)
    }

    fn verify(
        &self,
        _execution: &BackendExecutionToken,
        mutation: &PlannedMutation,
        _expected: StateFingerprint,
        expected_target_identity: TargetIdentity,
    ) -> Result<StateFingerprint, SysboostError> {
        self.verify_internal(mutation, expected_target_identity)
    }

    fn restore(
        &self,
        _execution: &BackendExecutionToken,
        mutation: &PlannedMutation,
        snapshot: &Snapshot,
        expected_ownership: StateFingerprint,
    ) -> Result<RestoreReceipt, SysboostError> {
        self.restore_internal(mutation, snapshot, expected_ownership)
    }

    fn validate_admission(
        &self,
        mutation: &PlannedMutation,
        expected_target_identity: TargetIdentity,
    ) -> Result<(), SysboostError> {
        let capability_owned = match mutation.kind {
            MutationKind::CgroupCpuWeight { .. } => {
                mutation.capability.as_str() == "cgroup.cpu.weight"
            }
            MutationKind::CgroupCpuMax { .. } => mutation.capability.as_str() == "cgroup.cpu.max",
            MutationKind::CgroupCpuset { .. } => {
                mutation.capability.as_str() == "cgroup.cpuset.cpus"
            }
            MutationKind::CgroupIoWeight { .. } => {
                mutation.capability.as_str() == "cgroup.io.weight"
            }
            MutationKind::CgroupUclampMin { .. } | MutationKind::CgroupUclampMax { .. } => {
                mutation.capability.as_str() == "cgroup.uclamp"
            }
            MutationKind::CgroupWorkload { .. } => {
                mutation.capability.as_str() == "cgroup.workload"
            }
            MutationKind::CgroupBackground { .. } => {
                mutation.capability.as_str() == "cgroup.background"
            }
            MutationKind::ProcessPlacement { .. } => {
                mutation.capability.as_str() == "scheduler.process.placement"
            }
            MutationKind::ProcessNice { .. } => mutation.capability.as_str() == "scheduler.nice",
            MutationKind::ProcessIoPriority { .. } => {
                mutation.capability.as_str() == "scheduler.ioprio"
            }
            _ => false,
        };
        if !self
            .descriptor
            .operations
            .contains(&mutation.kind.operation_id())
            || !capability_owned
            || !self.descriptor.capabilities.contains(&mutation.capability)
        {
            return Err(unsupported(
                "workload backend does not own operation/capability",
            ));
        }
        let observation = self.validate_canonical_target(mutation, expected_target_identity)?;
        if observation.fingerprint != mutation.precondition {
            return Err(target_error("workload target value changed since planning"));
        }
        Ok(())
    }

    fn validate_target(
        &self,
        mutation: &PlannedMutation,
        expected_target_identity: TargetIdentity,
    ) -> Result<(), SysboostError> {
        self.validate_canonical_target(mutation, expected_target_identity)
            .map(|_| ())
    }
}

/// Explicit child-process supervision hook.
///
/// The hook does not inspect names or scan arbitrary processes.  A trusted
/// composition root supplies a destination cgroup and a discovered
/// PID/start-time identity; the hook emits the same typed placement mutation
/// consumed by the planner and transaction engine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChildProcessSupervisor {
    destination: CgroupId,
}

impl ChildProcessSupervisor {
    /// Bind supervision to one validated destination cgroup.
    pub fn new(destination: CgroupId) -> Self {
        Self { destination }
    }

    /// Return the destination identity.
    pub fn destination(&self) -> &CgroupId {
        &self.destination
    }

    /// Convert an explicitly observed child into a typed placement operation.
    pub fn placement_for_child(&self, process: ProcessId) -> MutationKind {
        MutationKind::ProcessPlacement {
            process,
            cgroup: self.destination.clone(),
        }
    }

    /// Hook called by a process supervisor after a child has been observed.
    pub fn on_child_started(&self, process: ProcessId) -> MutationKind {
        self.placement_for_child(process)
    }

    /// Hook called when the child exits; no arbitrary process is stopped or
    /// killed, and no cleanup write is needed for a vanished process.
    pub fn on_child_exited(&self, _process: ProcessId) {}
}

#[derive(Clone, Debug)]
struct WorkloadObservation {
    raw: BoundedBytes,
    typed: TypedValue,
    fingerprint: StateFingerprint,
    target_identity: TargetIdentity,
}

impl WorkloadObservation {
    fn new(
        raw: Vec<u8>,
        typed: TypedValue,
        target_identity: TargetIdentity,
    ) -> Result<Self, SysboostError> {
        let raw = BoundedBytes::new(raw)?;
        let fingerprint = fingerprint_for_value(&PlanValue::Typed(typed.clone()));
        Ok(Self {
            raw,
            typed,
            fingerprint,
            target_identity,
        })
    }

    fn typed_shape_matches(&self, mutation: &PlannedMutation) -> bool {
        matches!(
            (&mutation.kind, &self.typed),
            (
                MutationKind::CgroupCpuWeight { .. },
                TypedValue::CgroupCpuWeight(_)
            ) | (
                MutationKind::CgroupCpuMax { .. },
                TypedValue::CgroupCpuMax { .. }
            ) | (
                MutationKind::CgroupCpuset { .. },
                TypedValue::CgroupCpuset(_)
            ) | (
                MutationKind::CgroupIoWeight { .. },
                TypedValue::CgroupIoWeight(_)
            ) | (
                MutationKind::CgroupUclampMin { .. },
                TypedValue::CgroupUclamp(_)
            ) | (
                MutationKind::CgroupUclampMax { .. },
                TypedValue::CgroupUclamp(_)
            ) | (
                MutationKind::CgroupWorkload { .. },
                TypedValue::CgroupLifecycle { .. }
            ) | (
                MutationKind::CgroupBackground { .. },
                TypedValue::CgroupLifecycle { .. }
            ) | (MutationKind::ProcessNice { .. }, TypedValue::Nice(_))
                | (
                    MutationKind::ProcessIoPriority { .. },
                    TypedValue::IoPriority(_)
                )
                | (
                    MutationKind::ProcessPlacement { .. },
                    TypedValue::ProcessPlacement(_)
                )
        )
    }
}

trait WorkloadControlIo: Send + Sync {
    fn detect(&self, clock: &dyn Clock) -> Result<CapabilityInventory, SysboostError>;
    fn targets(&self) -> Result<Vec<WorkloadTarget>, SysboostError>;
    fn read_node(&self, cgroup: &CgroupId, node: WorkloadNode) -> Result<Vec<u8>, SysboostError>;
    fn read_mutation(&self, mutation: &MutationKind) -> Result<WorkloadObservation, SysboostError>;
    fn read_process(&self, mutation: &MutationKind) -> Result<WorkloadObservation, SysboostError>;
    fn validate_desired(
        &self,
        mutation: &MutationKind,
        desired: &TypedValue,
    ) -> Result<(), SysboostError>;
    fn write_mutation(
        &self,
        mutation: &MutationKind,
        desired: &TypedValue,
    ) -> Result<(), SysboostError>;
}

fn workload_descriptor() -> BackendDescriptor {
    let backend = BackendId::new(WORKLOAD_BACKEND_ID).expect("static workload backend ID is valid");
    let operations = [
        "cgroup.cpu.weight",
        "cgroup.cpu.max",
        "cgroup.cpuset.cpus",
        "cgroup.io.weight",
        "cgroup.uclamp.min",
        "cgroup.uclamp.max",
        "cgroup.workload",
        "cgroup.background",
        "scheduler.process.placement",
        "scheduler.nice",
        "scheduler.ioprio",
    ]
    .into_iter()
    .map(|value| OperationId::new(value).expect("static workload operation is valid"))
    .collect();
    let capabilities = [
        "cgroup.cpu.weight",
        "cgroup.cpu.max",
        "cgroup.cpuset.cpus",
        "cgroup.io.weight",
        "cgroup.uclamp",
        "cgroup.workload",
        "cgroup.background",
        "scheduler.process.placement",
        "scheduler.nice",
        "scheduler.ioprio",
    ]
    .into_iter()
    .map(|value| CapabilityId::new(value).expect("static workload capability is valid"))
    .collect();
    BackendDescriptor {
        id: backend,
        version: "prompt8".to_owned(),
        capabilities,
        operations,
    }
}

/// Return the complete closed-operation catalog for scheduler and workload
/// control.  The catalog is pure planner metadata; it performs no host I/O.
pub fn workload_operation_catalog() -> OperationCatalog {
    let backend = BackendId::new(WORKLOAD_BACKEND_ID).expect("static workload backend is valid");
    let contract = |operation: &str,
                    capability: &str,
                    target_kind: TargetKind,
                    control: ControlId,
                    equality: EqualityKind,
                    risk: RiskClass,
                    classification: FeatureClass,
                    explicit_opt_in: bool| {
        OperationContract::complete(
            OperationId::new(operation).expect("static workload operation is valid"),
            CapabilityId::new(capability).expect("static workload capability is valid"),
            backend.clone(),
            target_kind,
            control,
            equality,
            risk,
            classification,
            explicit_opt_in,
        )
    };
    OperationCatalog::new(vec![
        contract(
            "cgroup.cpu.weight",
            "cgroup.cpu.weight",
            TargetKind::Cgroup,
            ControlId::CgroupCpuWeight,
            EqualityKind::ScalarExact,
            RiskClass::Medium,
            FeatureClass::RuntimeMutable,
            false,
        ),
        contract(
            "cgroup.cpu.max",
            "cgroup.cpu.max",
            TargetKind::Cgroup,
            ControlId::CgroupCpuMax,
            EqualityKind::ScalarExact,
            RiskClass::Medium,
            FeatureClass::RuntimeMutable,
            false,
        ),
        contract(
            "cgroup.cpuset.cpus",
            "cgroup.cpuset.cpus",
            TargetKind::Cgroup,
            ControlId::CgroupCpuset,
            EqualityKind::SetExact,
            RiskClass::Medium,
            FeatureClass::Conditional,
            true,
        ),
        contract(
            "cgroup.io.weight",
            "cgroup.io.weight",
            TargetKind::Cgroup,
            ControlId::CgroupIoWeight,
            EqualityKind::ScalarExact,
            RiskClass::Medium,
            FeatureClass::Conditional,
            true,
        ),
        contract(
            "cgroup.uclamp.min",
            "cgroup.uclamp",
            TargetKind::Cgroup,
            ControlId::CgroupUclampMin,
            EqualityKind::ScalarExact,
            RiskClass::Medium,
            FeatureClass::Conditional,
            true,
        ),
        contract(
            "cgroup.uclamp.max",
            "cgroup.uclamp",
            TargetKind::Cgroup,
            ControlId::CgroupUclampMax,
            EqualityKind::ScalarExact,
            RiskClass::Medium,
            FeatureClass::Conditional,
            true,
        ),
        contract(
            "cgroup.workload",
            "cgroup.workload",
            TargetKind::Cgroup,
            ControlId::CgroupWorkload,
            EqualityKind::ScalarExact,
            RiskClass::Medium,
            FeatureClass::Conditional,
            true,
        ),
        contract(
            "cgroup.background",
            "cgroup.background",
            TargetKind::Cgroup,
            ControlId::CgroupBackground,
            EqualityKind::ScalarExact,
            RiskClass::Medium,
            FeatureClass::Conditional,
            true,
        ),
        contract(
            "scheduler.process.placement",
            "scheduler.process.placement",
            TargetKind::Process,
            ControlId::ProcessPlacement,
            EqualityKind::ScalarExact,
            RiskClass::Medium,
            FeatureClass::Conditional,
            true,
        ),
        contract(
            "scheduler.nice",
            "scheduler.nice",
            TargetKind::Process,
            ControlId::ProcessNice,
            EqualityKind::ScalarExact,
            RiskClass::Low,
            FeatureClass::RuntimeMutable,
            true,
        ),
        contract(
            "scheduler.ioprio",
            "scheduler.ioprio",
            TargetKind::Process,
            ControlId::ProcessIoPriority,
            EqualityKind::ScalarExact,
            RiskClass::Low,
            FeatureClass::Experimental,
            true,
        ),
    ])
}

fn workload_capability(
    capability: &str,
    operation: &str,
    target_kind: TargetKind,
    equality: EqualityKind,
    state: CapabilityState,
    classification: FeatureClass,
    evidence: &str,
) -> CapabilityDescriptor {
    CapabilityDescriptor {
        id: CapabilityId::new(capability).expect("static workload capability is valid"),
        backend: BackendId::new(WORKLOAD_BACKEND_ID).expect("static workload backend is valid"),
        target_kind,
        state,
        operations: vec![OperationDescriptor {
            id: OperationId::new(operation).expect("static workload operation is valid"),
            privilege: PrivilegeRequirement::PrivilegedMutation,
            equality,
            classification,
        }],
        privilege: PrivilegeRequirement::PrivilegedMutation,
        equality,
        risk: RiskClass::Medium,
        classification,
        evidence: vec![CapabilityEvidence {
            source: EvidenceSource::CgroupV2,
            detail: evidence.to_owned(),
        }],
    }
}

fn uclamp_capability(state: CapabilityState, evidence: &str) -> CapabilityDescriptor {
    let equality = EqualityKind::ScalarExact;
    CapabilityDescriptor {
        id: CapabilityId::new("cgroup.uclamp").expect("static uclamp capability is valid"),
        backend: BackendId::new(WORKLOAD_BACKEND_ID).expect("static workload backend is valid"),
        target_kind: TargetKind::Cgroup,
        state,
        operations: ["cgroup.uclamp.min", "cgroup.uclamp.max"]
            .into_iter()
            .map(|operation| OperationDescriptor {
                id: OperationId::new(operation).expect("static uclamp operation is valid"),
                privilege: PrivilegeRequirement::PrivilegedMutation,
                equality,
                classification: FeatureClass::Conditional,
            })
            .collect(),
        privilege: PrivilegeRequirement::PrivilegedMutation,
        equality,
        risk: RiskClass::Medium,
        classification: FeatureClass::Conditional,
        evidence: vec![CapabilityEvidence {
            source: EvidenceSource::CgroupV2,
            detail: evidence.to_owned(),
        }],
    }
}

fn workload_error(code: ErrorCode, message: &str) -> SysboostError {
    SysboostError::new(code, message).with_stage(Stage::Apply)
}

fn unsupported(message: &str) -> SysboostError {
    workload_error(ErrorCode::Unsupported, message)
}

fn target_error(message: &str) -> SysboostError {
    workload_error(ErrorCode::TargetError, message)
}

fn permission_error(message: &str) -> SysboostError {
    workload_error(ErrorCode::AuthorizationError, message)
}

fn io_error(error: std::io::Error, message: &str) -> SysboostError {
    if error.kind() == std::io::ErrorKind::PermissionDenied {
        permission_error(message)
    } else if error.kind() == std::io::ErrorKind::NotFound {
        target_error(message)
    } else {
        workload_error(ErrorCode::ApplyError, message)
    }
}

const MAX_WORKLOAD_GROUPS: usize = 4096;

#[derive(Clone, Copy, Debug)]
enum WorkloadControlFile {
    Controllers,
    SubtreeControl,
    Procs,
}

impl WorkloadControlFile {
    fn filename(self) -> &'static str {
        match self {
            Self::Controllers => "cgroup.controllers",
            Self::SubtreeControl => "cgroup.subtree_control",
            Self::Procs => "cgroup.procs",
        }
    }
}

#[derive(Clone, Debug)]
struct SysfsGroup {
    identity: CgroupId,
    relative_path: String,
    path: PathBuf,
}

/// Production cgroup-v2/procfs adapter.
///
/// The adapter is intentionally private to [`WorkloadBackend`].  All paths
/// are derived from the fixed cgroup root and from names discovered in that
/// hierarchy; callers can supply only the typed target identity and closed
/// operation/value.  In particular, this type does not expose a path writer.
struct WorkloadSysfs {
    proc_root: PathBuf,
    groups: Mutex<BTreeMap<TargetId, SysfsGroup>>,
}

impl WorkloadSysfs {
    fn new(root: impl Into<PathBuf>, proc_root: impl Into<PathBuf>) -> Result<Self, SysboostError> {
        let root = root.into();
        let proc_root = proc_root.into();
        validate_directory(&root, "cgroup v2 root is unavailable")?;
        let adapter = Self {
            proc_root,
            groups: Mutex::new(BTreeMap::new()),
        };
        let mut groups = BTreeMap::new();
        let root_identity = cgroup_id_from_path(
            ROOT_TARGET,
            &root,
            "cgroup v2 root identity cannot be inspected",
        )?;
        collect_sysfs_groups(&root, "", &root_identity, &mut groups, 0)?;
        if groups.is_empty() {
            return Err(unsupported(
                "cgroup v2 hierarchy contains no discoverable targets",
            ));
        }
        *adapter.groups.lock().map_err(|_| {
            workload_error(ErrorCode::InvariantViolation, "cgroup target lock failed")
        })? = groups;
        Ok(adapter)
    }

    fn group_for(&self, cgroup: &CgroupId) -> Result<SysfsGroup, SysboostError> {
        if cgroup.mount_id == 0 || cgroup.inode == 0 {
            return Err(target_error(
                "production cgroup target lacks complete mount/inode identity",
            ));
        }
        let group = self
            .groups
            .lock()
            .map_err(|_| {
                workload_error(ErrorCode::InvariantViolation, "cgroup target lock failed")
            })?
            .get(&cgroup.handle)
            .cloned()
            .ok_or_else(|| target_error("cgroup target was not discovered by the backend"))?;
        if group.identity.mount_id != cgroup.mount_id
            || group.identity.inode != cgroup.inode
            || group.identity.handle != cgroup.handle
        {
            return Err(target_error(
                "cgroup target identity does not match discovery",
            ));
        }
        let identity = cgroup_id_from_path(
            group.identity.handle.as_str(),
            &group.path,
            "cgroup target disappeared or changed identity",
        )?;
        if identity.mount_id != group.identity.mount_id || identity.inode != group.identity.inode {
            return Err(target_error("cgroup target was replaced after discovery"));
        }
        Ok(group)
    }

    fn root_group(&self) -> Result<SysfsGroup, SysboostError> {
        let root = TargetId::new(ROOT_TARGET).expect("static root target is valid");
        let cgroup = self
            .groups
            .lock()
            .map_err(|_| {
                workload_error(ErrorCode::InvariantViolation, "cgroup target lock failed")
            })?
            .get(&root)
            .cloned()
            .ok_or_else(|| target_error("cgroup v2 root was not discovered"))?;
        self.group_for(&cgroup.identity)
    }

    fn insert_child(
        &self,
        parent: &SysfsGroup,
        name: &CgroupName,
    ) -> Result<CgroupId, SysboostError> {
        let path = parent.path.join(name.as_str());
        let target = child_target(&parent.identity.handle, name)?;
        let identity = cgroup_id_from_path(
            target.as_str(),
            &path,
            "managed cgroup identity cannot be inspected after creation",
        )?;
        let relative_path = if parent.relative_path.is_empty() {
            name.as_str().to_owned()
        } else {
            format!("{}/{}", parent.relative_path, name.as_str())
        };
        self.groups
            .lock()
            .map_err(|_| {
                workload_error(ErrorCode::InvariantViolation, "cgroup target lock failed")
            })?
            .insert(
                target,
                SysfsGroup {
                    identity: identity.clone(),
                    relative_path,
                    path,
                },
            );
        Ok(identity)
    }

    fn remove_child(&self, parent: &SysfsGroup, name: &CgroupName) -> Result<(), SysboostError> {
        let target = child_target(&parent.identity.handle, name)?;
        let child = self
            .groups
            .lock()
            .map_err(|_| {
                workload_error(ErrorCode::InvariantViolation, "cgroup target lock failed")
            })?
            .get(&target)
            .cloned()
            .ok_or_else(|| target_error("managed cgroup was not discovered by the backend"))?;
        let child = self.group_for(&child.identity)?;
        let procs = self.read_control(&child, WorkloadControlFile::Procs)?;
        if !procs.iter().all(u8::is_ascii_whitespace) {
            return Err(workload_error(
                ErrorCode::RestoreError,
                "managed cgroup still contains processes; cleanup refused",
            ));
        }
        let entries = fs::read_dir(&child.path)
            .map_err(|error| io_error(error, "managed cgroup children cannot be inspected"))?;
        if entries.filter_map(Result::ok).any(|entry| {
            entry
                .file_name()
                .to_str()
                .map(|name| !name.starts_with("cgroup."))
                .unwrap_or(true)
        }) {
            return Err(workload_error(
                ErrorCode::RestoreError,
                "managed cgroup has nested groups; cleanup refused",
            ));
        }
        fs::remove_dir(&child.path)
            .map_err(|error| io_error(error, "managed cgroup could not be removed safely"))?;
        self.groups
            .lock()
            .map_err(|_| {
                workload_error(ErrorCode::InvariantViolation, "cgroup target lock failed")
            })?
            .remove(&child.identity.handle);
        Ok(())
    }

    fn read_control(
        &self,
        group: &SysfsGroup,
        control: WorkloadControlFile,
    ) -> Result<Vec<u8>, SysboostError> {
        read_closed_file(
            &group.path.join(control.filename()),
            "cgroup control file cannot be read",
        )
    }

    fn read_node_value(
        &self,
        group: &SysfsGroup,
        node: WorkloadNode,
    ) -> Result<(TypedValue, Vec<u8>), SysboostError> {
        self.require_node(group, node)?;
        let raw = read_closed_file(
            &group.path.join(node.filename()),
            "cgroup controller file cannot be read",
        )?;
        Ok((parse_workload_node(node, &raw)?, raw))
    }

    fn require_controller(
        &self,
        group: &SysfsGroup,
        controller: &str,
    ) -> Result<(), SysboostError> {
        let controllers = text_tokens(&self.read_control(group, WorkloadControlFile::Controllers)?);
        let subtree = text_tokens(&self.read_control(group, WorkloadControlFile::SubtreeControl)?);
        if !controllers.contains(controller) && !subtree.contains(controller) {
            return Err(unsupported("cgroup controller is unavailable"));
        }
        let directory = fs::symlink_metadata(&group.path)
            .map_err(|error| io_error(error, "cgroup delegation cannot be inspected"))?;
        if directory.permissions().readonly() {
            return Err(permission_error(
                "cgroup controller is not delegated for writing",
            ));
        }
        Ok(())
    }

    fn require_node(&self, group: &SysfsGroup, node: WorkloadNode) -> Result<(), SysboostError> {
        let path = group.path.join(node.filename());
        let metadata = validate_regular_file(&path, "cgroup controller file is unavailable")?;
        self.require_controller(group, node.controller())?;
        if metadata.permissions().readonly() {
            return Err(permission_error(
                "cgroup controller is not writable by the backend",
            ));
        }
        Ok(())
    }

    fn read_proc_identity(&self, process: ProcessId) -> Result<ProcessId, SysboostError> {
        let raw = read_closed_file(
            &self.proc_root.join(process.pid().to_string()).join("stat"),
            "process identity cannot be inspected",
        )?;
        let text = std::str::from_utf8(&raw)
            .map_err(|_| target_error("process stat is not valid UTF-8"))?;
        let close = text
            .rfind(')')
            .ok_or_else(|| target_error("process stat is malformed"))?;
        let start_time = text
            .get(close + 1..)
            .and_then(|rest| rest.split_whitespace().nth(19))
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value != 0)
            .ok_or_else(|| target_error("process start time is unavailable"))?;
        let observed = ProcessId::new(process.pid(), start_time)?;
        if observed != process {
            return Err(target_error("process PID was recycled or identity changed"));
        }
        Ok(observed)
    }

    fn read_process_cgroup(&self, process: ProcessId) -> Result<SysfsGroup, SysboostError> {
        self.read_proc_identity(process)?;
        let raw = read_closed_file(
            &self
                .proc_root
                .join(process.pid().to_string())
                .join("cgroup"),
            "process cgroup placement cannot be inspected",
        )?;
        let text = std::str::from_utf8(&raw)
            .map_err(|_| target_error("process cgroup record is not valid UTF-8"))?;
        let relative_path = text
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .map(|path| path.trim_start_matches('/'))
            .ok_or_else(|| unsupported("process is not in a cgroup-v2 hierarchy"))?;
        let group = self
            .groups
            .lock()
            .map_err(|_| {
                workload_error(ErrorCode::InvariantViolation, "cgroup target lock failed")
            })?
            .values()
            .find(|group| group.relative_path == relative_path)
            .cloned()
            .ok_or_else(|| target_error("process cgroup target was not discovered"))?;
        let group = self.group_for(&group.identity)?;
        self.read_proc_identity(process)?;
        Ok(group)
    }

    fn write_node(
        &self,
        group: &SysfsGroup,
        node: WorkloadNode,
        value: &str,
    ) -> Result<(), SysboostError> {
        self.require_node(group, node)?;
        write_closed_file(
            &group.path.join(node.filename()),
            value,
            "cgroup controller write failed",
        )
    }

    fn write_process_placement(
        &self,
        process: ProcessId,
        destination: &SysfsGroup,
    ) -> Result<(), SysboostError> {
        let pid = Pid::from_raw(process.pid() as i32)
            .ok_or_else(|| target_error("process PID is invalid"))?;
        self.read_proc_identity(process)?;
        write_closed_file(
            &destination.path.join(WorkloadControlFile::Procs.filename()),
            &format!("{}\n", pid.as_raw_pid()),
            "process cgroup placement write failed",
        )?;
        self.read_proc_identity(process)?;
        Ok(())
    }

    fn current_process(&self) -> Result<ProcessId, SysboostError> {
        let pid = std::process::id();
        let raw = read_closed_file(
            &self.proc_root.join(pid.to_string()).join("stat"),
            "current process identity cannot be inspected",
        )?;
        let text = std::str::from_utf8(&raw)
            .map_err(|_| target_error("current process stat is not valid UTF-8"))?;
        let close = text
            .rfind(')')
            .ok_or_else(|| target_error("current process stat is malformed"))?;
        let start_time = text
            .get(close + 1..)
            .and_then(|rest| rest.split_whitespace().nth(19))
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value != 0)
            .ok_or_else(|| target_error("current process start time is unavailable"))?;
        ProcessId::new(pid, start_time)
    }
}

impl WorkloadControlIo for WorkloadSysfs {
    fn detect(&self, clock: &dyn Clock) -> Result<CapabilityInventory, SysboostError> {
        let observed_at = clock.now()?;
        let root = self.root_group()?;
        let groups = self
            .groups
            .lock()
            .map_err(|_| {
                workload_error(ErrorCode::InvariantViolation, "cgroup target lock failed")
            })?
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let probe = |node| {
            let mut state = CapabilityState::Unsupported;
            for group in &groups {
                match self.read_node_value(group, node) {
                    Ok(_) => return CapabilityState::Available,
                    Err(error) if error.code == ErrorCode::AuthorizationError => {
                        state = CapabilityState::Denied
                    }
                    Err(error) if error.code == ErrorCode::InvariantViolation => {
                        state = CapabilityState::Indeterminate
                    }
                    Err(error) if error.code == ErrorCode::TargetError => {
                        if state == CapabilityState::Unsupported {
                            state = CapabilityState::Unsupported;
                        }
                    }
                    Err(error) if error.code == ErrorCode::Unsupported => {
                        if state != CapabilityState::Denied {
                            state = CapabilityState::Unsupported;
                        }
                    }
                    Err(_) => state = CapabilityState::Indeterminate,
                }
            }
            state
        };
        let cpu_state = probe(WorkloadNode::CpuWeight);
        let cpu_max_state = probe(WorkloadNode::CpuMax);
        let cpuset_state = probe(WorkloadNode::CpusetCpus);
        let io_state = probe(WorkloadNode::IoWeight);
        let uclamp_min_state = probe(WorkloadNode::UclampMin);
        let uclamp_max_state = probe(WorkloadNode::UclampMax);
        let uclamp_state = combine_capability_states(uclamp_min_state, uclamp_max_state);
        let cpu_controller_state = match self.require_controller(&root, "cpu") {
            Ok(()) => CapabilityState::Available,
            Err(error) if error.code == ErrorCode::AuthorizationError => CapabilityState::Denied,
            Err(error) if error.code == ErrorCode::Unsupported => CapabilityState::Unsupported,
            Err(_) => CapabilityState::Indeterminate,
        };
        let process = self.current_process().ok();
        let nice_state = process
            .map(|process| {
                capability_state(self.read_process(&MutationKind::ProcessNice {
                    process,
                    nice: NiceValue::new(0).expect("zero nice is valid"),
                }))
            })
            .unwrap_or(CapabilityState::Unsupported);
        let placement_state = process
            .map(|process| {
                capability_state(self.read_process(&MutationKind::ProcessPlacement {
                    process,
                    cgroup: root.identity.clone(),
                }))
            })
            .unwrap_or(CapabilityState::Unsupported);
        Ok(CapabilityInventory {
            observed_at,
            capabilities: vec![
                workload_capability(
                    "cgroup.cpu.weight",
                    "cgroup.cpu.weight",
                    TargetKind::Cgroup,
                    EqualityKind::ScalarExact,
                    cpu_state,
                    FeatureClass::RuntimeMutable,
                    "cgroup v2 cpu.weight and fixed controller evidence",
                ),
                workload_capability(
                    "cgroup.cpu.max",
                    "cgroup.cpu.max",
                    TargetKind::Cgroup,
                    EqualityKind::ScalarExact,
                    cpu_max_state,
                    FeatureClass::RuntimeMutable,
                    "cgroup v2 cpu.max and fixed controller evidence",
                ),
                workload_capability(
                    "cgroup.cpuset.cpus",
                    "cgroup.cpuset.cpus",
                    TargetKind::Cgroup,
                    EqualityKind::SetExact,
                    cpuset_state,
                    FeatureClass::Conditional,
                    "cgroup v2 cpuset.cpus and fixed controller evidence",
                ),
                workload_capability(
                    "cgroup.io.weight",
                    "cgroup.io.weight",
                    TargetKind::Cgroup,
                    EqualityKind::ScalarExact,
                    io_state,
                    FeatureClass::Conditional,
                    "cgroup v2 io.weight default entry",
                ),
                uclamp_capability(uclamp_state, "cgroup v2 cpu.uclamp min/max entries"),
                workload_capability(
                    "cgroup.workload",
                    "cgroup.workload",
                    TargetKind::Cgroup,
                    EqualityKind::ScalarExact,
                    cpu_controller_state,
                    FeatureClass::Conditional,
                    "explicit managed workload child cgroup under a delegated parent",
                ),
                workload_capability(
                    "cgroup.background",
                    "cgroup.background",
                    TargetKind::Cgroup,
                    EqualityKind::ScalarExact,
                    cpu_controller_state,
                    FeatureClass::Conditional,
                    "explicit conservative background child cgroup under a delegated parent",
                ),
                process_capability(
                    "scheduler.process.placement",
                    "scheduler.process.placement",
                    placement_state,
                    FeatureClass::Conditional,
                    "procfs PID/start-time identity and cgroup-v2 placement",
                ),
                process_capability(
                    "scheduler.nice",
                    "scheduler.nice",
                    nice_state,
                    FeatureClass::RuntimeMutable,
                    "procfs PID/start-time identity and getpriority",
                ),
                process_capability(
                    "scheduler.ioprio",
                    "scheduler.ioprio",
                    CapabilityState::Unsupported,
                    FeatureClass::Experimental,
                    "safe ioprio syscall adapter is not enabled; operation degrades closed",
                ),
            ],
        })
    }

    fn targets(&self) -> Result<Vec<WorkloadTarget>, SysboostError> {
        let mut targets = self
            .groups
            .lock()
            .map_err(|_| {
                workload_error(ErrorCode::InvariantViolation, "cgroup target lock failed")
            })?
            .values()
            .map(|group| WorkloadTarget {
                identity: group.identity.clone(),
                relative_path: group.relative_path.clone(),
            })
            .collect::<Vec<_>>();
        targets.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        Ok(targets)
    }

    fn read_node(&self, cgroup: &CgroupId, node: WorkloadNode) -> Result<Vec<u8>, SysboostError> {
        let group = self.group_for(cgroup)?;
        self.require_node(&group, node)?;
        read_closed_file(
            &group.path.join(node.filename()),
            "cgroup controller file cannot be read",
        )
    }

    fn read_mutation(&self, mutation: &MutationKind) -> Result<WorkloadObservation, SysboostError> {
        match mutation {
            MutationKind::CgroupCpuWeight { cgroup, .. } => {
                self.read_cgroup_node(cgroup, WorkloadNode::CpuWeight)
            }
            MutationKind::CgroupCpuMax { cgroup, .. } => {
                self.read_cgroup_node(cgroup, WorkloadNode::CpuMax)
            }
            MutationKind::CgroupCpuset { cgroup, .. } => {
                self.read_cgroup_node(cgroup, WorkloadNode::CpusetCpus)
            }
            MutationKind::CgroupIoWeight { cgroup, .. } => {
                self.read_cgroup_node(cgroup, WorkloadNode::IoWeight)
            }
            MutationKind::CgroupUclampMin { cgroup, .. } => {
                self.read_cgroup_node(cgroup, WorkloadNode::UclampMin)
            }
            MutationKind::CgroupUclampMax { cgroup, .. } => {
                self.read_cgroup_node(cgroup, WorkloadNode::UclampMax)
            }
            MutationKind::CgroupWorkload { parent, name } => {
                self.read_lifecycle(parent, name, CgroupGroupKind::Workload)
            }
            MutationKind::CgroupBackground { parent, name } => {
                self.read_lifecycle(parent, name, CgroupGroupKind::ConservativeBackground)
            }
            _ => Err(unsupported("production mutation is not a cgroup operation")),
        }
    }

    fn read_process(&self, mutation: &MutationKind) -> Result<WorkloadObservation, SysboostError> {
        let process = match mutation {
            MutationKind::ProcessNice { process, .. }
            | MutationKind::ProcessIoPriority { process, .. }
            | MutationKind::ProcessPlacement { process, .. } => *process,
            _ => {
                return Err(unsupported(
                    "production mutation is not a process operation",
                ))
            }
        };
        self.read_proc_identity(process)?;
        let typed = match mutation {
            MutationKind::ProcessNice { .. } => {
                let pid = Pid::from_raw(process.pid() as i32)
                    .ok_or_else(|| target_error("process PID is invalid"))?;
                let value = getpriority_process(Some(pid))
                    .map_err(|_| target_error("process nice value cannot be read"))?;
                TypedValue::Nice(NiceValue::new(value as i8)?)
            }
            MutationKind::ProcessIoPriority { .. } => {
                return Err(unsupported("production ioprio adapter is unavailable"));
            }
            MutationKind::ProcessPlacement { .. } => {
                TypedValue::ProcessPlacement(self.read_process_cgroup(process)?.identity)
            }
            _ => unreachable!(),
        };
        self.read_proc_identity(process)?;
        WorkloadObservation::new(
            render_typed_process(&typed),
            typed,
            process_identity(process),
        )
    }

    fn validate_desired(
        &self,
        mutation: &MutationKind,
        desired: &TypedValue,
    ) -> Result<(), SysboostError> {
        if mutation.typed_value() != *desired {
            return Err(workload_error(
                ErrorCode::PlanningError,
                "workload kind and desired value disagree",
            ));
        }
        match mutation {
            MutationKind::CgroupCpuWeight { cgroup, .. } => {
                self.require_node(&self.group_for(cgroup)?, WorkloadNode::CpuWeight)
            }
            MutationKind::CgroupCpuMax { cgroup, .. } => {
                self.require_node(&self.group_for(cgroup)?, WorkloadNode::CpuMax)
            }
            MutationKind::CgroupCpuset { cgroup, .. } => {
                self.require_node(&self.group_for(cgroup)?, WorkloadNode::CpusetCpus)
            }
            MutationKind::CgroupIoWeight { cgroup, .. } => {
                self.require_node(&self.group_for(cgroup)?, WorkloadNode::IoWeight)
            }
            MutationKind::CgroupUclampMin { cgroup, value } => {
                let group = self.group_for(cgroup)?;
                if matches!(value, UclampValue::Max) {
                    return Err(workload_error(
                        ErrorCode::InvalidInput,
                        "uclamp.min cannot use the max sentinel",
                    ));
                }
                self.require_node(&group, WorkloadNode::UclampMin)?;
                self.require_node(&group, WorkloadNode::UclampMax)?;
                let (_, raw_max) = self.read_node_value(&group, WorkloadNode::UclampMax)?;
                validate_uclamp_pair(*value, parse_uclamp(&raw_max)?)
            }
            MutationKind::CgroupUclampMax { cgroup, value } => {
                let group = self.group_for(cgroup)?;
                self.require_node(&group, WorkloadNode::UclampMin)?;
                self.require_node(&group, WorkloadNode::UclampMax)?;
                let (_, raw_min) = self.read_node_value(&group, WorkloadNode::UclampMin)?;
                validate_uclamp_pair(parse_uclamp(&raw_min)?, *value)
            }
            MutationKind::CgroupWorkload { parent, .. }
            | MutationKind::CgroupBackground { parent, .. } => {
                self.require_controller(&self.group_for(parent)?, "cpu")
            }
            MutationKind::ProcessPlacement { process, cgroup } => {
                let _ = self.group_for(cgroup)?;
                self.read_proc_identity(*process).map(|_| ())
            }
            MutationKind::ProcessNice { process, .. } => {
                self.read_proc_identity(*process).map(|_| ())
            }
            MutationKind::ProcessIoPriority { .. } => {
                Err(unsupported("production ioprio adapter is unavailable"))
            }
            _ => Err(unsupported(
                "production backend does not own this workload operation",
            )),
        }
    }

    fn write_mutation(
        &self,
        mutation: &MutationKind,
        desired: &TypedValue,
    ) -> Result<(), SysboostError> {
        match (mutation, desired) {
            (MutationKind::CgroupCpuWeight { cgroup, .. }, TypedValue::CgroupCpuWeight(value)) => {
                self.write_node(
                    &self.group_for(cgroup)?,
                    WorkloadNode::CpuWeight,
                    &value.get().to_string(),
                )
            }
            (
                MutationKind::CgroupCpuMax { cgroup, .. },
                TypedValue::CgroupCpuMax { quota, period },
            ) => self.write_node(
                &self.group_for(cgroup)?,
                WorkloadNode::CpuMax,
                &format!("{} {}", render_quota(*quota), period.get()),
            ),
            (MutationKind::CgroupCpuset { cgroup, .. }, TypedValue::CgroupCpuset(value)) => self
                .write_node(
                    &self.group_for(cgroup)?,
                    WorkloadNode::CpusetCpus,
                    &render_cpuset(value),
                ),
            (MutationKind::CgroupIoWeight { cgroup, .. }, TypedValue::CgroupIoWeight(value)) => {
                self.write_node(
                    &self.group_for(cgroup)?,
                    WorkloadNode::IoWeight,
                    &format!("default {}", value.get()),
                )
            }
            (MutationKind::CgroupUclampMin { cgroup, .. }, TypedValue::CgroupUclamp(value)) => self
                .write_node(
                    &self.group_for(cgroup)?,
                    WorkloadNode::UclampMin,
                    &render_uclamp(*value),
                ),
            (MutationKind::CgroupUclampMax { cgroup, .. }, TypedValue::CgroupUclamp(value)) => self
                .write_node(
                    &self.group_for(cgroup)?,
                    WorkloadNode::UclampMax,
                    &render_uclamp(*value),
                ),
            (
                MutationKind::CgroupWorkload { parent, name },
                TypedValue::CgroupLifecycle { present: true, .. },
            )
            | (
                MutationKind::CgroupBackground { parent, name },
                TypedValue::CgroupLifecycle { present: true, .. },
            ) => {
                let parent = self.group_for(parent)?;
                let path = parent.path.join(name.as_str());
                if fs::symlink_metadata(&path).is_ok() {
                    return Err(workload_error(
                        ErrorCode::ApplyError,
                        "managed cgroup already exists",
                    ));
                }
                fs::create_dir(&path)
                    .map_err(|error| io_error(error, "managed cgroup could not be created"))?;
                if let Err(error) = self.insert_child(&parent, name) {
                    if let Err(cleanup_error) = fs::remove_dir(&path) {
                        return Err(io_error(
                            cleanup_error,
                            "managed cgroup setup cleanup failed",
                        ));
                    }
                    return Err(error);
                }
                Ok(())
            }
            (
                MutationKind::CgroupWorkload { parent, name },
                TypedValue::CgroupLifecycle { present: false, .. },
            )
            | (
                MutationKind::CgroupBackground { parent, name },
                TypedValue::CgroupLifecycle { present: false, .. },
            ) => self.remove_child(&self.group_for(parent)?, name),
            (MutationKind::ProcessNice { process, .. }, TypedValue::Nice(value)) => {
                let pid = Pid::from_raw(process.pid() as i32)
                    .ok_or_else(|| target_error("process PID is invalid"))?;
                self.read_proc_identity(*process)?;
                setpriority_process(Some(pid), i32::from(value.get()))
                    .map_err(|_| permission_error("process nice write was denied"))?;
                self.read_proc_identity(*process).map(|_| ())
            }
            (
                MutationKind::ProcessPlacement { process, cgroup },
                TypedValue::ProcessPlacement(_),
            ) => self.write_process_placement(*process, &self.group_for(cgroup)?),
            (MutationKind::ProcessIoPriority { .. }, TypedValue::IoPriority(_)) => {
                Err(unsupported("production ioprio adapter is unavailable"))
            }
            _ => Err(workload_error(
                ErrorCode::InvariantViolation,
                "production workload write shape is not closed",
            )),
        }
    }
}

impl WorkloadSysfs {
    fn read_cgroup_node(
        &self,
        cgroup: &CgroupId,
        node: WorkloadNode,
    ) -> Result<WorkloadObservation, SysboostError> {
        let group = self.group_for(cgroup)?;
        let (typed, raw) = self.read_node_value(&group, node)?;
        WorkloadObservation::new(raw, typed, cgroup_identity(&group.identity))
    }

    fn read_lifecycle(
        &self,
        parent: &CgroupId,
        name: &CgroupName,
        kind: CgroupGroupKind,
    ) -> Result<WorkloadObservation, SysboostError> {
        let parent = self.group_for(parent)?;
        self.require_controller(&parent, "cpu")?;
        let target = parent.path.join(name.as_str());
        let present = match fs::symlink_metadata(&target) {
            Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
                true
            }
            Ok(_) => return Err(target_error("managed cgroup path is not a directory")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => {
                return Err(io_error(
                    error,
                    "managed cgroup presence cannot be inspected",
                ))
            }
        };
        let typed = TypedValue::CgroupLifecycle {
            kind,
            name: name.clone(),
            present,
        };
        WorkloadObservation::new(
            if present {
                b"present\n".to_vec()
            } else {
                b"absent\n".to_vec()
            },
            typed,
            cgroup_identity(&parent.identity),
        )
    }
}

fn validate_directory(path: &Path, message: &str) -> Result<(), SysboostError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| io_error(error, message))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(target_error(message));
    }
    Ok(())
}

fn validate_regular_file(path: &Path, message: &str) -> Result<std::fs::Metadata, SysboostError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| io_error(error, message))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(target_error(message));
    }
    Ok(metadata)
}

fn cgroup_id_from_path(
    handle: &str,
    path: &Path,
    message: &str,
) -> Result<CgroupId, SysboostError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| io_error(error, message))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(target_error(message));
    }
    Ok(CgroupId::new(
        metadata.dev(),
        metadata.ino(),
        TargetId::new(handle).map_err(|_| target_error("cgroup target handle is invalid"))?,
    ))
}

fn collect_sysfs_groups(
    path: &Path,
    relative_path: &str,
    identity: &CgroupId,
    groups: &mut BTreeMap<TargetId, SysfsGroup>,
    depth: usize,
) -> Result<(), SysboostError> {
    if depth > MAX_WORKLOAD_GROUPS || groups.len() >= MAX_WORKLOAD_GROUPS {
        return Err(target_error(
            "cgroup hierarchy exceeds the bounded discovery limit",
        ));
    }
    groups.insert(
        identity.handle.clone(),
        SysfsGroup {
            identity: identity.clone(),
            relative_path: relative_path.to_owned(),
            path: path.to_owned(),
        },
    );
    let entries = fs::read_dir(path)
        .map_err(|error| io_error(error, "cgroup hierarchy cannot be enumerated"))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| io_error(error, "cgroup hierarchy entry cannot be read"))?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| io_error(error, "cgroup hierarchy entry identity cannot be read"))?;
        if metadata.file_type().is_symlink() {
            return Err(target_error(
                "cgroup hierarchy contains a symlinked directory",
            ));
        }
        if !metadata.file_type().is_dir() {
            continue;
        }
        let Some(name) = entry
            .file_name()
            .to_str()
            .and_then(|value| CgroupName::new(value).ok())
        else {
            continue;
        };
        let target = child_target(&identity.handle, &name)?;
        let child = CgroupId::new(metadata.dev(), metadata.ino(), target);
        let child_relative = if relative_path.is_empty() {
            name.as_str().to_owned()
        } else {
            format!("{}/{}", relative_path, name.as_str())
        };
        collect_sysfs_groups(&entry.path(), &child_relative, &child, groups, depth + 1)?;
    }
    Ok(())
}

fn read_closed_file(path: &Path, message: &str) -> Result<Vec<u8>, SysboostError> {
    validate_regular_file(path, message)?;
    let mut options = OpenOptions::new();
    options.read(true);
    options.custom_flags(open_cloexec_flags() | open_nofollow_flags());
    let mut file = options
        .open(path)
        .map_err(|error| io_error(error, message))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| io_error(error, message))?;
    if bytes.len() > MAX_READ_BYTES {
        return Err(target_error("workload control file is oversized"));
    }
    Ok(bytes)
}

fn write_closed_file(path: &Path, value: &str, message: &str) -> Result<(), SysboostError> {
    if value.is_empty() || value.len() > 128 || value.contains('\0') {
        return Err(workload_error(
            ErrorCode::InvalidInput,
            "generated workload value is invalid",
        ));
    }
    let metadata = validate_regular_file(path, message)?;
    if metadata.permissions().readonly() {
        return Err(permission_error(message));
    }
    let mut options = OpenOptions::new();
    options.write(true);
    options.custom_flags(open_cloexec_flags() | open_nofollow_flags());
    let mut file = options
        .open(path)
        .map_err(|error| io_error(error, message))?;
    file.write_all(value.as_bytes())
        .and_then(|_| file.flush())
        .map_err(|error| io_error(error, message))
}

#[cfg(target_os = "linux")]
const fn open_nofollow_flags() -> i32 {
    0x20000
}

#[cfg(not(target_os = "linux"))]
const fn open_nofollow_flags() -> i32 {
    0
}

#[cfg(target_os = "linux")]
const fn open_cloexec_flags() -> i32 {
    0x80000
}

#[cfg(not(target_os = "linux"))]
const fn open_cloexec_flags() -> i32 {
    0
}

fn text_tokens(raw: &[u8]) -> BTreeSet<String> {
    std::str::from_utf8(raw)
        .map(|text| text.split_whitespace().map(str::to_owned).collect())
        .unwrap_or_default()
}

fn parse_workload_node(node: WorkloadNode, raw: &[u8]) -> Result<TypedValue, SysboostError> {
    let text = std::str::from_utf8(raw)
        .map_err(|_| target_error("cgroup controller value is not valid UTF-8"))?;
    match node {
        WorkloadNode::CpuWeight => Ok(TypedValue::CgroupCpuWeight(CpuWeight::new(
            text.trim()
                .parse()
                .map_err(|_| target_error("cpu.weight is malformed"))?,
        )?)),
        WorkloadNode::CpuMax => {
            let mut parts = text.split_whitespace();
            let quota = match parts.next() {
                Some("max") => CpuQuota::Max,
                Some(value) => CpuQuota::micros(
                    value
                        .parse()
                        .map_err(|_| target_error("cpu.max quota is malformed"))?,
                )?,
                None => return Err(target_error("cpu.max is malformed")),
            };
            let period = CpuPeriod::new(
                parts
                    .next()
                    .ok_or_else(|| target_error("cpu.max period is missing"))?
                    .parse()
                    .map_err(|_| target_error("cpu.max period is malformed"))?,
            )?;
            if parts.next().is_some() {
                return Err(target_error("cpu.max has unexpected fields"));
            }
            Ok(TypedValue::CgroupCpuMax { quota, period })
        }
        WorkloadNode::CpusetCpus => Ok(TypedValue::CgroupCpuset(parse_cpuset(text)?)),
        WorkloadNode::IoWeight => {
            let mut value = None;
            for line in text.lines() {
                let mut parts = line.split_whitespace();
                match (parts.next(), parts.next(), parts.next()) {
                    (Some("default"), Some(weight), None) => {
                        if value.is_some() {
                            return Err(target_error("io.weight has duplicate default entries"));
                        }
                        value = Some(IoWeight::new(
                            weight
                                .parse()
                                .map_err(|_| target_error("io.weight is malformed"))?,
                        )?);
                    }
                    (Some(_), Some(_), _) => {
                        return Err(unsupported(
                            "per-device io.weight entries are outside the closed operation",
                        ));
                    }
                    _ => return Err(target_error("io.weight is malformed")),
                }
            }
            Ok(TypedValue::CgroupIoWeight(value.ok_or_else(|| {
                target_error("io.weight default entry is missing")
            })?))
        }
        WorkloadNode::UclampMin | WorkloadNode::UclampMax => {
            Ok(TypedValue::CgroupUclamp(parse_uclamp(raw)?))
        }
    }
}

fn parse_uclamp(raw: &[u8]) -> Result<UclampValue, SysboostError> {
    let text =
        std::str::from_utf8(raw).map_err(|_| target_error("uclamp value is not valid UTF-8"))?;
    match text.trim() {
        "max" => Ok(UclampValue::Max),
        value => Ok(UclampValue::new(
            value
                .parse()
                .map_err(|_| target_error("uclamp value is malformed"))?,
        )?),
    }
}

fn parse_cpuset(text: &str) -> Result<CpuSet, SysboostError> {
    let mut cpus = Vec::new();
    for part in text.trim().split(',') {
        if part.is_empty() {
            return Err(target_error("cpuset.cpus is malformed"));
        }
        if let Some((start, end)) = part.split_once('-') {
            let start: u32 = start
                .parse()
                .map_err(|_| target_error("cpuset range is malformed"))?;
            let end: u32 = end
                .parse()
                .map_err(|_| target_error("cpuset range is malformed"))?;
            if start > end || end.saturating_sub(start) > 4096 {
                return Err(target_error("cpuset range is outside the bounded contract"));
            }
            cpus.extend(start..=end);
        } else {
            cpus.push(
                part.parse()
                    .map_err(|_| target_error("cpuset CPU is malformed"))?,
            );
        }
        if cpus.len() > 4096 {
            return Err(target_error("cpuset value is oversized"));
        }
    }
    CpuSet::new(cpus).map_err(|_| target_error("cpuset.cpus is empty"))
}

fn capability_state(result: Result<WorkloadObservation, SysboostError>) -> CapabilityState {
    match result {
        Ok(_) => CapabilityState::Available,
        Err(error) if error.code == ErrorCode::AuthorizationError => CapabilityState::Denied,
        Err(error) if error.code == ErrorCode::Unsupported => CapabilityState::Unsupported,
        Err(_) => CapabilityState::Indeterminate,
    }
}

fn combine_capability_states(left: CapabilityState, right: CapabilityState) -> CapabilityState {
    match (left, right) {
        (CapabilityState::Available, CapabilityState::Available) => CapabilityState::Available,
        (CapabilityState::Denied, _) | (_, CapabilityState::Denied) => CapabilityState::Denied,
        (CapabilityState::Unsupported, _) | (_, CapabilityState::Unsupported) => {
            CapabilityState::Unsupported
        }
        _ => CapabilityState::Indeterminate,
    }
}

fn process_capability(
    capability: &str,
    operation: &str,
    state: CapabilityState,
    classification: FeatureClass,
    evidence: &str,
) -> CapabilityDescriptor {
    let mut descriptor = workload_capability(
        capability,
        operation,
        TargetKind::Process,
        EqualityKind::ScalarExact,
        state,
        classification,
        evidence,
    );
    descriptor.risk = match operation {
        "scheduler.nice" | "scheduler.ioprio" => RiskClass::Low,
        _ => RiskClass::Medium,
    };
    if let Some(item) = descriptor.evidence.first_mut() {
        item.source = EvidenceSource::Procfs;
    }
    descriptor
}

/// Deterministic cgroup-v2 hierarchy used by backend and transaction tests.
/// It has the same closed node vocabulary as the production adapter and does
/// not expose a generic byte writer.
#[derive(Clone, Debug)]
pub struct CgroupFixture {
    state: Arc<Mutex<CgroupFixtureState>>,
}

#[derive(Clone, Debug)]
struct CgroupFixtureState {
    groups: BTreeMap<TargetId, FixtureGroup>,
    processes: BTreeMap<ProcessId, FixtureProcess>,
}

#[derive(Clone, Debug)]
struct FixtureGroup {
    identity: CgroupId,
    relative_path: String,
    controllers: BTreeSet<String>,
    delegated: BTreeSet<String>,
    cpu_weight: CpuWeight,
    cpu_quota: CpuQuota,
    cpu_period: CpuPeriod,
    cpuset: CpuSet,
    io_weight: IoWeight,
    uclamp_min: UclampValue,
    uclamp_max: UclampValue,
    processes: BTreeSet<ProcessId>,
}

#[derive(Clone, Debug)]
struct FixtureProcess {
    identity: ProcessId,
    cgroup: TargetId,
    nice: NiceValue,
    ioprio: IoPriority,
}

impl CgroupFixture {
    /// Construct a hierarchy with a delegated root cgroup.
    pub fn new() -> Self {
        let fixture = Self {
            state: Arc::new(Mutex::new(CgroupFixtureState {
                groups: BTreeMap::new(),
                processes: BTreeMap::new(),
            })),
        };
        let root = CgroupId::new(
            1,
            1,
            TargetId::new(ROOT_TARGET).expect("static root cgroup target is valid"),
        );
        fixture.add_group(root, "".to_owned());
        fixture
    }

    /// Return the synthetic root identity.
    pub fn root_id(&self) -> CgroupId {
        CgroupId::new(
            1,
            1,
            TargetId::new(ROOT_TARGET).expect("static root cgroup target is valid"),
        )
    }

    /// Add or replace a cgroup fixture entry.
    pub fn add_group(&self, identity: CgroupId, relative_path: impl Into<String>) {
        let mut state = self.state.lock().expect("cgroup fixture lock is healthy");
        state.groups.insert(
            identity.handle.clone(),
            FixtureGroup {
                identity,
                relative_path: relative_path.into(),
                controllers: ["cpu", "cpuset", "io"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                delegated: ["cpu", "cpuset", "io"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                cpu_weight: CpuWeight::new(100).expect("fixture weight is valid"),
                cpu_quota: CpuQuota::Max,
                cpu_period: CpuPeriod::new(100_000).expect("fixture period is valid"),
                cpuset: CpuSet::new(vec![0, 1]).expect("fixture CPU set is valid"),
                io_weight: IoWeight::new(100).expect("fixture I/O weight is valid"),
                uclamp_min: UclampValue::Value(0),
                uclamp_max: UclampValue::Max,
                processes: BTreeSet::new(),
            },
        );
    }

    /// Add a nested child using the backend's deterministic child identity.
    pub fn add_child_group(
        &self,
        parent: &CgroupId,
        name: CgroupName,
        identity: CgroupId,
    ) -> Result<CgroupId, SysboostError> {
        let mut state = self.state.lock().expect("cgroup fixture lock is healthy");
        let parent_group = resolve_group(&state, parent)?.clone();
        let path = if parent_group.relative_path.is_empty() {
            name.as_str().to_owned()
        } else {
            format!("{}/{}", parent_group.relative_path, name.as_str())
        };
        let target = child_target(&parent.handle, &name)?;
        if target != identity.handle {
            return Err(target_error(
                "fixture child identity handle is not canonical",
            ));
        }
        state.groups.insert(
            target.clone(),
            FixtureGroup {
                identity: identity.clone(),
                relative_path: path,
                controllers: parent_group.controllers,
                delegated: parent_group.delegated,
                cpu_weight: CpuWeight::new(100).expect("fixture weight is valid"),
                cpu_quota: CpuQuota::Max,
                cpu_period: CpuPeriod::new(100_000).expect("fixture period is valid"),
                cpuset: parent_group.cpuset.clone(),
                io_weight: IoWeight::new(100).expect("fixture I/O weight is valid"),
                uclamp_min: UclampValue::Value(0),
                uclamp_max: UclampValue::Max,
                processes: BTreeSet::new(),
            },
        );
        Ok(identity)
    }

    /// Set whether one controller is delegated to a cgroup.
    pub fn set_delegation(
        &self,
        cgroup: &CgroupId,
        controller: &str,
        delegated: bool,
    ) -> Result<(), SysboostError> {
        let mut state = self.state.lock().expect("cgroup fixture lock is healthy");
        let group = resolve_group_mut(&mut state, cgroup)?;
        if delegated {
            group.delegated.insert(controller.to_owned());
        } else {
            group.delegated.remove(controller);
        }
        Ok(())
    }

    /// Set controller availability in the deterministic hierarchy.
    pub fn set_controller(
        &self,
        cgroup: &CgroupId,
        controller: &str,
        available: bool,
    ) -> Result<(), SysboostError> {
        let mut state = self.state.lock().expect("cgroup fixture lock is healthy");
        let group = resolve_group_mut(&mut state, cgroup)?;
        if available {
            group.controllers.insert(controller.to_owned());
        } else {
            group.controllers.remove(controller);
        }
        Ok(())
    }

    /// Add an explicitly identified process to a cgroup fixture.
    pub fn add_process(
        &self,
        process: ProcessId,
        cgroup: &CgroupId,
        nice: NiceValue,
        ioprio: IoPriority,
    ) -> Result<(), SysboostError> {
        let mut state = self.state.lock().expect("cgroup fixture lock is healthy");
        let group_handle = resolve_group(&state, cgroup)?.identity.handle.clone();
        if let Some(previous) = state
            .processes
            .get(&process)
            .map(|value| value.cgroup.clone())
        {
            if previous != group_handle {
                if let Some(group) = state.groups.get_mut(&previous) {
                    group.processes.remove(&process);
                }
            }
        }
        state
            .groups
            .get_mut(&group_handle)
            .ok_or_else(|| target_error("cgroup target was not discovered"))?
            .processes
            .insert(process);
        state.processes.insert(
            process,
            FixtureProcess {
                identity: process,
                cgroup: group_handle,
                nice,
                ioprio,
            },
        );
        Ok(())
    }

    /// Replace a cgroup's identity to simulate a remount or directory swap.
    pub fn replace_identity(
        &self,
        cgroup: &CgroupId,
        identity: CgroupId,
    ) -> Result<(), SysboostError> {
        let mut state = self.state.lock().expect("cgroup fixture lock is healthy");
        let group = resolve_group_mut(&mut state, cgroup)?;
        group.identity = identity;
        Ok(())
    }

    /// Simulate an external CPU-weight writer.
    pub fn external_set_cpu_weight(
        &self,
        cgroup: &CgroupId,
        weight: CpuWeight,
    ) -> Result<(), SysboostError> {
        let mut state = self.state.lock().expect("cgroup fixture lock is healthy");
        resolve_group_mut(&mut state, cgroup)?.cpu_weight = weight;
        Ok(())
    }

    /// Simulate a process exit.
    pub fn remove_process(&self, process: ProcessId) {
        let mut state = self.state.lock().expect("cgroup fixture lock is healthy");
        if let Some(process_state) = state.processes.remove(&process) {
            if let Some(group) = state.groups.get_mut(&process_state.cgroup) {
                group.processes.remove(&process);
            }
        }
    }

    fn state(&self) -> Result<std::sync::MutexGuard<'_, CgroupFixtureState>, SysboostError> {
        self.state.lock().map_err(|_| {
            workload_error(ErrorCode::InvariantViolation, "cgroup fixture lock failed")
        })
    }
}

impl Default for CgroupFixture {
    fn default() -> Self {
        Self::new()
    }
}

fn process_identity(process: ProcessId) -> TargetIdentity {
    let mut bytes = [0_u8; 16];
    bytes[..4].copy_from_slice(&process.pid().to_be_bytes());
    bytes[8..].copy_from_slice(&process.start_time_ticks().to_be_bytes());
    TargetIdentity::from_bytes(bytes)
}

fn cgroup_identity(cgroup: &CgroupId) -> TargetIdentity {
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&cgroup.mount_id.to_be_bytes());
    bytes[8..].copy_from_slice(&cgroup.inode.to_be_bytes());
    TargetIdentity::from_bytes(bytes)
}

fn resolve_group<'a>(
    state: &'a CgroupFixtureState,
    cgroup: &CgroupId,
) -> Result<&'a FixtureGroup, SysboostError> {
    let group = state
        .groups
        .get(&cgroup.handle)
        .ok_or_else(|| target_error("cgroup target was not discovered"))?;
    if (cgroup.mount_id != 0 && cgroup.mount_id != group.identity.mount_id)
        || (cgroup.inode != 0 && cgroup.inode != group.identity.inode)
    {
        return Err(target_error(
            "cgroup target identity does not match discovery",
        ));
    }
    Ok(group)
}

fn resolve_group_mut<'a>(
    state: &'a mut CgroupFixtureState,
    cgroup: &CgroupId,
) -> Result<&'a mut FixtureGroup, SysboostError> {
    let group = state
        .groups
        .get_mut(&cgroup.handle)
        .ok_or_else(|| target_error("cgroup target was not discovered"))?;
    if (cgroup.mount_id != 0 && cgroup.mount_id != group.identity.mount_id)
        || (cgroup.inode != 0 && cgroup.inode != group.identity.inode)
    {
        return Err(target_error(
            "cgroup target identity does not match discovery",
        ));
    }
    Ok(group)
}

fn child_target(parent: &TargetId, name: &CgroupName) -> Result<TargetId, SysboostError> {
    TargetId::new(format!("{}.{}", parent.as_str(), name.as_str()))
        .map_err(|_| target_error("managed cgroup child target is invalid"))
}

fn require_controller(group: &FixtureGroup, controller: &str) -> Result<(), SysboostError> {
    if !group.controllers.contains(controller) {
        return Err(unsupported("cgroup controller is unavailable"));
    }
    if !group.delegated.contains(controller) {
        return Err(permission_error("cgroup controller is not delegated"));
    }
    Ok(())
}

fn observation_for_group(
    group: &FixtureGroup,
    typed: TypedValue,
    raw: String,
) -> Result<WorkloadObservation, SysboostError> {
    WorkloadObservation::new(raw.into_bytes(), typed, cgroup_identity(&group.identity))
}

fn render_fixture_node(group: &FixtureGroup, node: WorkloadNode) -> String {
    match node {
        WorkloadNode::CpuWeight => format!("{}\n", group.cpu_weight.get()),
        WorkloadNode::CpuMax => format!(
            "{} {}\n",
            render_quota(group.cpu_quota),
            group.cpu_period.get()
        ),
        WorkloadNode::CpusetCpus => format!("{}\n", render_cpuset(&group.cpuset)),
        WorkloadNode::IoWeight => format!("{}\n", group.io_weight.get()),
        WorkloadNode::UclampMin => format!("{}\n", render_uclamp(group.uclamp_min)),
        WorkloadNode::UclampMax => format!("{}\n", render_uclamp(group.uclamp_max)),
    }
}

fn render_quota(quota: CpuQuota) -> String {
    match quota {
        CpuQuota::Max => "max".to_owned(),
        CpuQuota::Micros(value) => value.to_string(),
    }
}

fn render_cpuset(cpus: &CpuSet) -> String {
    cpus.as_slice()
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn render_uclamp(value: UclampValue) -> String {
    match value {
        UclampValue::Value(value) => value.to_string(),
        UclampValue::Max => "max".to_owned(),
    }
}

fn render_typed_process(value: &TypedValue) -> Vec<u8> {
    PlanValue::Typed(value.clone())
        .to_string()
        .as_bytes()
        .to_vec()
}

fn read_lifecycle(
    state: &CgroupFixtureState,
    parent: &CgroupId,
    name: &CgroupName,
    kind: CgroupGroupKind,
) -> Result<WorkloadObservation, SysboostError> {
    let parent_group = resolve_group(state, parent)?;
    require_controller(parent_group, "cpu")?;
    let target = child_target(&parent.handle, name)?;
    let present = state.groups.contains_key(&target);
    let typed = TypedValue::CgroupLifecycle {
        kind,
        name: name.clone(),
        present,
    };
    observation_for_group(
        parent_group,
        typed,
        if present { "present\n" } else { "absent\n" }.to_owned(),
    )
}

fn validate_uclamp_pair(min: UclampValue, max: UclampValue) -> Result<(), SysboostError> {
    let min = min.get().unwrap_or(1024);
    let max = max.get().unwrap_or(1024);
    if min > max {
        Err(target_error("cgroup uclamp minimum exceeds maximum"))
    } else {
        Ok(())
    }
}

fn create_fixture_group(
    state: &mut CgroupFixtureState,
    parent: &CgroupId,
    name: CgroupName,
    _kind: CgroupGroupKind,
) -> Result<(), SysboostError> {
    let parent_group = resolve_group(state, parent)?.clone();
    let target = child_target(&parent.handle, &name)?;
    if state.groups.contains_key(&target) {
        return Err(workload_error(
            ErrorCode::ApplyError,
            "managed cgroup already exists",
        ));
    }
    let next_inode = state
        .groups
        .values()
        .map(|group| group.identity.inode)
        .max()
        .unwrap_or(1)
        .saturating_add(1);
    let relative_path = if parent_group.relative_path.is_empty() {
        name.as_str().to_owned()
    } else {
        format!("{}/{}", parent_group.relative_path, name.as_str())
    };
    let identity = CgroupId::new(parent_group.identity.mount_id, next_inode, target.clone());
    state.groups.insert(
        target,
        FixtureGroup {
            identity,
            relative_path,
            controllers: parent_group.controllers,
            delegated: parent_group.delegated,
            cpu_weight: CpuWeight::new(100).expect("fixture weight is valid"),
            cpu_quota: CpuQuota::Max,
            cpu_period: CpuPeriod::new(100_000).expect("fixture period is valid"),
            cpuset: parent_group.cpuset,
            io_weight: IoWeight::new(100).expect("fixture I/O weight is valid"),
            uclamp_min: UclampValue::Value(0),
            uclamp_max: UclampValue::Max,
            processes: BTreeSet::new(),
        },
    );
    Ok(())
}

fn remove_fixture_group(
    state: &mut CgroupFixtureState,
    parent: &CgroupId,
    name: &CgroupName,
) -> Result<(), SysboostError> {
    let parent_group = resolve_group(state, parent)?.clone();
    let target = child_target(&parent.handle, name)?;
    let group = state
        .groups
        .get(&target)
        .ok_or_else(|| target_error("managed cgroup disappeared before cleanup"))?;
    if !group.processes.is_empty()
        || state.groups.values().any(|candidate| {
            candidate
                .relative_path
                .starts_with(&format!("{}/", group.relative_path))
        })
    {
        return Err(workload_error(
            ErrorCode::RestoreError,
            "managed cgroup is not empty and cannot be removed safely",
        ));
    }
    if parent_group.relative_path == group.relative_path {
        return Err(target_error(
            "managed cgroup parent and child are identical",
        ));
    }
    state.groups.remove(&target);
    Ok(())
}

fn move_fixture_process(
    state: &mut CgroupFixtureState,
    process: ProcessId,
    destination: &CgroupId,
) -> Result<(), SysboostError> {
    let destination_handle = resolve_group(state, destination)?.identity.handle.clone();
    let current_handle = state
        .processes
        .get(&process)
        .ok_or_else(|| target_error("fixture process disappeared"))?
        .cgroup
        .clone();
    if let Some(current) = state.groups.get_mut(&current_handle) {
        current.processes.remove(&process);
    }
    state
        .groups
        .get_mut(&destination_handle)
        .ok_or_else(|| target_error("fixture destination cgroup disappeared"))?
        .processes
        .insert(process);
    state
        .processes
        .get_mut(&process)
        .ok_or_else(|| target_error("fixture process disappeared"))?
        .cgroup = destination_handle;
    Ok(())
}

impl WorkloadControlIo for CgroupFixture {
    fn detect(&self, clock: &dyn Clock) -> Result<CapabilityInventory, SysboostError> {
        let observed_at = clock.now()?;
        let state = self.state()?;
        let groups = state.groups.values().collect::<Vec<_>>();
        let processes = state.processes.values().collect::<Vec<_>>();
        let has_group = !groups.is_empty();
        let has_controller = |controller: &str| {
            groups
                .iter()
                .any(|group| group.controllers.contains(controller))
        };
        let has_delegation = |controller: &str| {
            groups.iter().any(|group| {
                group.controllers.contains(controller) && group.delegated.contains(controller)
            })
        };
        let cgroup_state = |controller: &str| {
            if !has_group || !has_controller(controller) {
                CapabilityState::Unsupported
            } else if has_delegation(controller) {
                CapabilityState::Available
            } else {
                CapabilityState::Denied
            }
        };
        let process_state = |available: bool| {
            if available {
                CapabilityState::Available
            } else if processes.is_empty() {
                CapabilityState::Unsupported
            } else {
                CapabilityState::Denied
            }
        };
        Ok(CapabilityInventory {
            observed_at,
            capabilities: vec![
                workload_capability(
                    "cgroup.cpu.weight",
                    "cgroup.cpu.weight",
                    TargetKind::Cgroup,
                    EqualityKind::ScalarExact,
                    cgroup_state("cpu"),
                    FeatureClass::RuntimeMutable,
                    "fixture cgroup v2 cpu controller delegation",
                ),
                workload_capability(
                    "cgroup.cpu.max",
                    "cgroup.cpu.max",
                    TargetKind::Cgroup,
                    EqualityKind::ScalarExact,
                    cgroup_state("cpu"),
                    FeatureClass::RuntimeMutable,
                    "fixture cgroup v2 cpu controller delegation",
                ),
                workload_capability(
                    "cgroup.cpuset.cpus",
                    "cgroup.cpuset.cpus",
                    TargetKind::Cgroup,
                    EqualityKind::SetExact,
                    cgroup_state("cpuset"),
                    FeatureClass::Conditional,
                    "fixture cgroup v2 cpuset controller delegation",
                ),
                workload_capability(
                    "cgroup.io.weight",
                    "cgroup.io.weight",
                    TargetKind::Cgroup,
                    EqualityKind::ScalarExact,
                    cgroup_state("io"),
                    FeatureClass::Conditional,
                    "fixture cgroup v2 io controller delegation",
                ),
                uclamp_capability(
                    cgroup_state("cpu"),
                    "fixture cgroup v2 CPU uclamp delegation",
                ),
                workload_capability(
                    "cgroup.workload",
                    "cgroup.workload",
                    TargetKind::Cgroup,
                    EqualityKind::ScalarExact,
                    cgroup_state("cpu"),
                    FeatureClass::Conditional,
                    "fixture delegated parent permits explicit workload group management",
                ),
                workload_capability(
                    "cgroup.background",
                    "cgroup.background",
                    TargetKind::Cgroup,
                    EqualityKind::ScalarExact,
                    cgroup_state("cpu"),
                    FeatureClass::Conditional,
                    "fixture delegated parent permits conservative background management",
                ),
                workload_capability(
                    "scheduler.process.placement",
                    "scheduler.process.placement",
                    TargetKind::Process,
                    EqualityKind::ScalarExact,
                    process_state(has_group && !processes.is_empty()),
                    FeatureClass::Conditional,
                    "fixture explicitly identified process and cgroup targets",
                ),
                workload_capability(
                    "scheduler.nice",
                    "scheduler.nice",
                    TargetKind::Process,
                    EqualityKind::ScalarExact,
                    process_state(!processes.is_empty()),
                    FeatureClass::RuntimeMutable,
                    "fixture explicitly identified process target",
                ),
                workload_capability(
                    "scheduler.ioprio",
                    "scheduler.ioprio",
                    TargetKind::Process,
                    EqualityKind::ScalarExact,
                    process_state(!processes.is_empty()),
                    FeatureClass::Experimental,
                    "fixture explicitly identified process target",
                ),
            ],
        })
    }

    fn targets(&self) -> Result<Vec<WorkloadTarget>, SysboostError> {
        let state = self.state()?;
        Ok(state
            .groups
            .values()
            .map(|group| WorkloadTarget {
                identity: group.identity.clone(),
                relative_path: group.relative_path.clone(),
            })
            .collect())
    }

    fn read_node(&self, cgroup: &CgroupId, node: WorkloadNode) -> Result<Vec<u8>, SysboostError> {
        let state = self.state()?;
        let group = resolve_group(&state, cgroup)?;
        require_controller(group, node.controller())?;
        Ok(render_fixture_node(group, node).into_bytes())
    }

    fn read_mutation(&self, mutation: &MutationKind) -> Result<WorkloadObservation, SysboostError> {
        let state = self.state()?;
        match mutation {
            MutationKind::CgroupCpuWeight { cgroup, .. } => {
                let group = resolve_group(&state, cgroup)?;
                require_controller(group, "cpu")?;
                observation_for_group(
                    group,
                    TypedValue::CgroupCpuWeight(group.cpu_weight),
                    render_fixture_node(group, WorkloadNode::CpuWeight),
                )
            }
            MutationKind::CgroupCpuMax { cgroup, .. } => {
                let group = resolve_group(&state, cgroup)?;
                require_controller(group, "cpu")?;
                observation_for_group(
                    group,
                    TypedValue::CgroupCpuMax {
                        quota: group.cpu_quota,
                        period: group.cpu_period,
                    },
                    render_fixture_node(group, WorkloadNode::CpuMax),
                )
            }
            MutationKind::CgroupCpuset { cgroup, .. } => {
                let group = resolve_group(&state, cgroup)?;
                require_controller(group, "cpuset")?;
                observation_for_group(
                    group,
                    TypedValue::CgroupCpuset(group.cpuset.clone()),
                    render_fixture_node(group, WorkloadNode::CpusetCpus),
                )
            }
            MutationKind::CgroupIoWeight { cgroup, .. } => {
                let group = resolve_group(&state, cgroup)?;
                require_controller(group, "io")?;
                observation_for_group(
                    group,
                    TypedValue::CgroupIoWeight(group.io_weight),
                    render_fixture_node(group, WorkloadNode::IoWeight),
                )
            }
            MutationKind::CgroupUclampMin { cgroup, .. } => {
                let group = resolve_group(&state, cgroup)?;
                require_controller(group, "cpu")?;
                observation_for_group(
                    group,
                    TypedValue::CgroupUclamp(group.uclamp_min),
                    render_fixture_node(group, WorkloadNode::UclampMin),
                )
            }
            MutationKind::CgroupUclampMax { cgroup, .. } => {
                let group = resolve_group(&state, cgroup)?;
                require_controller(group, "cpu")?;
                observation_for_group(
                    group,
                    TypedValue::CgroupUclamp(group.uclamp_max),
                    render_fixture_node(group, WorkloadNode::UclampMax),
                )
            }
            MutationKind::CgroupWorkload { parent, name } => {
                read_lifecycle(&state, parent, name, CgroupGroupKind::Workload)
            }
            MutationKind::CgroupBackground { parent, name } => read_lifecycle(
                &state,
                parent,
                name,
                CgroupGroupKind::ConservativeBackground,
            ),
            _ => Err(unsupported("fixture mutation is not a cgroup operation")),
        }
    }

    fn read_process(&self, mutation: &MutationKind) -> Result<WorkloadObservation, SysboostError> {
        let state = self.state()?;
        let process = match mutation {
            MutationKind::ProcessNice { process, .. }
            | MutationKind::ProcessIoPriority { process, .. }
            | MutationKind::ProcessPlacement { process, .. } => process,
            _ => return Err(unsupported("fixture mutation is not a process operation")),
        };
        let current = state
            .processes
            .get(process)
            .ok_or_else(|| target_error("fixture process disappeared"))?;
        if current.identity != *process {
            return Err(target_error("fixture process identity was replaced"));
        }
        let group = state
            .groups
            .get(&current.cgroup)
            .ok_or_else(|| target_error("fixture process cgroup disappeared"))?;
        let typed = match mutation {
            MutationKind::ProcessNice { .. } => TypedValue::Nice(current.nice),
            MutationKind::ProcessIoPriority { .. } => TypedValue::IoPriority(current.ioprio),
            MutationKind::ProcessPlacement { .. } => {
                TypedValue::ProcessPlacement(group.identity.clone())
            }
            _ => unreachable!(),
        };
        WorkloadObservation::new(
            render_typed_process(&typed),
            typed,
            process_identity(*process),
        )
    }

    fn validate_desired(
        &self,
        mutation: &MutationKind,
        desired: &TypedValue,
    ) -> Result<(), SysboostError> {
        if mutation.typed_value() != *desired {
            return Err(workload_error(
                ErrorCode::PlanningError,
                "workload kind and desired value disagree",
            ));
        }
        let state = self.state()?;
        match mutation {
            MutationKind::CgroupUclampMin { cgroup, value } => {
                if matches!(value, UclampValue::Max) {
                    return Err(workload_error(
                        ErrorCode::InvalidInput,
                        "uclamp.min cannot be max",
                    ));
                }
                let group = resolve_group(&state, cgroup)?;
                require_controller(group, "cpu")?;
                validate_uclamp_pair(*value, group.uclamp_max)
            }
            MutationKind::CgroupUclampMax { cgroup, value } => {
                let group = resolve_group(&state, cgroup)?;
                require_controller(group, "cpu")?;
                validate_uclamp_pair(group.uclamp_min, *value)
            }
            MutationKind::ProcessPlacement { cgroup, .. } => {
                let _ = resolve_group(&state, cgroup)?;
                Ok(())
            }
            MutationKind::CgroupWorkload { parent, .. }
            | MutationKind::CgroupBackground { parent, .. } => {
                let parent = resolve_group(&state, parent)?;
                require_controller(parent, "cpu")
            }
            _ => Ok(()),
        }
    }

    fn write_mutation(
        &self,
        mutation: &MutationKind,
        desired: &TypedValue,
    ) -> Result<(), SysboostError> {
        let mut state = self.state.lock().expect("cgroup fixture lock is healthy");
        match (mutation, desired) {
            (MutationKind::CgroupCpuWeight { cgroup, .. }, TypedValue::CgroupCpuWeight(value)) => {
                resolve_group_mut(&mut state, cgroup)?.cpu_weight = *value
            }
            (
                MutationKind::CgroupCpuMax { cgroup, .. },
                TypedValue::CgroupCpuMax { quota, period },
            ) => {
                let group = resolve_group_mut(&mut state, cgroup)?;
                group.cpu_quota = *quota;
                group.cpu_period = *period;
            }
            (MutationKind::CgroupCpuset { cgroup, .. }, TypedValue::CgroupCpuset(value)) => {
                resolve_group_mut(&mut state, cgroup)?.cpuset = value.clone()
            }
            (MutationKind::CgroupIoWeight { cgroup, .. }, TypedValue::CgroupIoWeight(value)) => {
                resolve_group_mut(&mut state, cgroup)?.io_weight = *value
            }
            (MutationKind::CgroupUclampMin { cgroup, .. }, TypedValue::CgroupUclamp(value)) => {
                resolve_group_mut(&mut state, cgroup)?.uclamp_min = *value
            }
            (MutationKind::CgroupUclampMax { cgroup, .. }, TypedValue::CgroupUclamp(value)) => {
                resolve_group_mut(&mut state, cgroup)?.uclamp_max = *value
            }
            (
                MutationKind::CgroupWorkload { parent, name },
                TypedValue::CgroupLifecycle { present: true, .. },
            ) => create_fixture_group(&mut state, parent, name.clone(), CgroupGroupKind::Workload)?,
            (
                MutationKind::CgroupBackground { parent, name },
                TypedValue::CgroupLifecycle { present: true, .. },
            ) => create_fixture_group(
                &mut state,
                parent,
                name.clone(),
                CgroupGroupKind::ConservativeBackground,
            )?,
            (
                MutationKind::CgroupWorkload { parent, name },
                TypedValue::CgroupLifecycle { present: false, .. },
            )
            | (
                MutationKind::CgroupBackground { parent, name },
                TypedValue::CgroupLifecycle { present: false, .. },
            ) => remove_fixture_group(&mut state, parent, name)?,
            (MutationKind::ProcessNice { process, .. }, TypedValue::Nice(value)) => {
                state
                    .processes
                    .get_mut(process)
                    .ok_or_else(|| target_error("fixture process disappeared"))?
                    .nice = *value
            }
            (MutationKind::ProcessIoPriority { process, .. }, TypedValue::IoPriority(value)) => {
                state
                    .processes
                    .get_mut(process)
                    .ok_or_else(|| target_error("fixture process disappeared"))?
                    .ioprio = *value
            }
            (
                MutationKind::ProcessPlacement { process, .. },
                TypedValue::ProcessPlacement(cgroup),
            ) => move_fixture_process(&mut state, *process, cgroup)?,
            _ => {
                return Err(workload_error(
                    ErrorCode::InvariantViolation,
                    "fixture write shape is not closed",
                ))
            }
        }
        Ok(())
    }
}
