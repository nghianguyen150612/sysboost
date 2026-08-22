#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Deterministic fake ports for core and backend contract tests.

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use sysboost_core::{
    ApplyReceipt, BackendId, BoundedBytes, CapabilityId, CapabilityInventory, EqualityKind,
    ErrorCode, MutationId, MutationKind, OperationId, Plan, PlanAction, PlanId, PlanItem,
    PlanValue, PlannedMutation, Profile, RestoreContract, RestoreMode, RestoreReceipt, RiskClass,
    Session, SessionId, SessionRecord, SessionState, Snapshot, SnapshotContract, Stage,
    StateFingerprint, SysboostError, TargetId, TargetIdentity, Timestamp, TransitionRecord,
    TypedValue, VerificationContract,
};
use sysboost_platform::{
    BackendDescriptor, BackendExecutionToken, Clock, DirectoryEntry, EntryKind,
    ExclusiveSessionLock, FileMetadata, JournalStore, MutationBackend, ProcessIdentity,
    ProcessIdentityProvider, ReadOnlyFileSystem, RelativePath, SessionIdSource, SessionStateStore,
    StoredIntent,
};

/// In-memory filesystem fixture with no host path access.
#[derive(Clone, Debug, Default)]
pub struct MemoryFileSystem {
    files: BTreeMap<RelativePath, MemoryFile>,
}

#[derive(Clone, Debug)]
struct MemoryFile {
    bytes: Vec<u8>,
    read_only: bool,
}

impl MemoryFileSystem {
    /// Create an empty memory fixture.
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed a node for a fixture test.
    pub fn seed(&mut self, path: RelativePath, bytes: impl Into<Vec<u8>>, read_only: bool) {
        self.files.insert(
            path,
            MemoryFile {
                bytes: bytes.into(),
                read_only,
            },
        );
    }

    /// Simulate a concurrent external writer in a test fixture.
    pub fn external_replace(&mut self, path: &RelativePath, bytes: impl Into<Vec<u8>>) {
        if let Some(file) = self.files.get_mut(path) {
            file.bytes = bytes.into();
        }
    }
}

impl ReadOnlyFileSystem for MemoryFileSystem {
    fn read(&self, path: &RelativePath) -> Result<Vec<u8>, SysboostError> {
        self.files
            .get(path)
            .map(|file| file.bytes.clone())
            .ok_or_else(|| {
                SysboostError::new(ErrorCode::TargetError, "memory fixture node is missing")
            })
    }

    fn metadata(&self, path: &RelativePath) -> Result<FileMetadata, SysboostError> {
        self.files
            .get(path)
            .map(|file| FileMetadata {
                len: file.bytes.len() as u64,
                read_only: file.read_only,
            })
            .ok_or_else(|| {
                SysboostError::new(ErrorCode::TargetError, "memory fixture node is missing")
            })
    }

    fn list(&self, path: Option<&RelativePath>) -> Result<Vec<DirectoryEntry>, SysboostError> {
        let prefix = path.map(RelativePath::as_str);
        let mut entries = BTreeMap::new();
        let mut path_exists = path.is_none();
        for file_path in self.files.keys() {
            let remainder = match prefix {
                Some(prefix) => {
                    if file_path.as_str() == prefix {
                        path_exists = true;
                        continue;
                    }
                    let prefix_with_separator = format!("{prefix}/");
                    let Some(remainder) = file_path.as_str().strip_prefix(&prefix_with_separator)
                    else {
                        continue;
                    };
                    path_exists = true;
                    remainder
                }
                None => file_path.as_str(),
            };
            let Some((name, suffix)) = remainder.split_once('/') else {
                entries.insert(remainder.to_owned(), EntryKind::File);
                continue;
            };
            if !name.is_empty() && !suffix.is_empty() {
                entries.insert(name.to_owned(), EntryKind::Directory);
            }
        }
        if let Some(path) = path {
            if self.files.contains_key(path) {
                return Err(SysboostError::new(
                    ErrorCode::TargetError,
                    "memory list target is not a directory",
                ));
            }
        }
        if !path_exists {
            return Err(SysboostError::new(
                ErrorCode::TargetError,
                "memory directory is missing",
            ));
        }
        Ok(entries
            .into_iter()
            .map(|(name, kind)| DirectoryEntry { name, kind })
            .collect())
    }
}

/// Journal fixture with explicit failure injection.
#[derive(Clone, Debug, Default)]
pub struct MemoryJournal {
    /// Durable intents captured by the fixture.
    pub intents: Vec<StoredIntent>,
    /// Durable transitions captured by the fixture.
    pub transitions: Vec<TransitionRecord>,
    /// If set, intent creation fails.
    pub fail_create: bool,
    /// If set, transition persistence fails.
    pub fail_append: bool,
}

impl JournalStore for MemoryJournal {
    fn create_intent(
        &mut self,
        session: &Session,
        snapshots: &[Snapshot],
    ) -> Result<(), SysboostError> {
        if self.fail_create {
            return Err(SysboostError::new(
                ErrorCode::DurabilityError,
                "memory journal injected intent failure",
            ));
        }
        self.intents.push(StoredIntent {
            session: session.clone(),
            snapshots: snapshots.to_vec(),
        });
        Ok(())
    }

    fn append_transition(&mut self, transition: &TransitionRecord) -> Result<(), SysboostError> {
        if self.fail_append {
            return Err(SysboostError::new(
                ErrorCode::DurabilityError,
                "memory journal injected transition failure",
            ));
        }
        self.transitions.push(transition.clone());
        Ok(())
    }

    fn load_unfinished(&self) -> Result<Vec<StoredIntent>, SysboostError> {
        Ok(self
            .intents
            .iter()
            .filter(|intent| !matches!(intent.session.state, sysboost_core::SessionState::Restored))
            .cloned()
            .collect())
    }
}

/// In-memory durable session-state store with deterministic write failures.
#[derive(Clone, Debug, Default)]
pub struct MemoryStateStore {
    /// Raw encoded files, keyed by their typed session ID.
    pub files: BTreeMap<SessionId, Vec<u8>>,
    /// Number of attempted create/replace writes.
    pub write_count: usize,
    /// Fail every intent creation when set.
    pub fail_create: bool,
    /// Fail every state replacement when set.
    pub fail_replace: bool,
    /// Fail exactly one numbered write attempt when set.
    pub fail_on_write: Option<usize>,
    /// Fail reads when set.
    pub fail_load: bool,
}

impl MemoryStateStore {
    /// Seed a raw state-file payload, including intentionally corrupt bytes.
    pub fn seed_raw(&mut self, session_id: SessionId, bytes: Vec<u8>) {
        self.files.insert(session_id, bytes);
    }

    /// Decode one retained state record for fixture assertions.
    pub fn record(&self, session_id: SessionId) -> Result<SessionRecord, SysboostError> {
        self.files
            .get(&session_id)
            .ok_or_else(|| SysboostError::new(ErrorCode::TargetError, "memory state is missing"))
            .and_then(|bytes| SessionRecord::decode(bytes))
    }

    fn should_fail_write(&mut self, creating: bool) -> bool {
        self.write_count = self.write_count.saturating_add(1);
        self.fail_on_write == Some(self.write_count)
            || (creating && self.fail_create)
            || (!creating && self.fail_replace)
    }
}

impl SessionStateStore for MemoryStateStore {
    fn create(&mut self, record: &SessionRecord) -> Result<(), SysboostError> {
        if self.should_fail_write(true) {
            return Err(SysboostError::new(
                ErrorCode::DurabilityError,
                "memory state store injected create failure",
            ));
        }
        let session_id = record.session.header.session_id;
        if self.files.contains_key(&session_id) {
            return Err(SysboostError::new(
                ErrorCode::InvariantViolation,
                "memory state store session ID collision",
            ));
        }
        self.files.insert(session_id, record.encode()?);
        Ok(())
    }

    fn replace(&mut self, record: &SessionRecord) -> Result<(), SysboostError> {
        if self.should_fail_write(false) {
            return Err(SysboostError::new(
                ErrorCode::DurabilityError,
                "memory state store injected replacement failure",
            ));
        }
        let session_id = record.session.header.session_id;
        if !self.files.contains_key(&session_id) {
            return Err(SysboostError::new(
                ErrorCode::DurabilityError,
                "memory state store replacement target is missing",
            ));
        }
        self.files.insert(session_id, record.encode()?);
        Ok(())
    }

    fn load(&self, session_id: SessionId) -> Result<SessionRecord, SysboostError> {
        if self.fail_load {
            return Err(SysboostError::new(
                ErrorCode::DurabilityError,
                "memory state store injected load failure",
            ));
        }
        self.files
            .get(&session_id)
            .ok_or_else(|| SysboostError::new(ErrorCode::TargetError, "memory state is missing"))
            .and_then(|bytes| SessionRecord::decode(bytes))
    }

    fn load_unfinished(&self) -> Result<Vec<SessionRecord>, SysboostError> {
        if self.fail_load {
            return Err(SysboostError::new(
                ErrorCode::DurabilityError,
                "memory state store injected load failure",
            ));
        }
        let mut records = self
            .files
            .values()
            .map(|bytes| SessionRecord::decode(bytes))
            .collect::<Result<Vec<_>, _>>()?;
        records.retain(|record| record.session.state != SessionState::Restored);
        records.sort_by_key(|record| record.session.header.session_id);
        Ok(records)
    }

    fn remove(&mut self, session_id: SessionId) -> Result<(), SysboostError> {
        self.files.remove(&session_id);
        Ok(())
    }
}

/// Shared in-memory exclusive lock for contention tests.
#[derive(Clone, Debug)]
pub struct MemorySessionLock {
    held: Arc<AtomicBool>,
}

impl MemorySessionLock {
    /// Create a lock with a shareable ownership flag.
    pub fn shared() -> Self {
        Self {
            held: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl Default for MemorySessionLock {
    fn default() -> Self {
        Self::shared()
    }
}

#[derive(Debug)]
/// Guard for the in-memory exclusive mutation lease.
pub struct MemorySessionLockGuard {
    held: Arc<AtomicBool>,
}

impl Drop for MemorySessionLockGuard {
    fn drop(&mut self) {
        self.held.store(false, Ordering::Release);
    }
}

impl ExclusiveSessionLock for MemorySessionLock {
    type Guard = MemorySessionLockGuard;

    fn acquire(&mut self) -> Result<Self::Guard, SysboostError> {
        self.held
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| MemorySessionLockGuard {
                held: Arc::clone(&self.held),
            })
            .map_err(|_| {
                SysboostError::new(
                    ErrorCode::AuthorizationError,
                    "memory mutation lock is already held",
                )
            })
    }
}

/// Deterministic session-ID source used by transaction tests.
#[derive(Clone, Debug)]
pub struct FixedSessionIdSource {
    ids: VecDeque<SessionId>,
}

impl FixedSessionIdSource {
    /// Construct a source from a fixed sequence.
    pub fn new(ids: impl IntoIterator<Item = SessionId>) -> Self {
        Self {
            ids: ids.into_iter().collect(),
        }
    }
}

impl SessionIdSource for FixedSessionIdSource {
    fn next_id(&mut self) -> Result<SessionId, SysboostError> {
        self.ids.pop_front().ok_or_else(|| {
            SysboostError::new(
                ErrorCode::DurabilityError,
                "fixed session-ID fixture is exhausted",
            )
        })
    }
}

#[derive(Clone, Debug, Default)]
struct FakeBackendState {
    values: BTreeMap<TargetId, TypedValue>,
    apply_order: Vec<MutationId>,
    restore_order: Vec<MutationId>,
    verify_order: Vec<MutationId>,
    fail_snapshot: Option<MutationId>,
    fail_apply: Option<MutationId>,
    fail_apply_after_write: Option<MutationId>,
    fail_verify: Option<MutationId>,
    fail_restore: Option<MutationId>,
}

/// Deterministic typed mutation executor.  It never accesses a host path.
/// Interior state preserves the frozen `MutationBackend` receiver contract.
#[derive(Debug)]
pub struct FakeMutationBackend {
    descriptor: BackendDescriptor,
    state: RefCell<FakeBackendState>,
}

impl Clone for FakeMutationBackend {
    fn clone(&self) -> Self {
        Self {
            descriptor: self.descriptor.clone(),
            state: RefCell::new(self.state.borrow().clone()),
        }
    }
}

impl Default for FakeMutationBackend {
    fn default() -> Self {
        Self {
            descriptor: BackendDescriptor {
                id: BackendId::new("fixture.fake").expect("static backend ID is valid"),
                version: "fixture-v1".to_owned(),
                capabilities: vec![
                    CapabilityId::new("cpu.policy.governor").expect("static capability is valid")
                ],
                operations: vec![
                    OperationId::new("cpu.governor").expect("static operation is valid")
                ],
            },
            state: RefCell::new(FakeBackendState::default()),
        }
    }
}

impl FakeMutationBackend {
    /// Seed the original typed value for a target.
    pub fn seed(&mut self, target: TargetId, value: TypedValue) {
        self.state.get_mut().values.insert(target, value);
    }

    /// Read a fixture value after a transaction attempt.
    pub fn value(&self, target: &TargetId) -> Option<TypedValue> {
        self.state.borrow().values.get(target).cloned()
    }

    /// Return the successful apply order.
    pub fn apply_order(&self) -> Vec<MutationId> {
        self.state.borrow().apply_order.clone()
    }

    /// Return restore call order, including failed restore calls.
    pub fn restore_order(&self) -> Vec<MutationId> {
        self.state.borrow().restore_order.clone()
    }

    /// Return verification call order.
    pub fn verify_order(&self) -> Vec<MutationId> {
        self.state.borrow().verify_order.clone()
    }

    /// Replace a fixture value as an external writer would.
    pub fn external_replace(&mut self, target: &TargetId, value: TypedValue) {
        if let Some(current) = self.state.get_mut().values.get_mut(target) {
            *current = value;
        }
    }

    /// Inject a snapshot failure for one operation.
    pub fn fail_snapshot_on(&mut self, mutation_id: MutationId) {
        self.state.get_mut().fail_snapshot = Some(mutation_id);
    }

    /// Inject a definite pre-write apply failure for one operation.
    pub fn fail_apply_on(&mut self, mutation_id: MutationId) {
        self.state.get_mut().fail_apply = Some(mutation_id);
    }

    /// Inject an ambiguous apply failure after the fake has changed the
    /// target.  Recovery must stop in `RecoveryPending` because no receipt was
    /// durable.
    pub fn fail_apply_after_write_on(&mut self, mutation_id: MutationId) {
        self.state.get_mut().fail_apply_after_write = Some(mutation_id);
    }

    /// Inject a readback failure for one operation.
    pub fn fail_verify_on(&mut self, mutation_id: MutationId) {
        self.state.get_mut().fail_verify = Some(mutation_id);
    }

    /// Inject a restore failure for one operation.
    pub fn fail_restore_on(&mut self, mutation_id: MutationId) {
        self.state.get_mut().fail_restore = Some(mutation_id);
    }

    /// Stable fixture fingerprint for a typed value.
    pub fn fingerprint(value: &TypedValue) -> StateFingerprint {
        let bytes = format!("{value:?}").into_bytes();
        let mut lanes = [
            0xcbf29ce484222325_u64,
            0x84222325cbf29ce4_u64,
            0x9e3779b185ebca87_u64,
            0x517cc1b727220a95_u64,
        ];
        for (index, byte) in bytes.into_iter().enumerate() {
            let lane = index % lanes.len();
            lanes[lane] ^= u64::from(byte);
            lanes[lane] = lanes[lane]
                .wrapping_mul(0x100000001b3)
                .rotate_left(((index % 63) + 1) as u32);
        }
        let mut output = [0_u8; 32];
        for (index, lane) in lanes.into_iter().enumerate() {
            output[index * 8..(index + 1) * 8].copy_from_slice(&lane.to_be_bytes());
        }
        StateFingerprint::from_bytes(output)
    }

    fn current(&self, target: &TargetId) -> Result<TypedValue, SysboostError> {
        self.state
            .borrow()
            .values
            .get(target)
            .cloned()
            .ok_or_else(|| {
                SysboostError::new(ErrorCode::SnapshotError, "fake target has no seeded value")
            })
    }

    fn failure(code: ErrorCode, stage: Stage, message: &str) -> SysboostError {
        SysboostError::new(code, message).with_stage(stage)
    }
}

impl MutationBackend for FakeMutationBackend {
    fn descriptor(&self) -> &BackendDescriptor {
        &self.descriptor
    }

    fn validate_target(
        &self,
        mutation: &PlannedMutation,
        expected_target_identity: TargetIdentity,
    ) -> Result<(), SysboostError> {
        let MutationKind::CpuGovernor { policy, .. } = &mutation.kind else {
            return Err(SysboostError::new(
                ErrorCode::Unsupported,
                "fake backend target allowlist covers only CPU governor fixtures",
            ));
        };
        let expected_target = format!("fixture.cpu.policy.{}", policy.get());
        let expected_identity = TargetIdentity::from_bytes([policy.get() as u8; 16]);
        if mutation.target.as_str() != expected_target
            || expected_target_identity != expected_identity
        {
            return Err(SysboostError::new(
                ErrorCode::TargetError,
                "fake backend rejected a target outside its compiled-in allowlist",
            )
            .with_target(mutation.target.clone()));
        }
        Ok(())
    }

    fn detect(&self, _clock: &dyn Clock) -> Result<CapabilityInventory, SysboostError> {
        Err(Self::failure(
            ErrorCode::Unsupported,
            Stage::Detect,
            "fake mutation backend has no discovery implementation",
        ))
    }

    fn snapshot(
        &self,
        _execution: &BackendExecutionToken,
        mutation: &PlannedMutation,
        now: Timestamp,
    ) -> Result<Snapshot, SysboostError> {
        if self.state.borrow().fail_snapshot == Some(mutation.mutation_id) {
            return Err(Self::failure(
                ErrorCode::SnapshotError,
                Stage::Snapshot,
                "fake snapshot failure",
            ));
        }
        let current = self.current(&mutation.target)?;
        Ok(Snapshot {
            mutation_id: mutation.mutation_id,
            target: mutation.target.clone(),
            original_raw: BoundedBytes::new(format!("{current:?}").into_bytes())?,
            original_typed: current.clone(),
            original_fingerprint: Self::fingerprint(&current),
            equality: EqualityKind::ScalarExact,
            target_identity: TargetIdentity::from_bytes([mutation.mutation_id.get() as u8; 16]),
            captured_at: now,
        })
    }

    fn apply(
        &self,
        _execution: &BackendExecutionToken,
        mutation: &PlannedMutation,
        _snapshot: &Snapshot,
    ) -> Result<ApplyReceipt, SysboostError> {
        let current = self.current(&mutation.target)?;
        let observed_precondition = Self::fingerprint(&current);
        if self.state.borrow().fail_apply == Some(mutation.mutation_id) {
            return Err(Self::failure(
                ErrorCode::ApplyError,
                Stage::Apply,
                "fake apply failure before write",
            ));
        }
        let mut state = self.state.borrow_mut();
        state
            .values
            .insert(mutation.target.clone(), mutation.desired.clone());
        state.apply_order.push(mutation.mutation_id);
        let ownership_fingerprint = Self::fingerprint(&mutation.desired);
        if state.fail_apply_after_write == Some(mutation.mutation_id) {
            return Err(Self::failure(
                ErrorCode::ApplyError,
                Stage::Apply,
                "fake apply failure after write",
            )
            .retryable(sysboost_core::Retryability::Unknown));
        }
        Ok(ApplyReceipt {
            mutation_id: mutation.mutation_id,
            observed_precondition,
            observed_postcondition: ownership_fingerprint,
            ownership_fingerprint,
        })
    }

    fn verify(
        &self,
        _execution: &BackendExecutionToken,
        mutation: &PlannedMutation,
        _expected: StateFingerprint,
        _expected_target_identity: TargetIdentity,
    ) -> Result<StateFingerprint, SysboostError> {
        self.state
            .borrow_mut()
            .verify_order
            .push(mutation.mutation_id);
        let fail_verify = self.state.borrow().fail_verify == Some(mutation.mutation_id);
        if fail_verify {
            self.state.borrow_mut().fail_verify = None;
            return Err(Self::failure(
                ErrorCode::VerificationError,
                Stage::Verify,
                "fake verification failure",
            ));
        }
        Ok(Self::fingerprint(&self.current(&mutation.target)?))
    }

    fn restore(
        &self,
        _execution: &BackendExecutionToken,
        mutation: &PlannedMutation,
        snapshot: &Snapshot,
        expected_ownership: StateFingerprint,
    ) -> Result<RestoreReceipt, SysboostError> {
        self.state
            .borrow_mut()
            .restore_order
            .push(mutation.mutation_id);
        if self.state.borrow().fail_restore == Some(mutation.mutation_id) {
            return Err(Self::failure(
                ErrorCode::RestoreError,
                Stage::Restore,
                "fake restore failure",
            ));
        }
        if Self::fingerprint(&self.current(&mutation.target)?) != expected_ownership {
            return Err(Self::failure(
                ErrorCode::RestoreConflict,
                Stage::Restore,
                "fake restore ownership precondition changed",
            ));
        }
        self.state
            .borrow_mut()
            .values
            .insert(mutation.target.clone(), snapshot.original_typed.clone());
        Ok(RestoreReceipt {
            mutation_id: mutation.mutation_id,
            restored_fingerprint: Self::fingerprint(&snapshot.original_typed),
            verified: true,
        })
    }
}

/// Build a complete transaction plan for fixture mutations.  Production code
/// must obtain these contracts from the pure typed planner; this helper makes
/// the contract explicit for executor tests without introducing a backend.
pub fn complete_fixture_plan(mutations: Vec<PlannedMutation>) -> Plan {
    let items = mutations
        .iter()
        .map(|mutation| PlanItem {
            capability: mutation.capability.clone(),
            operation: mutation.kind.operation_id(),
            backend: Some(BackendId::new("fixture.fake").expect("valid backend")),
            target: Some(mutation.target.clone()),
            control: sysboost_core::ControlId::CpuGovernor,
            current: Some(PlanValue::Typed(mutation.desired.clone())),
            desired: Some(PlanValue::Typed(mutation.desired.clone())),
            action: PlanAction::Mutation,
            feature: sysboost_core::Feature::CpuGovernor,
            feature_class: sysboost_core::FeatureClass::RuntimeMutable,
            risk: RiskClass::Low,
            explicit_opt_in_required: false,
            experimental: sysboost_core::ExperimentalStatus::NotExperimental,
            evidence: vec![sysboost_core::CapabilityEvidence {
                source: sysboost_core::EvidenceSource::Synthetic,
                detail: "deterministic fake executor fixture".to_owned(),
            }],
            rationale: "fixture mutation has a complete typed contract".to_owned(),
            reason: None,
            target_identity: Some(TargetIdentity::from_bytes(
                [mutation.mutation_id.get() as u8; 16],
            )),
            snapshot: SnapshotContract {
                defined: true,
                typed_preimage: true,
                raw_preimage: true,
                equality: mutation.equality,
            },
            restore: RestoreContract {
                defined: true,
                mode: Some(RestoreMode::CompareAndRestore),
                equality: mutation.equality,
            },
            verification: VerificationContract {
                defined: true,
                readback: true,
                equality: mutation.equality,
            },
            dependencies: mutation.dependencies.clone(),
            mutation: Some(mutation.clone()),
        })
        .collect();
    Plan::from_items(
        PlanId::from_bytes([0xabu8; 16]),
        [0x11; 32],
        [0x22; 32],
        [0x33; 32],
        Profile::Performance,
        items,
    )
    .expect("fixture mutations have complete contracts")
}

/// Deterministic clock.
#[derive(Clone, Copy, Debug)]
pub struct FakeClock {
    /// Fixed timestamp.
    pub timestamp: Timestamp,
}

impl FakeClock {
    /// Construct a fixed test clock.
    pub const fn new(timestamp: Timestamp) -> Self {
        Self { timestamp }
    }
}

impl sysboost_platform::Clock for FakeClock {
    fn now(&self) -> Result<Timestamp, SysboostError> {
        Ok(self.timestamp)
    }
}

/// Deterministic process identity.
#[derive(Clone, Copy, Debug)]
pub struct FakeProcess {
    /// Fixed identity.
    pub identity: ProcessIdentity,
}

impl FakeProcess {
    /// Construct a fixed process provider.
    pub const fn new(identity: ProcessIdentity) -> Self {
        Self { identity }
    }
}

impl ProcessIdentityProvider for FakeProcess {
    fn current(&self) -> Result<ProcessIdentity, SysboostError> {
        Ok(self.identity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sysboost_core::{
        CgroupGroupKind, CgroupId, CgroupName, CpuPeriod, CpuPolicyId, CpuQuota, CpuSet, CpuWeight,
        CurrentState, CurrentStateFact, GovernorId, IoPriority, IoPriorityClass, IoWeight,
        NiceValue, PlannerInput, PlannerPolicy, PolicyRequest, PolicySource, ProcessId,
        TypedPlanner, TypedTarget, UclampValue,
    };
    use sysboost_linux::{
        CgroupFixture, CpuBackend, CpuFixture, CpuNode, WorkloadBackend, WorkloadNode,
        CPU_BACKEND_ID,
    };
    use sysboost_platform::{PrivilegeBroker, PrivilegeService, TransactionEngine};
    use sysboost_protocol::{Request, RequestId, Response, WireCodec};

    fn governor_mutation(id: u32, original: &str, desired: &str) -> PlannedMutation {
        let kind = MutationKind::CpuGovernor {
            policy: CpuPolicyId::new(id),
            governor: GovernorId::new(desired).expect("valid desired governor"),
        };
        let original =
            TypedValue::Governor(GovernorId::new(original).expect("valid original governor"));
        PlannedMutation::new(
            MutationId::new(id),
            CapabilityId::new("cpu.policy.governor").expect("valid capability"),
            TargetId::new(format!("fixture.cpu.policy.{id}")).expect("valid target"),
            kind.clone(),
            kind.typed_value(),
            FakeMutationBackend::fingerprint(&original),
            EqualityKind::ScalarExact,
            Vec::new(),
        )
        .expect("valid fixture mutation")
    }

    fn transaction_fixture() -> (FakeMutationBackend, Plan) {
        let mutations = vec![
            governor_mutation(1, "schedutil", "performance"),
            governor_mutation(2, "powersave", "performance"),
            governor_mutation(3, "schedutil", "performance"),
        ];
        let mut backend = FakeMutationBackend::default();
        backend.seed(
            mutations[0].target.clone(),
            TypedValue::Governor(GovernorId::new("schedutil").expect("valid governor")),
        );
        backend.seed(
            mutations[1].target.clone(),
            TypedValue::Governor(GovernorId::new("powersave").expect("valid governor")),
        );
        backend.seed(
            mutations[2].target.clone(),
            TypedValue::Governor(GovernorId::new("schedutil").expect("valid governor")),
        );
        (backend, complete_fixture_plan(mutations))
    }

    fn engine(
        backend: FakeMutationBackend,
        store: MemoryStateStore,
        lock: MemorySessionLock,
        ids: [u8; 2],
    ) -> TransactionEngine<
        FakeMutationBackend,
        MemoryStateStore,
        MemorySessionLock,
        FixedSessionIdSource,
        FakeClock,
    > {
        TransactionEngine::new(
            backend,
            store,
            lock,
            FixedSessionIdSource::new([
                SessionId::from_bytes([ids[0]; 16]),
                SessionId::from_bytes([ids[1]; 16]),
            ]),
            FakeClock::new(Timestamp::from_unix_millis(100)),
        )
    }

    fn helper_peer() -> ProcessIdentity {
        ProcessIdentity::fixture(41_001, 77, [0x41; 16])
    }

    fn helper(
        backend: FakeMutationBackend,
    ) -> PrivilegeService<
        FakeMutationBackend,
        MemoryStateStore,
        MemorySessionLock,
        FixedSessionIdSource,
        FakeClock,
    > {
        PrivilegeService::new(
            engine(
                backend,
                MemoryStateStore::default(),
                MemorySessionLock::shared(),
                [15, 16],
            ),
            helper_peer(),
        )
        .expect("clean helper starts after recovery audit")
    }

    fn cpu_governor_mutation(
        mutation_id: u32,
        policy: CpuPolicyId,
        identity: TargetIdentity,
        original: &str,
        desired: &str,
    ) -> (PlannedMutation, TypedValue, TargetIdentity) {
        let kind = MutationKind::CpuGovernor {
            policy,
            governor: GovernorId::new(desired).expect("valid desired governor"),
        };
        let original =
            TypedValue::Governor(GovernorId::new(original).expect("valid original governor"));
        let target =
            TargetId::new(format!("cpu.policy.{}", policy.get())).expect("valid CPU policy target");
        let mutation = PlannedMutation::new(
            MutationId::new(mutation_id),
            CapabilityId::new("cpu.policy.governor").expect("valid CPU capability"),
            target,
            kind.clone(),
            kind.typed_value(),
            sysboost_core::fingerprint_for_value(&PlanValue::Typed(original.clone())),
            EqualityKind::ScalarExact,
            Vec::new(),
        )
        .expect("CPU fixture mutation is valid");
        (mutation, original, identity)
    }

    fn complete_cpu_plan(entries: Vec<(PlannedMutation, TypedValue, TargetIdentity)>) -> Plan {
        let items = entries
            .iter()
            .map(|(mutation, original, identity)| PlanItem {
                capability: mutation.capability.clone(),
                operation: mutation.kind.operation_id(),
                backend: Some(BackendId::new(CPU_BACKEND_ID).expect("valid CPU backend")),
                target: Some(mutation.target.clone()),
                control: sysboost_core::ControlId::CpuGovernor,
                current: Some(PlanValue::Typed(original.clone())),
                desired: Some(PlanValue::Typed(mutation.desired.clone())),
                action: PlanAction::Mutation,
                feature: sysboost_core::Feature::CpuGovernor,
                feature_class: sysboost_core::FeatureClass::RuntimeMutable,
                risk: RiskClass::Low,
                explicit_opt_in_required: false,
                experimental: sysboost_core::ExperimentalStatus::NotExperimental,
                evidence: vec![sysboost_core::CapabilityEvidence {
                    source: sysboost_core::EvidenceSource::Synthetic,
                    detail: "typed CPU backend transaction fixture".to_owned(),
                }],
                rationale: "CPU fixture mutation has a complete reversible contract".to_owned(),
                reason: None,
                target_identity: Some(*identity),
                snapshot: SnapshotContract {
                    defined: true,
                    typed_preimage: true,
                    raw_preimage: true,
                    equality: mutation.equality,
                },
                restore: RestoreContract {
                    defined: true,
                    mode: Some(RestoreMode::CompareAndRestore),
                    equality: mutation.equality,
                },
                verification: VerificationContract {
                    defined: true,
                    readback: true,
                    equality: mutation.equality,
                },
                dependencies: mutation.dependencies.clone(),
                mutation: Some(mutation.clone()),
            })
            .collect();
        Plan::from_items(
            PlanId::from_bytes([0xc1; 16]),
            [0x41; 32],
            [0x42; 32],
            [0x43; 32],
            Profile::Performance,
            items,
        )
        .expect("CPU fixture plan is complete")
    }

    fn cpu_helper(
        backend: CpuBackend,
    ) -> PrivilegeService<
        CpuBackend,
        MemoryStateStore,
        MemorySessionLock,
        FixedSessionIdSource,
        FakeClock,
    > {
        PrivilegeService::new(
            TransactionEngine::new(
                backend,
                MemoryStateStore::default(),
                MemorySessionLock::shared(),
                FixedSessionIdSource::new([
                    SessionId::from_bytes([0x51; 16]),
                    SessionId::from_bytes([0x52; 16]),
                ]),
                FakeClock::new(Timestamp::from_unix_millis(200)),
            ),
            helper_peer(),
        )
        .expect("CPU helper starts after recovery audit")
    }

    fn cgroup_target_identity(cgroup: &CgroupId) -> TargetIdentity {
        let mut bytes = [0_u8; 16];
        bytes[..8].copy_from_slice(&cgroup.mount_id.to_be_bytes());
        bytes[8..].copy_from_slice(&cgroup.inode.to_be_bytes());
        TargetIdentity::from_bytes(bytes)
    }

    fn process_target_identity(process: ProcessId) -> TargetIdentity {
        let mut bytes = [0_u8; 16];
        bytes[..4].copy_from_slice(&process.pid().to_be_bytes());
        bytes[8..].copy_from_slice(&process.start_time_ticks().to_be_bytes());
        TargetIdentity::from_bytes(bytes)
    }

    fn workload_plan_item(
        mutation: &PlannedMutation,
        original: &TypedValue,
        target_identity: TargetIdentity,
        feature: sysboost_core::Feature,
        control: sysboost_core::ControlId,
        feature_class: sysboost_core::FeatureClass,
    ) -> PlanItem {
        PlanItem {
            capability: mutation.capability.clone(),
            operation: mutation.kind.operation_id(),
            backend: Some(sysboost_core::BackendId::new("linux.workload").expect("valid backend")),
            target: Some(mutation.target.clone()),
            control,
            current: Some(PlanValue::Typed(original.clone())),
            desired: Some(PlanValue::Typed(mutation.desired.clone())),
            action: PlanAction::Mutation,
            feature,
            feature_class,
            risk: RiskClass::Medium,
            explicit_opt_in_required: feature_class != sysboost_core::FeatureClass::RuntimeMutable,
            experimental: if feature_class == sysboost_core::FeatureClass::Experimental {
                sysboost_core::ExperimentalStatus::Enabled
            } else {
                sysboost_core::ExperimentalStatus::NotExperimental
            },
            evidence: vec![sysboost_core::CapabilityEvidence {
                source: sysboost_core::EvidenceSource::Synthetic,
                detail: "fake cgroup-v2 hierarchy and typed workload backend".to_owned(),
            }],
            rationale: "fixture workload mutation has a complete reversible contract".to_owned(),
            reason: None,
            target_identity: Some(target_identity),
            snapshot: SnapshotContract {
                defined: true,
                typed_preimage: true,
                raw_preimage: true,
                equality: mutation.equality,
            },
            restore: RestoreContract {
                defined: true,
                mode: Some(RestoreMode::CompareAndRestore),
                equality: mutation.equality,
            },
            verification: VerificationContract {
                defined: true,
                readback: true,
                equality: mutation.equality,
            },
            dependencies: mutation.dependencies.clone(),
            mutation: Some(mutation.clone()),
        }
    }

    fn workload_plan(
        seed: u8,
        entries: Vec<(
            PlannedMutation,
            TypedValue,
            TargetIdentity,
            sysboost_core::Feature,
            sysboost_core::ControlId,
            sysboost_core::FeatureClass,
        )>,
    ) -> Plan {
        Plan::from_items(
            PlanId::from_bytes([seed; 16]),
            [seed.wrapping_add(1); 32],
            [seed.wrapping_add(2); 32],
            [seed.wrapping_add(3); 32],
            Profile::Performance,
            entries
                .iter()
                .map(|(mutation, original, identity, feature, control, class)| {
                    workload_plan_item(
                        mutation,
                        original,
                        *identity,
                        feature.clone(),
                        *control,
                        *class,
                    )
                })
                .collect(),
        )
        .expect("workload fixture plan is complete")
    }

    fn workload_weight_mutation(
        id: u32,
        cgroup: &CgroupId,
        desired: CpuWeight,
    ) -> (PlannedMutation, TypedValue, TargetIdentity) {
        let kind = MutationKind::CgroupCpuWeight {
            cgroup: cgroup.clone(),
            weight: desired,
        };
        let original = TypedValue::CgroupCpuWeight(CpuWeight::new(100).expect("valid weight"));
        let mutation = PlannedMutation::new(
            MutationId::new(id),
            CapabilityId::new("cgroup.cpu.weight").expect("valid capability"),
            cgroup.handle.clone(),
            kind.clone(),
            kind.typed_value(),
            sysboost_core::fingerprint_for_value(&PlanValue::Typed(original.clone())),
            EqualityKind::ScalarExact,
            Vec::new(),
        )
        .expect("valid workload weight mutation");
        (mutation, original, cgroup_target_identity(cgroup))
    }

    fn typed_workload_mutation(
        id: u32,
        capability: &str,
        target: TargetId,
        kind: MutationKind,
        original: TypedValue,
        target_identity: TargetIdentity,
        equality: EqualityKind,
    ) -> (PlannedMutation, TypedValue, TargetIdentity) {
        let mutation = PlannedMutation::new(
            MutationId::new(id),
            CapabilityId::new(capability).expect("valid capability"),
            target,
            kind.clone(),
            kind.typed_value(),
            sysboost_core::fingerprint_for_value(&PlanValue::Typed(original.clone())),
            equality,
            Vec::new(),
        )
        .expect("valid typed workload mutation");
        (mutation, original, target_identity)
    }

    fn workload_lifecycle_mutation(
        id: u32,
        parent: &CgroupId,
        name: &str,
        background: bool,
    ) -> (PlannedMutation, TypedValue, TargetIdentity) {
        let name = CgroupName::new(name).expect("valid cgroup name");
        let kind = if background {
            MutationKind::CgroupBackground {
                parent: parent.clone(),
                name: name.clone(),
            }
        } else {
            MutationKind::CgroupWorkload {
                parent: parent.clone(),
                name: name.clone(),
            }
        };
        let group_kind = if background {
            CgroupGroupKind::ConservativeBackground
        } else {
            CgroupGroupKind::Workload
        };
        let original = TypedValue::CgroupLifecycle {
            kind: group_kind,
            name: name.clone(),
            present: false,
        };
        let mutation = PlannedMutation::new(
            MutationId::new(id),
            CapabilityId::new(if background {
                "cgroup.background"
            } else {
                "cgroup.workload"
            })
            .expect("valid capability"),
            parent.handle.clone(),
            kind.clone(),
            kind.typed_value(),
            sysboost_core::fingerprint_for_value(&PlanValue::Typed(original.clone())),
            EqualityKind::ScalarExact,
            Vec::new(),
        )
        .expect("valid workload lifecycle mutation");
        (mutation, original, cgroup_target_identity(parent))
    }

    fn workload_helper(
        backend: WorkloadBackend,
        ids: [u8; 2],
    ) -> PrivilegeService<
        WorkloadBackend,
        MemoryStateStore,
        MemorySessionLock,
        FixedSessionIdSource,
        FakeClock,
    > {
        PrivilegeService::new(
            TransactionEngine::new(
                backend,
                MemoryStateStore::default(),
                MemorySessionLock::shared(),
                FixedSessionIdSource::new([
                    SessionId::from_bytes([ids[0]; 16]),
                    SessionId::from_bytes([ids[1]; 16]),
                ]),
                FakeClock::new(Timestamp::from_unix_millis(300)),
            ),
            helper_peer(),
        )
        .expect("workload helper starts after recovery audit")
    }

    #[test]
    fn memory_fixture_supports_external_change_simulation() {
        let path = RelativePath::new("fixture/value").expect("valid fixture path");
        let mut filesystem = MemoryFileSystem::new();
        filesystem.seed(path.clone(), b"before", false);
        filesystem.external_replace(&path, b"external");
        assert_eq!(filesystem.read(&path).unwrap(), b"external");
    }

    #[test]
    fn journal_failure_is_explicit() {
        let mut journal = MemoryJournal {
            fail_create: true,
            ..MemoryJournal::default()
        };
        let result = journal.create_intent(
            &Session {
                header: sysboost_core::SessionHeader {
                    session_id: sysboost_core::SessionId::from_bytes([1; 16]),
                    plan_id: sysboost_core::PlanId::from_bytes([2; 16]),
                    plan_digest: [3; 32],
                    created_at: Timestamp::from_unix_millis(1),
                    targets: Vec::new(),
                },
                state: sysboost_core::SessionState::New,
            },
            &[],
        );
        assert_eq!(result.unwrap_err().code, ErrorCode::DurabilityError);
    }

    #[test]
    fn journal_persists_intent_transitions_and_filters_restored_sessions() {
        let session_id = sysboost_core::SessionId::from_bytes([4; 16]);
        let mut journal = MemoryJournal::default();
        let session = Session {
            header: sysboost_core::SessionHeader {
                session_id,
                plan_id: sysboost_core::PlanId::from_bytes([5; 16]),
                plan_digest: [6; 32],
                created_at: Timestamp::from_unix_millis(2),
                targets: Vec::new(),
            },
            state: sysboost_core::SessionState::New,
        };

        journal
            .create_intent(&session, &[])
            .expect("intent is retained in memory");
        let transition = TransitionRecord {
            sequence: 1,
            session_id,
            from: sysboost_core::SessionState::New,
            to: sysboost_core::SessionState::Detected,
            at: Timestamp::from_unix_millis(3),
            reason: "fixture transition".to_owned(),
        };
        journal
            .append_transition(&transition)
            .expect("transition is retained in memory");

        assert_eq!(journal.intents.len(), 1);
        assert_eq!(journal.transitions, vec![transition]);
        assert_eq!(journal.load_unfinished().unwrap().len(), 1);

        journal.intents[0].session.state = sysboost_core::SessionState::Restored;
        assert!(journal.load_unfinished().unwrap().is_empty());
    }

    #[test]
    fn mandatory_partial_apply_rolls_back_two_then_one_and_restores_exact_values() {
        let (mut backend, plan) = transaction_fixture();
        let originals = plan
            .mutations
            .iter()
            .map(|mutation| {
                (
                    mutation.target.clone(),
                    backend.value(&mutation.target).expect("seeded value"),
                )
            })
            .collect::<Vec<_>>();
        backend.fail_apply_on(MutationId::new(3));
        let mut engine = engine(
            backend,
            MemoryStateStore::default(),
            MemorySessionLock::default(),
            [1, 2],
        );

        let session_id = engine.prepare(&plan).expect("complete plan prepares");
        let error = engine.apply(session_id).expect_err("operation three fails");
        assert_eq!(error.code, ErrorCode::ApplyError);
        assert_eq!(
            engine.backend().apply_order(),
            vec![MutationId::new(1), MutationId::new(2)]
        );
        assert_eq!(
            engine.backend().restore_order(),
            vec![MutationId::new(2), MutationId::new(1)]
        );
        for (target, original) in originals {
            assert_eq!(engine.backend().value(&target), Some(original));
        }
        assert_eq!(
            engine.status(session_id).expect("status exists").state,
            SessionState::Restored
        );
    }

    #[test]
    fn ambiguous_partial_apply_recovers_known_predecessors_but_blocks_uncertain_target() {
        let (mut backend, plan) = transaction_fixture();
        let uncertain_target = plan.mutations[2].target.clone();
        backend.fail_apply_after_write_on(MutationId::new(3));
        let mut engine = engine(
            backend,
            MemoryStateStore::default(),
            MemorySessionLock::default(),
            [30, 31],
        );
        let session_id = engine.prepare(&plan).expect("prepare succeeds");
        let error = engine
            .apply(session_id)
            .expect_err("ambiguous apply is not reported as success");
        assert_eq!(error.code, ErrorCode::JournalCorrupt);
        assert_eq!(
            engine.backend().restore_order(),
            vec![MutationId::new(2), MutationId::new(1)]
        );
        assert_eq!(
            engine.status(session_id).expect("status exists").state,
            SessionState::RecoveryPending
        );
        assert_eq!(
            engine.backend().value(&uncertain_target),
            Some(TypedValue::Governor(
                GovernorId::new("performance").expect("valid governor"),
            ))
        );
    }

    #[test]
    fn snapshot_failure_prevents_intent_and_every_apply() {
        let (mut backend, plan) = transaction_fixture();
        backend.fail_snapshot_on(MutationId::new(2));
        let mut engine = engine(
            backend,
            MemoryStateStore::default(),
            MemorySessionLock::default(),
            [3, 4],
        );
        let error = engine
            .prepare(&plan)
            .expect_err("snapshot failure rejects prepare");
        assert_eq!(error.code, ErrorCode::SnapshotError);
        assert!(engine.backend().apply_order().is_empty());
        assert!(engine.state_store().files.is_empty());
    }

    #[test]
    fn state_write_failure_prevents_the_first_apply() {
        let (backend, plan) = transaction_fixture();
        let store = MemoryStateStore {
            fail_create: true,
            ..MemoryStateStore::default()
        };
        let mut engine = engine(backend, store.clone(), MemorySessionLock::default(), [5, 6]);
        let error = engine
            .prepare(&plan)
            .expect_err("intent write failure rejects prepare");
        assert_eq!(error.code, ErrorCode::DurabilityError);
        assert!(engine.backend().apply_order().is_empty());
        assert!(engine.state_store().files.is_empty());
    }

    #[test]
    fn state_replacement_failure_is_reported_before_an_untracked_apply() {
        let (backend, plan) = transaction_fixture();
        let store = MemoryStateStore {
            // create() is write 1; the Applying transition is write 2.
            fail_on_write: Some(2),
            ..MemoryStateStore::default()
        };
        let mut engine = engine(backend, store, MemorySessionLock::default(), [26, 27]);
        let session_id = engine.prepare(&plan).expect("intent is durable");
        let error = engine
            .apply(session_id)
            .expect_err("state replacement failure is reported");
        assert_eq!(error.code, ErrorCode::DurabilityError);
        assert!(engine.backend().apply_order().is_empty());
        assert_eq!(
            engine
                .status(session_id)
                .expect("rollback state is durable")
                .state,
            SessionState::Restored
        );
    }

    #[test]
    fn final_active_state_write_failure_restores_all_verified_operations() {
        let (backend, plan) = transaction_fixture();
        let store = MemoryStateStore {
            // create 1, session Applying 2, then three operations each take
            // three writes (Applying, Applied, Verified); Active is write 12.
            fail_on_write: Some(12),
            ..MemoryStateStore::default()
        };
        let mut engine = engine(backend, store, MemorySessionLock::default(), [32, 33]);
        let session_id = engine.prepare(&plan).expect("intent is durable");
        let error = engine
            .apply(session_id)
            .expect_err("final state durability failure is reported");
        assert_eq!(error.code, ErrorCode::DurabilityError);
        assert_eq!(
            engine.backend().restore_order(),
            vec![MutationId::new(3), MutationId::new(2), MutationId::new(1)]
        );
        assert_eq!(
            engine
                .status(session_id)
                .expect("rollback state is durable")
                .state,
            SessionState::Restored
        );
    }

    #[test]
    fn verification_failure_rolls_back_the_failed_operation_and_predecessor() {
        let (mut backend, plan) = transaction_fixture();
        backend.fail_verify_on(MutationId::new(2));
        let mut engine = engine(
            backend,
            MemoryStateStore::default(),
            MemorySessionLock::default(),
            [7, 8],
        );
        let session_id = engine.prepare(&plan).expect("prepare succeeds");
        let error = engine
            .apply(session_id)
            .expect_err("verification failure is reported");
        assert_eq!(error.code, ErrorCode::VerificationError);
        assert_eq!(
            engine.backend().restore_order(),
            vec![MutationId::new(2), MutationId::new(1)]
        );
        assert_eq!(
            engine.status(session_id).expect("status exists").state,
            SessionState::Restored
        );
    }

    #[test]
    fn rollback_failure_is_reported_and_leaves_degraded_state() {
        let (mut backend, plan) = transaction_fixture();
        backend.fail_apply_on(MutationId::new(3));
        backend.fail_restore_on(MutationId::new(2));
        let mut engine = engine(
            backend,
            MemoryStateStore::default(),
            MemorySessionLock::default(),
            [9, 10],
        );
        let session_id = engine.prepare(&plan).expect("prepare succeeds");
        let error = engine
            .apply(session_id)
            .expect_err("rollback failure is not ignored");
        assert_eq!(error.code, ErrorCode::RestoreError);
        assert_eq!(
            engine.backend().restore_order(),
            vec![MutationId::new(2), MutationId::new(1)]
        );
        assert_eq!(
            engine.status(session_id).expect("status exists").state,
            SessionState::Degraded
        );
    }

    #[test]
    fn external_change_is_a_restore_conflict_and_is_not_clobbered() {
        let (backend, plan) = transaction_fixture();
        let target = plan.mutations[1].target.clone();
        let external = TypedValue::Governor(GovernorId::new("ondemand").expect("valid governor"));
        let mut engine = engine(
            backend,
            MemoryStateStore::default(),
            MemorySessionLock::default(),
            [28, 29],
        );
        let session_id = engine.prepare(&plan).expect("prepare succeeds");
        engine.apply(session_id).expect("apply succeeds");
        engine
            .backend_mut()
            .external_replace(&target, external.clone());
        let error = engine
            .restore(session_id)
            .expect_err("external writer creates a conflict");
        assert_eq!(error.code, ErrorCode::RestoreConflict);
        assert_eq!(engine.backend().value(&target), Some(external));
        assert_eq!(
            engine.status(session_id).expect("status exists").state,
            SessionState::Degraded
        );
    }

    #[test]
    fn double_restore_is_idempotent_after_durable_proof() {
        let (backend, plan) = transaction_fixture();
        let mut engine = engine(
            backend,
            MemoryStateStore::default(),
            MemorySessionLock::default(),
            [11, 12],
        );
        let session_id = engine.prepare(&plan).expect("prepare succeeds");
        engine.apply(session_id).expect("apply succeeds");
        assert_eq!(
            engine.restore(session_id).expect("first restore succeeds"),
            SessionState::Restored
        );
        assert_eq!(
            engine
                .restore(session_id)
                .expect("second restore is idempotent"),
            SessionState::Restored
        );
        assert_eq!(
            engine.status(session_id).expect("status exists").state,
            SessionState::Restored
        );
        assert!(engine.backend().restore_order().len() == 3);
    }

    #[test]
    fn lock_contention_rejects_a_second_mutating_session() {
        let (backend, plan) = transaction_fixture();
        let shared_lock = MemorySessionLock::shared();
        let mut first = engine(
            backend.clone(),
            MemoryStateStore::default(),
            shared_lock.clone(),
            [13, 14],
        );
        let _session_id = first.prepare(&plan).expect("first session acquires lock");
        let mut second = engine(backend, MemoryStateStore::default(), shared_lock, [15, 16]);
        let error = second.prepare(&plan).expect_err("second session contends");
        assert_eq!(error.code, ErrorCode::AuthorizationError);
    }

    #[test]
    fn corrupt_state_parsing_is_fail_closed() {
        let session_id = SessionId::from_bytes([17; 16]);
        let mut store = MemoryStateStore::default();
        store.seed_raw(session_id, b"corrupt-state".to_vec());
        let error = store
            .load(session_id)
            .expect_err("corrupt state is rejected");
        assert_eq!(error.code, ErrorCode::JournalCorrupt);
    }

    #[test]
    fn crash_boundary_with_an_ambiguous_apply_stops_in_recovery_pending() {
        let (backend, plan) = transaction_fixture();
        let mut first = engine(
            backend,
            MemoryStateStore::default(),
            MemorySessionLock::default(),
            [18, 19],
        );
        let session_id = first.prepare(&plan).expect("prepare succeeds");
        let mut crash_record = first
            .state_store()
            .record(session_id)
            .expect("durable intent exists");
        crash_record.operations[0]
            .transition(sysboost_core::OperationState::Applying)
            .expect("crash boundary is a legal operation state");
        first
            .state_store_mut()
            .replace(&crash_record)
            .expect("crash state persists");
        let state_copy = first.state_store().clone();
        drop(first);

        let mut recovered = engine(
            FakeMutationBackend::default(),
            state_copy,
            MemorySessionLock::default(),
            [20, 21],
        );
        let error = recovered
            .recover_unfinished()
            .expect_err("ambiguous apply requires operator recovery");
        assert_eq!(error.code, ErrorCode::JournalCorrupt);
        assert_eq!(
            recovered
                .status(session_id)
                .expect("crash state remains readable")
                .state,
            SessionState::RecoveryPending
        );
        assert!(recovered.backend().restore_order().is_empty());
    }

    #[test]
    fn unique_session_ids_can_be_reused_only_after_the_prior_session_is_restored() {
        let (backend, plan) = transaction_fixture();
        let mut engine = engine(
            backend,
            MemoryStateStore::default(),
            MemorySessionLock::default(),
            [22, 23],
        );
        let first = engine.prepare(&plan).expect("first session prepares");
        engine.apply(first).expect("first session applies");
        engine.restore(first).expect("first session restores");
        let second = engine
            .prepare(&plan)
            .expect("second session prepares after restore");
        assert_ne!(first, second);
    }

    #[test]
    fn report_only_or_empty_plans_cannot_enter_transaction_engine() {
        let (backend, mut plan) = transaction_fixture();
        plan.mutations.clear();
        let mut engine = engine(
            backend,
            MemoryStateStore::default(),
            MemorySessionLock::default(),
            [24, 25],
        );
        let error = engine
            .prepare(&plan)
            .expect_err("empty/report-only plan is not executable");
        assert_eq!(error.code, ErrorCode::PlanningError);
    }

    #[test]
    fn helper_prepares_only_after_backend_admission_and_durable_intent() {
        let (backend, plan) = transaction_fixture();
        let mut helper = helper(backend);
        let handle = helper.prepare(&plan).expect("typed plan is admitted");
        assert_eq!(
            helper.status(handle).expect("intent status exists"),
            SessionState::IntentDurable
        );
        assert_eq!(
            helper.apply(handle).expect("helper applies prepared plan"),
            SessionState::Active
        );
        assert_eq!(
            helper.restore(handle).expect("helper restores active plan"),
            SessionState::Restored
        );
    }

    #[test]
    fn helper_rejects_unauthenticated_and_wrong_peers() {
        let request = Request::Prepare {
            request_id: RequestId::new(1).expect("non-zero request ID"),
            plan_id: PlanId::from_bytes([0xab; 16]),
            plan_digest: [0x11; 32],
        }
        .encode()
        .expect("request encodes");
        let (backend, _) = transaction_fixture();
        let mut helper = helper(backend);
        assert_eq!(
            helper
                .handle_frame(None, &request)
                .expect_err("missing peer credentials")
                .code,
            ErrorCode::AuthorizationError
        );
        assert_eq!(
            helper
                .handle_frame(
                    Some(ProcessIdentity::fixture(41_002, 77, [0x41; 16])),
                    &request,
                )
                .expect_err("wrong peer identity")
                .code,
            ErrorCode::AuthorizationError
        );
    }

    #[test]
    fn helper_rejects_malformed_and_replayed_protocol_frames() {
        let (backend, plan) = transaction_fixture();
        let mut helper = helper(backend);
        helper
            .register_plan(plan.clone())
            .expect("catalog registration");
        assert_eq!(
            helper
                .handle_frame(Some(helper_peer()), b"not-a-frame")
                .expect_err("malformed frame")
                .code,
            ErrorCode::TransportError
        );
        let frame = Request::Prepare {
            request_id: RequestId::new(1).expect("request ID"),
            plan_id: plan.id,
            plan_digest: plan.plan_digest,
        }
        .encode()
        .expect("request encodes");
        Response::decode(
            &helper
                .handle_frame(Some(helper_peer()), &frame)
                .expect("first request is accepted"),
        )
        .expect("accepted response decodes");
        assert_eq!(
            helper
                .handle_frame(Some(helper_peer()), &frame)
                .expect_err("replayed request ID")
                .code,
            ErrorCode::TransportError
        );
    }

    #[test]
    fn helper_binds_plan_digest_session_and_backend_ownership() {
        let (backend, plan) = transaction_fixture();
        let mut helper = helper(backend);
        helper
            .register_plan(plan.clone())
            .expect("catalog registration");
        let wrong_digest = Request::Prepare {
            request_id: RequestId::new(1).expect("request ID"),
            plan_id: plan.id,
            plan_digest: [0x99; 32],
        }
        .encode()
        .expect("request encodes");
        let response = Response::decode(
            &helper
                .handle_frame(Some(helper_peer()), &wrong_digest)
                .expect("rejected requests still receive a typed response"),
        )
        .expect("rejection decodes");
        assert!(matches!(
            response,
            Response::Rejected {
                code: ErrorCode::AuthorizationError,
                ..
            }
        ));

        let unknown_session = Request::Apply {
            request_id: RequestId::new(2).expect("request ID"),
            session_id: SessionId::from_bytes([0xfe; 16]),
        }
        .encode()
        .expect("request encodes");
        let response = Response::decode(
            &helper
                .handle_frame(Some(helper_peer()), &unknown_session)
                .expect("unknown session receives rejection"),
        )
        .expect("rejection decodes");
        assert!(matches!(
            response,
            Response::Rejected {
                code: ErrorCode::AuthorizationError,
                ..
            }
        ));

        let mut wrong_backend = plan.clone();
        wrong_backend.items[0].backend = Some(BackendId::new("other.backend").expect("backend"));
        let error = helper
            .prepare_for_peer(helper_peer(), &wrong_backend)
            .expect_err("backend ownership mismatch");
        assert_eq!(error.code, ErrorCode::AuthorizationError);

        let mut wrong_target = plan.clone();
        wrong_target.id = PlanId::from_bytes([0xcd; 16]);
        let injected = TargetId::new("fixture.cpu.policy.1:symlink").expect("bounded target ID");
        wrong_target.mutations[0].target = injected.clone();
        wrong_target.items[0].target = Some(injected);
        wrong_target.items[0]
            .mutation
            .as_mut()
            .expect("mutation item")
            .target = wrong_target.mutations[0].target.clone();
        let error = helper
            .prepare_for_peer(helper_peer(), &wrong_target)
            .expect_err("unallowlisted target is rejected");
        assert_eq!(error.code, ErrorCode::TargetError);
        assert!(TargetId::new("../etc/shadow").is_err());
    }

    #[test]
    fn helper_rejects_target_identity_mismatch_and_absent_plan_mutation() {
        let (backend, plan) = transaction_fixture();
        let mut helper = helper(backend);
        let mut wrong_identity = plan.clone();
        wrong_identity.items[0].target_identity = Some(TargetIdentity::from_bytes([0x99; 16]));
        let error = helper
            .prepare_for_peer(helper_peer(), &wrong_identity)
            .expect_err("target identity is not in the backend allowlist");
        assert_eq!(error.code, ErrorCode::TargetError);

        let absent = Request::Apply {
            request_id: RequestId::new(1).expect("request ID"),
            session_id: SessionId::from_bytes([0x77; 16]),
        }
        .encode()
        .expect("request encodes");
        let response = Response::decode(
            &helper
                .handle_frame(Some(helper_peer()), &absent)
                .expect("absent session is rejected"),
        )
        .expect("rejection decodes");
        assert!(matches!(
            response,
            Response::Rejected {
                code: ErrorCode::AuthorizationError,
                ..
            }
        ));
    }

    #[test]
    fn privilege_integration_preserves_reverse_rollback_and_recovery_contract() {
        let (mut backend, plan) = transaction_fixture();
        backend.fail_apply_on(MutationId::new(2));
        let mut helper = helper(backend);
        let handle = helper
            .prepare(&plan)
            .expect("prepare persists intent first");
        let error = helper
            .apply(handle)
            .expect_err("failed typed apply rolls back");
        assert_eq!(error.code, ErrorCode::ApplyError);
        assert_eq!(
            helper.status(handle).expect("status remains durable"),
            SessionState::Restored
        );
    }

    #[test]
    fn cpu_backend_is_reached_through_privilege_service_and_rolls_back_partial_apply() {
        let fixture = CpuFixture::new();
        fixture.add_policy(
            CpuPolicyId::new(0),
            TargetIdentity::from_bytes([0x10; 16]),
            GovernorId::new("schedutil").expect("valid governor"),
            vec![
                GovernorId::new("schedutil").expect("valid governor"),
                GovernorId::new("performance").expect("valid governor"),
            ],
            sysboost_core::EnergyPreference::BalancePerformance,
            vec![sysboost_core::EnergyPreference::BalancePerformance],
            sysboost_core::FrequencyKHz::new(800_000).expect("valid frequency"),
            sysboost_core::FrequencyKHz::new(3_600_000).expect("valid frequency"),
            sysboost_core::FrequencyKHz::new(400_000).expect("valid frequency"),
            sysboost_core::FrequencyKHz::new(4_000_000).expect("valid frequency"),
        );
        fixture.add_policy(
            CpuPolicyId::new(1),
            TargetIdentity::from_bytes([0x11; 16]),
            GovernorId::new("powersave").expect("valid governor"),
            vec![
                GovernorId::new("powersave").expect("valid governor"),
                GovernorId::new("performance").expect("valid governor"),
            ],
            sysboost_core::EnergyPreference::Power,
            vec![sysboost_core::EnergyPreference::Power],
            sysboost_core::FrequencyKHz::new(600_000).expect("valid frequency"),
            sysboost_core::FrequencyKHz::new(2_400_000).expect("valid frequency"),
            sysboost_core::FrequencyKHz::new(400_000).expect("valid frequency"),
            sysboost_core::FrequencyKHz::new(3_000_000).expect("valid frequency"),
        );
        fixture.fail_writes_for(CpuNode::Governor(CpuPolicyId::new(1)));

        let (first, first_original, first_identity) = cpu_governor_mutation(
            1,
            CpuPolicyId::new(0),
            TargetIdentity::from_bytes([0x10; 16]),
            "schedutil",
            "performance",
        );
        let (second, second_original, second_identity) = cpu_governor_mutation(
            2,
            CpuPolicyId::new(1),
            TargetIdentity::from_bytes([0x11; 16]),
            "powersave",
            "performance",
        );
        let plan = complete_cpu_plan(vec![
            (first, first_original, first_identity),
            (second, second_original, second_identity),
        ]);
        let mut helper = cpu_helper(CpuBackend::from_fixture(fixture.clone()));
        helper
            .register_plan(plan.clone())
            .expect("approved CPU plan is catalogued");
        let handle = helper
            .prepare(&plan)
            .expect("CPU snapshots and durable intent complete before apply");
        assert_eq!(
            helper.status(handle).expect("prepared status is readable"),
            SessionState::IntentDurable
        );
        assert_eq!(
            fixture
                .read(CpuNode::Governor(CpuPolicyId::new(0)))
                .expect("policy 0 is readable")
                .typed,
            TypedValue::Governor(GovernorId::new("schedutil").expect("valid governor"))
        );

        let error = helper
            .apply(handle)
            .expect_err("second policy failure triggers transaction rollback");
        assert_eq!(error.code, ErrorCode::ApplyError);
        assert_eq!(
            helper.status(handle).expect("restored status is durable"),
            SessionState::Restored
        );
        assert_eq!(
            fixture
                .read(CpuNode::Governor(CpuPolicyId::new(0)))
                .expect("policy 0 is readable after rollback")
                .typed,
            TypedValue::Governor(GovernorId::new("schedutil").expect("valid governor"))
        );
        assert_eq!(
            fixture
                .read(CpuNode::Governor(CpuPolicyId::new(1)))
                .expect("policy 1 is readable after rollback")
                .typed,
            TypedValue::Governor(GovernorId::new("powersave").expect("valid governor"))
        );
    }

    #[test]
    fn workload_fixture_reports_controller_availability_and_delegation() {
        let fixture = CgroupFixture::new();
        let root = fixture.root_id();
        let backend = WorkloadBackend::from_fixture(fixture.clone());
        let clock = FakeClock::new(Timestamp::from_unix_millis(301));

        let inventory = backend.detect(&clock).expect("fixture detection succeeds");
        assert_eq!(
            inventory
                .capabilities
                .iter()
                .find(|capability| capability.id.as_str() == "cgroup.io.weight")
                .expect("I/O capability is reported")
                .state,
            sysboost_core::CapabilityState::Available
        );
        assert_eq!(
            backend
                .io()
                .read(&root, WorkloadNode::IoWeight)
                .expect("delegated I/O node is readable"),
            b"100\n"
        );

        fixture
            .set_controller(&root, "io", false)
            .expect("fixture controller can be disabled");
        let inventory = backend
            .detect(&clock)
            .expect("detection degrades gracefully");
        assert_eq!(
            inventory
                .capabilities
                .iter()
                .find(|capability| capability.id.as_str() == "cgroup.io.weight")
                .expect("I/O capability remains explained")
                .state,
            sysboost_core::CapabilityState::Unsupported
        );
        assert_eq!(
            backend
                .io()
                .read(&root, WorkloadNode::IoWeight)
                .expect_err("unavailable controller is rejected")
                .code,
            ErrorCode::Unsupported
        );

        fixture
            .set_controller(&root, "io", true)
            .expect("fixture controller can be restored");
        fixture
            .set_delegation(&root, "io", false)
            .expect("fixture delegation can be removed");
        let inventory = backend
            .detect(&clock)
            .expect("delegation denial is explained");
        assert_eq!(
            inventory
                .capabilities
                .iter()
                .find(|capability| capability.id.as_str() == "cgroup.io.weight")
                .expect("I/O capability remains explained")
                .state,
            sysboost_core::CapabilityState::Denied
        );
        assert_eq!(
            backend
                .io()
                .read(&root, WorkloadNode::IoWeight)
                .expect_err("undelegated controller is rejected")
                .code,
            ErrorCode::AuthorizationError
        );
    }

    #[test]
    fn workload_closed_controls_apply_verify_and_restore_exact_typed_values() {
        let fixture = CgroupFixture::new();
        let root = fixture.root_id();
        let process = ProcessId::new(3456, 7890).expect("valid process identity");
        let original_ioprio =
            IoPriority::new(IoPriorityClass::BestEffort, 4).expect("valid original I/O priority");
        fixture
            .add_process(
                process,
                &root,
                NiceValue::new(0).expect("valid original nice"),
                original_ioprio,
            )
            .expect("fixture process is placed");

        let max_period = CpuPeriod::new(100_000).expect("valid period");
        let max_kind = MutationKind::CgroupCpuMax {
            cgroup: root.clone(),
            quota: CpuQuota::micros(50_000).expect("valid quota"),
            period: max_period,
        };
        let max_original = TypedValue::CgroupCpuMax {
            quota: CpuQuota::Max,
            period: max_period,
        };
        let max_entry = typed_workload_mutation(
            1,
            "cgroup.cpu.max",
            root.handle.clone(),
            max_kind,
            max_original,
            cgroup_target_identity(&root),
            EqualityKind::ScalarExact,
        );

        let cpuset_kind = MutationKind::CgroupCpuset {
            cgroup: root.clone(),
            cpus: CpuSet::new(vec![1]).expect("valid desired CPU set"),
        };
        let cpuset_entry = typed_workload_mutation(
            2,
            "cgroup.cpuset.cpus",
            root.handle.clone(),
            cpuset_kind,
            TypedValue::CgroupCpuset(CpuSet::new(vec![0, 1]).expect("valid original CPU set")),
            cgroup_target_identity(&root),
            EqualityKind::SetExact,
        );

        let io_kind = MutationKind::CgroupIoWeight {
            cgroup: root.clone(),
            weight: IoWeight::new(250).expect("valid desired I/O weight"),
        };
        let io_entry = typed_workload_mutation(
            3,
            "cgroup.io.weight",
            root.handle.clone(),
            io_kind,
            TypedValue::CgroupIoWeight(IoWeight::new(100).expect("valid original I/O weight")),
            cgroup_target_identity(&root),
            EqualityKind::ScalarExact,
        );

        let min_kind = MutationKind::CgroupUclampMin {
            cgroup: root.clone(),
            value: UclampValue::new(128).expect("valid desired minimum clamp"),
        };
        let min_entry = typed_workload_mutation(
            4,
            "cgroup.uclamp",
            root.handle.clone(),
            min_kind,
            TypedValue::CgroupUclamp(UclampValue::Value(0)),
            cgroup_target_identity(&root),
            EqualityKind::ScalarExact,
        );

        let max_kind = MutationKind::CgroupUclampMax {
            cgroup: root.clone(),
            value: UclampValue::new(800).expect("valid desired maximum clamp"),
        };
        let max_clamp_entry = typed_workload_mutation(
            5,
            "cgroup.uclamp",
            root.handle.clone(),
            max_kind,
            TypedValue::CgroupUclamp(UclampValue::Max),
            cgroup_target_identity(&root),
            EqualityKind::ScalarExact,
        );

        let nice_kind = MutationKind::ProcessNice {
            process,
            nice: NiceValue::new(7).expect("valid desired nice"),
        };
        let nice_entry = typed_workload_mutation(
            6,
            "scheduler.nice",
            process.target_id(),
            nice_kind,
            TypedValue::Nice(NiceValue::new(0).expect("valid original nice")),
            process_target_identity(process),
            EqualityKind::ScalarExact,
        );

        let ioprio_kind = MutationKind::ProcessIoPriority {
            process,
            priority: IoPriority::new(IoPriorityClass::Idle, 6)
                .expect("valid desired I/O priority"),
        };
        let ioprio_entry = typed_workload_mutation(
            7,
            "scheduler.ioprio",
            process.target_id(),
            ioprio_kind,
            TypedValue::IoPriority(original_ioprio),
            process_target_identity(process),
            EqualityKind::ScalarExact,
        );

        let plan = workload_plan(
            0xa1,
            vec![
                (
                    max_entry.0,
                    max_entry.1,
                    max_entry.2,
                    sysboost_core::Feature::CgroupCpu,
                    sysboost_core::ControlId::CgroupCpuMax,
                    sysboost_core::FeatureClass::RuntimeMutable,
                ),
                (
                    cpuset_entry.0,
                    cpuset_entry.1,
                    cpuset_entry.2,
                    sysboost_core::Feature::CgroupCpu,
                    sysboost_core::ControlId::CgroupCpuset,
                    sysboost_core::FeatureClass::Conditional,
                ),
                (
                    io_entry.0,
                    io_entry.1,
                    io_entry.2,
                    sysboost_core::Feature::CgroupCpu,
                    sysboost_core::ControlId::CgroupIoWeight,
                    sysboost_core::FeatureClass::Conditional,
                ),
                (
                    min_entry.0,
                    min_entry.1,
                    min_entry.2,
                    sysboost_core::Feature::CgroupCpu,
                    sysboost_core::ControlId::CgroupUclampMin,
                    sysboost_core::FeatureClass::Conditional,
                ),
                (
                    max_clamp_entry.0,
                    max_clamp_entry.1,
                    max_clamp_entry.2,
                    sysboost_core::Feature::CgroupCpu,
                    sysboost_core::ControlId::CgroupUclampMax,
                    sysboost_core::FeatureClass::Conditional,
                ),
                (
                    nice_entry.0,
                    nice_entry.1,
                    nice_entry.2,
                    sysboost_core::Feature::SchedulerTuning,
                    sysboost_core::ControlId::ProcessNice,
                    sysboost_core::FeatureClass::RuntimeMutable,
                ),
                (
                    ioprio_entry.0,
                    ioprio_entry.1,
                    ioprio_entry.2,
                    sysboost_core::Feature::SchedulerTuning,
                    sysboost_core::ControlId::ProcessIoPriority,
                    sysboost_core::FeatureClass::Experimental,
                ),
            ],
        );
        let mut helper =
            workload_helper(WorkloadBackend::from_fixture(fixture.clone()), [0xa1, 0xa2]);
        let handle = helper
            .prepare(&plan)
            .expect("all closed typed workload preimages are captured");
        helper
            .apply(handle)
            .expect("all closed workload operations apply");

        let inspector = WorkloadBackend::from_fixture(fixture.clone());
        assert_eq!(
            inspector.io().read(&root, WorkloadNode::CpuMax).unwrap(),
            b"50000 100000\n"
        );
        assert_eq!(
            inspector
                .io()
                .read(&root, WorkloadNode::CpusetCpus)
                .unwrap(),
            b"1\n"
        );
        assert_eq!(
            inspector.io().read(&root, WorkloadNode::IoWeight).unwrap(),
            b"250\n"
        );
        assert_eq!(
            inspector.io().read(&root, WorkloadNode::UclampMin).unwrap(),
            b"128\n"
        );
        assert_eq!(
            inspector.io().read(&root, WorkloadNode::UclampMax).unwrap(),
            b"800\n"
        );
        assert_eq!(
            inspector.io().read_nice(process).unwrap(),
            NiceValue::new(7).unwrap()
        );
        assert_eq!(
            inspector.io().read_ioprio(process).unwrap(),
            IoPriority::new(IoPriorityClass::Idle, 6).unwrap()
        );

        helper
            .restore(handle)
            .expect("all closed workload values restore");
        assert_eq!(
            inspector.io().read(&root, WorkloadNode::CpuMax).unwrap(),
            b"max 100000\n"
        );
        assert_eq!(
            inspector
                .io()
                .read(&root, WorkloadNode::CpusetCpus)
                .unwrap(),
            b"0,1\n"
        );
        assert_eq!(
            inspector.io().read(&root, WorkloadNode::IoWeight).unwrap(),
            b"100\n"
        );
        assert_eq!(
            inspector.io().read(&root, WorkloadNode::UclampMin).unwrap(),
            b"0\n"
        );
        assert_eq!(
            inspector.io().read(&root, WorkloadNode::UclampMax).unwrap(),
            b"max\n"
        );
        assert_eq!(
            inspector.io().read_nice(process).unwrap(),
            NiceValue::new(0).unwrap()
        );
        assert_eq!(
            inspector.io().read_ioprio(process).unwrap(),
            original_ioprio
        );
    }

    #[test]
    fn workload_operation_catalog_feeds_the_pure_planner() {
        let fixture = CgroupFixture::new();
        let root = fixture.root_id();
        let backend = WorkloadBackend::from_fixture(fixture);
        let observed_at = Timestamp::from_unix_millis(401);
        let inventory = backend
            .detect(&FakeClock::new(observed_at))
            .expect("workload inventory is available to the planner");
        let capability = CapabilityId::new("cgroup.io.weight").expect("valid capability");
        let original = TypedValue::CgroupIoWeight(IoWeight::new(100).expect("valid weight"));
        let desired = TypedValue::CgroupIoWeight(IoWeight::new(250).expect("valid weight"));
        let target = root.handle.clone();
        let operation = MutationKind::CgroupIoWeight {
            cgroup: root.clone(),
            weight: IoWeight::new(250).expect("valid weight"),
        };
        let current = CurrentState::new(
            observed_at,
            vec![CurrentStateFact::known(
                capability.clone(),
                target.clone(),
                sysboost_core::ControlId::CgroupIoWeight,
                PlanValue::Typed(original.clone()),
                sysboost_core::fingerprint_for_value(&PlanValue::Typed(original)),
            )
            .with_target_identity(cgroup_target_identity(&root))
            .with_typed_target(TypedTarget::Cgroup(root))],
        )
        .expect("current workload state is consistent");
        let policy = PlannerPolicy::for_profile(Profile::Performance)
            .with_mode(sysboost_core::PolicyMode::Boost)
            .opt_in(sysboost_core::Feature::CgroupCpu)
            .proposal(
                PolicySource::User,
                PolicyRequest::optional(capability, target, operation),
            );
        let plan = TypedPlanner::new(sysboost_linux::linux_operation_catalog())
            .build(&PlannerInput {
                policy,
                inventory,
                current_state: current,
            })
            .expect("workload operation is admitted by the pure planner");
        assert!(plan.mutations.iter().any(|mutation| {
            mutation.kind.operation_id().as_str() == "cgroup.io.weight"
                && mutation.desired == desired
                && mutation.capability.as_str() == "cgroup.io.weight"
        }));
        let item = plan
            .items
            .iter()
            .find(|item| item.operation.as_str() == "cgroup.io.weight")
            .expect("planner retains an explainable workload item");
        assert_eq!(item.backend.as_ref().unwrap().as_str(), "linux.workload");
        assert!(item.snapshot.is_complete());
        assert!(item.restore.is_complete());
        assert!(item.verification.is_complete());
    }

    #[test]
    fn workload_process_catalog_entries_match_detected_typed_capabilities() {
        let fixture = CgroupFixture::new();
        let root = fixture.root_id();
        let process = ProcessId::new(4567, 8901).expect("valid process identity");
        fixture
            .add_process(
                process,
                &root,
                NiceValue::new(0).expect("valid original nice"),
                IoPriority::new(IoPriorityClass::None, 0).expect("valid original I/O priority"),
            )
            .expect("fixture process is placed");

        let backend = WorkloadBackend::from_fixture(fixture);
        let observed_at = Timestamp::from_unix_millis(402);
        let inventory = backend
            .detect(&FakeClock::new(observed_at))
            .expect("workload inventory is available to the planner");
        let capability = CapabilityId::new("scheduler.nice").expect("valid capability");
        let target = process.target_id();
        let original = TypedValue::Nice(NiceValue::new(0).expect("valid original nice"));
        let operation = MutationKind::ProcessNice {
            process,
            nice: NiceValue::new(7).expect("valid desired nice"),
        };
        let current_state = CurrentState::new(
            observed_at,
            vec![CurrentStateFact::known(
                capability.clone(),
                target.clone(),
                sysboost_core::ControlId::ProcessNice,
                PlanValue::Typed(original.clone()),
                sysboost_core::fingerprint_for_value(&PlanValue::Typed(original)),
            )
            .with_target_identity(process_target_identity(process))
            .with_typed_target(TypedTarget::Process(process))],
        )
        .expect("current process state is consistent");
        let policy = PlannerPolicy::for_profile(Profile::Performance)
            .with_experimental_permission(true)
            .opt_in(sysboost_core::Feature::SchedulerTuning)
            .proposal(
                PolicySource::User,
                PolicyRequest::optional(capability, target, operation),
            );
        let plan = TypedPlanner::new(sysboost_linux::linux_operation_catalog())
            .build(&PlannerInput {
                policy,
                inventory,
                current_state,
            })
            .expect("typed nice operation is admitted by the pure planner");
        assert!(plan.mutations.iter().any(|mutation| {
            matches!(
                mutation.kind,
                MutationKind::ProcessNice {
                    process: observed,
                    nice
                } if observed == process && nice == NiceValue::new(7).unwrap()
            )
        }));
        let item = plan
            .items
            .iter()
            .find(|item| item.operation.as_str() == "scheduler.nice")
            .expect("planner retains an explainable nice item");
        assert_eq!(item.backend.as_ref().unwrap().as_str(), "linux.workload");
        assert!(item.snapshot.is_complete());
        assert!(item.restore.is_complete());
        assert!(item.verification.is_complete());
    }

    #[test]
    fn workload_process_placement_is_nested_target_validated_and_transactional() {
        let fixture = CgroupFixture::new();
        let root = fixture.root_id();
        let name = CgroupName::new("workload").expect("valid group name");
        let child = CgroupId::new(
            1,
            2,
            TargetId::new("cgroup.root.workload").expect("valid child target"),
        );
        fixture
            .add_child_group(&root, name, child.clone())
            .expect("nested cgroup is valid");
        let process = ProcessId::new(1234, 5678).expect("valid process identity");
        fixture
            .add_process(
                process,
                &root,
                NiceValue::new(0).expect("valid nice"),
                IoPriority::new(IoPriorityClass::BestEffort, 4).expect("valid I/O priority"),
            )
            .expect("fixture process is placed");

        let kind = MutationKind::ProcessPlacement {
            process,
            cgroup: child.clone(),
        };
        let original = TypedValue::ProcessPlacement(root.clone());
        let mutation = PlannedMutation::new(
            MutationId::new(1),
            CapabilityId::new("scheduler.process.placement").expect("valid capability"),
            process.target_id(),
            kind.clone(),
            kind.typed_value(),
            sysboost_core::fingerprint_for_value(&PlanValue::Typed(original.clone())),
            EqualityKind::ScalarExact,
            Vec::new(),
        )
        .expect("valid placement mutation");
        let plan = workload_plan(
            0x61,
            vec![(
                mutation,
                original,
                process_target_identity(process),
                sysboost_core::Feature::SchedulerTuning,
                sysboost_core::ControlId::ProcessPlacement,
                sysboost_core::FeatureClass::Conditional,
            )],
        );
        let mut helper =
            workload_helper(WorkloadBackend::from_fixture(fixture.clone()), [0x61, 0x62]);
        let handle = helper
            .prepare(&plan)
            .expect("placement snapshot and durable intent succeed");
        assert_eq!(
            helper.apply(handle).expect("placement apply succeeds"),
            SessionState::Active
        );
        let inspector = WorkloadBackend::from_fixture(fixture.clone());
        assert_eq!(
            inspector
                .io()
                .read_placement(process)
                .expect("placement readback succeeds"),
            child
        );
        assert_eq!(
            helper.restore(handle).expect("placement restore succeeds"),
            SessionState::Restored
        );
        assert_eq!(
            inspector
                .io()
                .read_placement(process)
                .expect("placement restore readback succeeds"),
            root
        );

        let supervisor = sysboost_linux::ChildProcessSupervisor::new(child.clone());
        assert_eq!(
            supervisor.on_child_started(process),
            MutationKind::ProcessPlacement {
                process,
                cgroup: child,
            }
        );
        fixture.remove_process(process);
        assert_eq!(
            inspector
                .io()
                .read_nice(process)
                .expect_err("exited workload is no longer a valid target")
                .code,
            ErrorCode::TargetError
        );
        supervisor.on_child_exited(process);
    }

    #[test]
    fn workload_group_cleanup_is_exact_after_explicit_workload_exit() {
        let fixture = CgroupFixture::new();
        let root = fixture.root_id();
        let (mutation, original, identity) =
            workload_lifecycle_mutation(1, &root, "workload", false);
        let plan = workload_plan(
            0x71,
            vec![(
                mutation,
                original,
                identity,
                sysboost_core::Feature::CgroupCpu,
                sysboost_core::ControlId::CgroupWorkload,
                sysboost_core::FeatureClass::Conditional,
            )],
        );
        let mut helper =
            workload_helper(WorkloadBackend::from_fixture(fixture.clone()), [0x71, 0x72]);
        let handle = helper.prepare(&plan).expect("workload setup is admitted");
        helper.apply(handle).expect("workload cgroup is created");

        let child = CgroupId::new(
            1,
            2,
            TargetId::new("cgroup.root.workload").expect("valid child target"),
        );
        let process = ProcessId::new(2345, 6789).expect("valid process identity");
        fixture
            .add_process(
                process,
                &child,
                NiceValue::new(5).expect("valid nice"),
                IoPriority::new(IoPriorityClass::Idle, 7).expect("valid I/O priority"),
            )
            .expect("workload process is supervised explicitly");
        fixture.remove_process(process);

        helper
            .restore(handle)
            .expect("empty managed cgroup is removed exactly");
        let inspector = WorkloadBackend::from_fixture(fixture);
        assert!(inspector
            .io()
            .targets()
            .expect("target enumeration succeeds")
            .iter()
            .all(|target| target.relative_path != "workload"));
    }

    #[test]
    fn workload_partial_setup_rolls_back_the_first_managed_group() {
        let fixture = CgroupFixture::new();
        let root = fixture.root_id();
        let first = workload_lifecycle_mutation(1, &root, "shared", false);
        let second = workload_lifecycle_mutation(2, &root, "shared", true);
        let plan = workload_plan(
            0x81,
            vec![
                (
                    first.0,
                    first.1,
                    first.2,
                    sysboost_core::Feature::CgroupCpu,
                    sysboost_core::ControlId::CgroupWorkload,
                    sysboost_core::FeatureClass::Conditional,
                ),
                (
                    second.0,
                    second.1,
                    second.2,
                    sysboost_core::Feature::CgroupCpu,
                    sysboost_core::ControlId::CgroupBackground,
                    sysboost_core::FeatureClass::Conditional,
                ),
            ],
        );
        let mut helper =
            workload_helper(WorkloadBackend::from_fixture(fixture.clone()), [0x81, 0x82]);
        let handle = helper
            .prepare(&plan)
            .expect("both lifecycle preimages are captured");
        let error = helper
            .apply(handle)
            .expect_err("second closed lifecycle setup collides safely");
        assert_eq!(error.code, ErrorCode::TargetError);
        assert_eq!(
            helper.status(handle).expect("rollback state is durable"),
            SessionState::Restored
        );
        let inspector = WorkloadBackend::from_fixture(fixture);
        assert!(inspector
            .io()
            .targets()
            .expect("target enumeration succeeds")
            .iter()
            .all(|target| target.relative_path != "shared"));
    }

    #[test]
    fn workload_delegation_failure_blocks_privilege_admission() {
        let fixture = CgroupFixture::new();
        let root = fixture.root_id();
        fixture
            .set_delegation(&root, "cpu", false)
            .expect("fixture delegation can be removed");
        let (mutation, original, identity) =
            workload_weight_mutation(1, &root, CpuWeight::new(200).expect("valid desired weight"));
        let plan = workload_plan(
            0x91,
            vec![(
                mutation,
                original,
                identity,
                sysboost_core::Feature::CgroupCpu,
                sysboost_core::ControlId::CgroupCpuWeight,
                sysboost_core::FeatureClass::RuntimeMutable,
            )],
        );
        let mut helper = workload_helper(WorkloadBackend::from_fixture(fixture), [0x91, 0x92]);
        let error = helper
            .prepare(&plan)
            .expect_err("privilege admission must reject undelegated controller");
        assert_eq!(error.code, ErrorCode::AuthorizationError);
    }
}
