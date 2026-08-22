//! Transaction coordinator for typed mutation backends.
//!
//! The coordinator is deliberately generic over the backend, durable state
//! store, lock, clock, and session-ID source.  Production composition roots
//! can wire the filesystem store and the reviewed Linux backend later; the
//! safety-critical behavior is exercised entirely with fake implementations.

use sysboost_core::{
    ErrorCode, MutationId, OperationState, Plan, RestoreReceipt, Retryability, SessionId,
    SessionRecord, SessionState, Snapshot, Stage, SysboostError, Timestamp, VerificationResult,
};

use crate::backend::MutationBackend;
use crate::clock::Clock;
use crate::state::{ExclusiveSessionLock, SessionIdSource, SessionStateStore};

/// Status returned by recovery and status inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionStatus {
    /// Session identity.
    pub session_id: SessionId,
    /// Durable overall state.
    pub state: SessionState,
}

struct ActiveLease<G> {
    session_id: SessionId,
    _guard: G,
}

/// Unforgeable capability held by [`TransactionEngine`] while it drives one
/// backend through the snapshot/apply/verify/restore lifecycle.
///
/// The type is public only because it appears in the public
/// [`MutationBackend`](crate::backend::MutationBackend) trait.  Its
/// constructor and field are private to this module, so neither a caller nor
/// another platform service can manufacture mutation-stage authority.
///
/// ```compile_fail
/// use sysboost_platform::BackendExecutionToken;
///
/// let _token = BackendExecutionToken::new();
/// ```
#[must_use]
#[derive(Debug)]
pub struct BackendExecutionToken {
    _private: (),
}

impl BackendExecutionToken {
    const fn new() -> Self {
        Self { _private: () }
    }
}

/// Generic transaction engine.  `B` is the only component that can perform a
/// typed mutation; it is never called until complete snapshots and durable
/// intent have been written.
pub struct TransactionEngine<B, S, L, G, C>
where
    B: MutationBackend,
    S: SessionStateStore,
    L: ExclusiveSessionLock,
    G: SessionIdSource,
    C: Clock,
{
    backend: B,
    state_store: S,
    lock: L,
    id_source: G,
    clock: C,
    execution: BackendExecutionToken,
    active: Option<ActiveLease<L::Guard>>,
}

impl<B, S, L, G, C> TransactionEngine<B, S, L, G, C>
where
    B: MutationBackend,
    S: SessionStateStore,
    L: ExclusiveSessionLock,
    G: SessionIdSource,
    C: Clock,
{
    /// Construct an engine from typed ports.
    pub fn new(backend: B, state_store: S, lock: L, id_source: G, clock: C) -> Self {
        Self {
            backend,
            state_store,
            lock,
            id_source,
            clock,
            execution: BackendExecutionToken::new(),
            active: None,
        }
    }

    /// Borrow the configured backend for deterministic fixture inspection.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Mutably borrow the configured backend for fixture setup or inspection.
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    /// Borrow the durable state store.
    pub fn state_store(&self) -> &S {
        &self.state_store
    }

    /// Mutably borrow the durable state store for test inspection.
    pub fn state_store_mut(&mut self) -> &mut S {
        &mut self.state_store
    }

    /// Prepare a complete typed plan: capture every preimage and persist the
    /// intent before returning a session ID.  No backend apply is possible in
    /// this method.
    pub fn prepare(&mut self, plan: &Plan) -> Result<SessionId, SysboostError> {
        if self.active.is_some() {
            return Err(SysboostError::new(
                ErrorCode::AuthorizationError,
                "this coordinator already owns a mutating session",
            )
            .retryable(Retryability::Retry));
        }
        plan.validate_complete()?;
        if plan.mutations.is_empty() {
            return Err(SysboostError::new(
                ErrorCode::AuthorizationError,
                "a report-only or no-op plan cannot enter the mutation engine",
            )
            .with_stage(Stage::Plan));
        }

        let guard = self.lock.acquire().map_err(|error| {
            error
                .with_stage(Stage::DurableIntent)
                .retryable(Retryability::Retry)
        })?;
        let unfinished = self
            .state_store
            .load_unfinished()
            .map_err(|error| error.with_stage(Stage::Recovery))?;
        if !unfinished.is_empty() {
            return Err(SysboostError::new(
                ErrorCode::AuthorizationError,
                "an unfinished session requires recovery before a new mutation",
            )
            .with_stage(Stage::Recovery)
            .retryable(Retryability::AfterRecovery));
        }

        let now = self
            .clock
            .now()
            .map_err(|error| error.with_stage(Stage::Detect))?;
        let mut snapshots = Vec::with_capacity(plan.mutations.len());
        for mutation in &plan.mutations {
            let snapshot = self
                .backend
                .snapshot(&self.execution, mutation, now)
                .map_err(|error| {
                    contextual(error, Stage::Snapshot, None, Some(mutation.mutation_id))
                })?;
            validate_snapshot(mutation, &snapshot)?;
            if snapshot.original_fingerprint != mutation.precondition {
                return Err(SysboostError::new(
                    ErrorCode::TargetError,
                    "target changed between planning and snapshot",
                )
                .with_stage(Stage::Snapshot)
                .with_mutation(mutation.mutation_id)
                .with_target(mutation.target.clone()));
            }
            snapshots.push(snapshot);
        }

        // A candidate collision is retried with a fresh ID.  The preimages
        // are independent of the session ID and remain valid for each
        // candidate record.
        for _attempt in 0..32 {
            let session_id = self
                .id_source
                .next_id()
                .map_err(|error| error.with_stage(Stage::DurableIntent))?;
            let session = sysboost_core::Session::new(session_id, plan, now);
            let mut record = SessionRecord::new(session, plan.mutations.clone())?;
            record.transition(SessionState::Detected, now, "capability evidence accepted")?;
            record.transition(SessionState::Planned, now, "complete typed plan accepted")?;
            for snapshot in &snapshots {
                record.capture_snapshot(snapshot.clone())?;
            }
            record.transition(
                SessionState::Snapshotted,
                now,
                "all original states captured",
            )?;
            record.record_intent()?;
            record.transition(
                SessionState::IntentDurable,
                now,
                "snapshots and mutation intent are durable",
            )?;

            match self.state_store.create(&record) {
                Ok(()) => {
                    self.active = Some(ActiveLease {
                        session_id,
                        _guard: guard,
                    });
                    return Ok(session_id);
                }
                Err(error) if error.code == ErrorCode::InvariantViolation => continue,
                Err(error) => {
                    return Err(contextual(
                        error,
                        Stage::DurableIntent,
                        Some(session_id),
                        None,
                    ));
                }
            }
        }
        Err(SysboostError::new(
            ErrorCode::InvariantViolation,
            "unable to allocate a unique boost session ID",
        )
        .with_stage(Stage::DurableIntent))
    }

    /// Abort a prepared session before any backend apply has been attempted.
    ///
    /// This is intentionally narrower than restore: it can remove only a
    /// durable intent whose every operation is still `IntentRecorded`.  The
    /// privilege boundary uses it when a backend-owned target identity does
    /// not match the planner's identity evidence after snapshot admission.
    pub fn abort_prepared(&mut self, session_id: SessionId) -> Result<(), SysboostError> {
        self.require_active(session_id)?;
        let record = self.load_active_record(session_id)?;
        if record.session.state != SessionState::IntentDurable
            || record
                .operations
                .iter()
                .any(|operation| operation.state != OperationState::IntentRecorded)
        {
            return Err(SysboostError::new(
                ErrorCode::InvariantViolation,
                "only an unapplied durable intent can be aborted",
            )
            .with_stage(Stage::DurableIntent)
            .with_session(session_id));
        }
        self.state_store
            .remove(session_id)
            .map_err(|error| contextual(error, Stage::DurableIntent, Some(session_id), None))?;
        self.active = None;
        Ok(())
    }

    /// Apply the prepared operations in their plan/dependency order.
    pub fn apply(&mut self, session_id: SessionId) -> Result<SessionState, SysboostError> {
        self.require_active(session_id)?;
        let mut record = self.load_active_record(session_id)?;
        match record.session.state {
            SessionState::IntentDurable => {}
            SessionState::Active => return Ok(SessionState::Active),
            SessionState::Restored => {
                self.release_if_restored(session_id);
                return Ok(SessionState::Restored);
            }
            state => {
                return Err(SysboostError::new(
                    ErrorCode::InvariantViolation,
                    format!("apply is not legal from durable state {state:?}"),
                )
                .with_stage(Stage::Apply)
                .with_session(session_id));
            }
        }

        record.transition(
            SessionState::Applying,
            self.now(Stage::Apply)?,
            "ordered mutation application started",
        )?;
        match self.persist(&record, Stage::Apply) {
            Ok(()) => {}
            Err(error) => {
                record.record_failure(&error);
                return self.rollback_after_failure(record, error, true);
            }
        }

        for index in 0..record.operations.len() {
            let operation_state = record.operations[index].state;
            if matches!(
                operation_state,
                OperationState::Verified | OperationState::Restored
            ) {
                continue;
            }
            if operation_state == OperationState::Applying {
                let error = SysboostError::new(
                    ErrorCode::JournalCorrupt,
                    "crash-state shows an apply with no durable completion",
                )
                .with_stage(Stage::Recovery)
                .with_session(session_id)
                .with_mutation(record.operations[index].mutation.mutation_id);
                record.record_failure(&error);
                return self.rollback_after_failure(record, error, true);
            }
            if operation_state != OperationState::IntentRecorded {
                let error = SysboostError::new(
                    ErrorCode::InvariantViolation,
                    "operation is not at durable intent before apply",
                )
                .with_stage(Stage::Apply)
                .with_session(session_id)
                .with_mutation(record.operations[index].mutation.mutation_id);
                record.record_failure(&error);
                return self.rollback_after_failure(record, error, true);
            }

            let mutation_id = record.operations[index].mutation.mutation_id;
            record.operations[index].transition(OperationState::Applying)?;
            if let Err(error) = self.persist(&record, Stage::Apply) {
                record.record_failure(&error);
                return self.rollback_after_failure(record, error, true);
            }
            let mutation = record.operations[index].mutation.clone();
            let snapshot = record.operations[index].snapshot.clone().ok_or_else(|| {
                SysboostError::new(
                    ErrorCode::InvariantViolation,
                    "durable intent operation is missing its snapshot",
                )
                .with_stage(Stage::Apply)
                .with_session(session_id)
                .with_mutation(mutation_id)
            })?;

            let receipt = match self.backend.apply(&self.execution, &mutation, &snapshot) {
                Ok(receipt) => receipt,
                Err(error) => {
                    let error =
                        contextual(error, Stage::Apply, Some(session_id), Some(mutation_id));
                    if error.retryability != Retryability::Unknown {
                        let _ = record.fail_operation(mutation_id, &error);
                    } else {
                        // An unknown apply result remains in Applying.  The
                        // receipt is absent, so recovery must not guess or
                        // issue an unowned restore write.
                        record.record_failure(&error);
                    }
                    let _ = self.persist(&record, Stage::Apply);
                    return self.rollback_after_failure(record, error, true);
                }
            };
            if receipt.mutation_id != mutation_id
                || receipt.observed_precondition != mutation.precondition
                || receipt.observed_postcondition != receipt.ownership_fingerprint
            {
                let error = SysboostError::new(
                    ErrorCode::ApplyError,
                    "backend apply receipt failed its typed identity or precondition checks",
                )
                .with_stage(Stage::Apply)
                .with_session(session_id)
                .with_mutation(mutation_id);
                record.record_apply(mutation_id, receipt)?;
                let _ = record.fail_operation(mutation_id, &error);
                let _ = self.persist(&record, Stage::Apply);
                return self.rollback_after_failure(record, error, true);
            }
            record.record_apply(mutation_id, receipt.clone())?;
            if let Err(error) = self.persist(&record, Stage::Apply) {
                record.record_failure(&error);
                return self.rollback_after_failure(record, error, true);
            }

            let verification = match self.backend.verify(
                &self.execution,
                &mutation,
                receipt.ownership_fingerprint,
                snapshot.target_identity,
            ) {
                Ok(observed) => VerificationResult {
                    mutation_id,
                    expected: receipt.ownership_fingerprint,
                    observed: Some(observed),
                    matched: observed == receipt.ownership_fingerprint,
                },
                Err(error) => {
                    let error =
                        contextual(error, Stage::Verify, Some(session_id), Some(mutation_id));
                    let verification = VerificationResult {
                        mutation_id,
                        expected: receipt.ownership_fingerprint,
                        observed: None,
                        matched: false,
                    };
                    record.record_verification(mutation_id, verification)?;
                    let _ = record.fail_operation(mutation_id, &error);
                    let _ = self.persist(&record, Stage::Verify);
                    return self.rollback_after_failure(record, error, true);
                }
            };
            if !verification.matched {
                let error = SysboostError::new(
                    ErrorCode::VerificationError,
                    "apply readback did not match the session-owned value",
                )
                .with_stage(Stage::Verify)
                .with_session(session_id)
                .with_mutation(mutation_id);
                record.record_verification(mutation_id, verification)?;
                let _ = record.fail_operation(mutation_id, &error);
                let _ = self.persist(&record, Stage::Verify);
                return self.rollback_after_failure(record, error, true);
            }
            record.record_verification(mutation_id, verification)?;
            if let Err(error) = self.persist(&record, Stage::Verify) {
                record.record_failure(&error);
                return self.rollback_after_failure(record, error, true);
            }
        }

        record.transition(
            SessionState::Active,
            self.now(Stage::Verify)?,
            "all ordered applies and readbacks verified",
        )?;
        if let Err(error) = self.persist(&record, Stage::Verify) {
            record.record_failure(&error);
            return self.rollback_after_failure(record, error, true);
        }
        Ok(SessionState::Active)
    }

    /// Restore a prepared session.  A second call is idempotent after the
    /// first call has durably proven `Restored`.
    pub fn restore(&mut self, session_id: SessionId) -> Result<SessionState, SysboostError> {
        if self.active.is_none() {
            match self.state_store.load(session_id) {
                Ok(record) if record.session.state == SessionState::Restored => {
                    return Ok(SessionState::Restored);
                }
                Ok(_) => {}
                Err(error) => {
                    return Err(contextual(error, Stage::Recovery, Some(session_id), None));
                }
            }
        }
        self.require_active(session_id)?;
        let mut record = self.load_active_record(session_id)?;
        if record.session.state == SessionState::Restored {
            self.release_if_restored(session_id);
            return Ok(SessionState::Restored);
        }
        self.prepare_restore_state(&mut record)?;
        let result = self.restore_record(&mut record, None);
        match result {
            Ok(state) => {
                if state == SessionState::Restored {
                    self.release_if_restored(session_id);
                }
                Ok(state)
            }
            Err(error) => Err(error),
        }
    }

    /// Replay all unfinished durable state after a process restart.  The
    /// global lock remains held if any session is degraded or recovery-pending.
    pub fn recover_unfinished(&mut self) -> Result<Vec<TransactionStatus>, SysboostError> {
        if self.active.is_some() {
            return Err(SysboostError::new(
                ErrorCode::AuthorizationError,
                "cannot recover while this coordinator owns an active session",
            ));
        }
        let guard = self.lock.acquire().map_err(|error| {
            error
                .with_stage(Stage::Recovery)
                .retryable(Retryability::Retry)
        })?;
        let mut records = self.state_store.load_unfinished()?;
        records.sort_by_key(|record| record.session.header.session_id);
        if records.is_empty() {
            return Ok(Vec::new());
        }
        let mut statuses = Vec::with_capacity(records.len());
        let mut first_error = None;
        for mut record in records {
            let session_id = record.session.header.session_id;
            if let Err(error) = self.prepare_restore_state(&mut record) {
                first_error.get_or_insert(error);
                statuses.push(TransactionStatus {
                    session_id,
                    state: record.session.state,
                });
                continue;
            }
            match self.restore_record(&mut record, None) {
                Ok(state) => statuses.push(TransactionStatus { session_id, state }),
                Err(error) => {
                    statuses.push(TransactionStatus {
                        session_id,
                        state: record.session.state,
                    });
                    first_error.get_or_insert(error);
                }
            }
        }
        if statuses
            .iter()
            .all(|status| status.state == SessionState::Restored)
            && first_error.is_none()
        {
            drop(guard);
            Ok(statuses)
        } else {
            // Keep ownership of the lock until the engine is dropped or a
            // caller explicitly retries through a new coordinator.  This
            // prevents a new session from racing unresolved recovery.
            let session_id = statuses
                .iter()
                .find(|status| status.state != SessionState::Restored)
                .map(|status| status.session_id)
                .unwrap_or(statuses[0].session_id);
            self.active = Some(ActiveLease {
                session_id,
                _guard: guard,
            });
            Err(first_error.unwrap_or_else(|| {
                SysboostError::new(
                    ErrorCode::RestoreError,
                    "one or more unfinished sessions remain unresolved",
                )
                .with_stage(Stage::Recovery)
                .with_session(session_id)
            }))
        }
    }

    /// Read one durable status without granting mutation authority.
    pub fn status(&self, session_id: SessionId) -> Result<TransactionStatus, SysboostError> {
        let record = self
            .state_store
            .load(session_id)
            .map_err(|error| contextual(error, Stage::Recovery, Some(session_id), None))?;
        Ok(TransactionStatus {
            session_id,
            state: record.session.state,
        })
    }

    fn require_active(&self, session_id: SessionId) -> Result<(), SysboostError> {
        match &self.active {
            Some(active) if active.session_id == session_id => Ok(()),
            Some(active) => Err(SysboostError::new(
                ErrorCode::AuthorizationError,
                "requested session is not owned by this coordinator",
            )
            .with_stage(Stage::Transport)
            .with_session(active.session_id)),
            None => Err(SysboostError::new(
                ErrorCode::AuthorizationError,
                "no mutating-session lease is held by this coordinator",
            )
            .with_stage(Stage::Transport)),
        }
    }

    fn load_active_record(&self, session_id: SessionId) -> Result<SessionRecord, SysboostError> {
        self.state_store
            .load(session_id)
            .map_err(|error| contextual(error, Stage::Recovery, Some(session_id), None))
    }

    fn persist(&mut self, record: &SessionRecord, stage: Stage) -> Result<(), SysboostError> {
        self.state_store
            .replace(record)
            .map_err(|error| contextual(error, stage, Some(record.session.header.session_id), None))
    }

    fn now(&self, stage: Stage) -> Result<Timestamp, SysboostError> {
        self.clock.now().map_err(|error| error.with_stage(stage))
    }

    fn prepare_restore_state(&mut self, record: &mut SessionRecord) -> Result<(), SysboostError> {
        let now = self.now(Stage::Restore)?;
        match record.session.state {
            SessionState::Active => {
                record.transition(SessionState::Restoring, now, "normal restore started")?
            }
            SessionState::Degraded => {
                record.transition(
                    SessionState::RecoveryPending,
                    now,
                    "retrying degraded restore",
                )?;
                record.transition(SessionState::Restoring, now, "recovery restore started")?;
            }
            SessionState::RecoveryPending => {
                record.transition(SessionState::Restoring, now, "recovery restore resumed")?;
            }
            SessionState::IntentDurable | SessionState::Applying | SessionState::RollingBack => {
                if record.session.state != SessionState::RollingBack {
                    record.transition(
                        SessionState::RollingBack,
                        now,
                        "rollback/recovery started",
                    )?;
                }
            }
            SessionState::Restoring => {}
            SessionState::Restored => return Ok(()),
            state => {
                return Err(SysboostError::new(
                    ErrorCode::InvariantViolation,
                    format!("restore is not legal from durable state {state:?}"),
                )
                .with_stage(Stage::Restore)
                .with_session(record.session.header.session_id));
            }
        }
        self.persist(record, Stage::Restore)
    }

    fn rollback_after_failure(
        &mut self,
        mut record: SessionRecord,
        trigger: SysboostError,
        from_apply: bool,
    ) -> Result<SessionState, SysboostError> {
        let session_id = record.session.header.session_id;
        if from_apply {
            let now = self
                .now(Stage::Recovery)
                .unwrap_or(Timestamp::from_unix_millis(0));
            let next = match record.session.state {
                SessionState::Applying | SessionState::IntentDurable => {
                    Some(SessionState::RollingBack)
                }
                SessionState::Active => Some(SessionState::Restoring),
                _ => None,
            };
            if let Some(next) = next {
                let reason = if next == SessionState::Restoring {
                    "apply durability failure triggered normal restore"
                } else {
                    "apply failure triggered reverse rollback"
                };
                if let Err(error) = record.transition(next, now, reason) {
                    record.record_failure(&error);
                }
            }
        }
        if let Err(error) = self.persist(&record, Stage::Recovery) {
            record.record_failure(&error);
        }
        let restore_result = self.restore_record(&mut record, Some(trigger.clone()));
        match restore_result {
            Ok(SessionState::Restored) => Err(trigger),
            Ok(state) => Err(SysboostError::new(
                ErrorCode::RestoreError,
                format!("transaction failed and ended in {state:?}"),
            )
            .with_stage(Stage::Recovery)
            .with_session(session_id)),
            Err(rollback_error) => Err(combine_failure(trigger, rollback_error, session_id)),
        }
    }

    fn restore_record(
        &mut self,
        record: &mut SessionRecord,
        _trigger: Option<SysboostError>,
    ) -> Result<SessionState, SysboostError> {
        let session_id = record.session.header.session_id;
        let mut failures = Vec::new();
        let mut uncertain = false;
        let now = self
            .now(Stage::Restore)
            .unwrap_or(Timestamp::from_unix_millis(0));

        for index in (0..record.operations.len()).rev() {
            let mutation_id = record.operations[index].mutation.mutation_id;
            if record.operations[index].state == OperationState::Restored {
                continue;
            }
            if record.operations[index].apply_receipt.is_none() {
                if record.operations[index].state == OperationState::Applying {
                    let error = SysboostError::new(
                        ErrorCode::JournalCorrupt,
                        "operation may have applied before its receipt became durable",
                    )
                    .with_stage(Stage::Recovery)
                    .with_session(session_id)
                    .with_mutation(mutation_id);
                    record.record_failure(&error);
                    failures.push(error);
                    uncertain = true;
                }
                continue;
            }
            let mutation = record.operations[index].mutation.clone();
            let snapshot = match record.operations[index].snapshot.clone() {
                Some(snapshot) => snapshot,
                None => {
                    let error = SysboostError::new(
                        ErrorCode::InvariantViolation,
                        "applied operation is missing its original snapshot",
                    )
                    .with_stage(Stage::Restore)
                    .with_session(session_id)
                    .with_mutation(mutation_id);
                    record.record_failure(&error);
                    failures.push(error);
                    uncertain = true;
                    continue;
                }
            };
            let ownership = record.operations[index]
                .apply_receipt
                .as_ref()
                .expect("receipt presence was checked")
                .ownership_fingerprint;
            if let Err(error) = record.begin_restore_operation(mutation_id) {
                failures.push(error);
                uncertain = true;
                continue;
            }
            if let Err(error) = self.persist(record, Stage::Restore) {
                record.record_failure(&error);
                failures.push(error);
                uncertain = true;
            }

            let current = match self.backend.verify(
                &self.execution,
                &mutation,
                snapshot.original_fingerprint,
                snapshot.target_identity,
            ) {
                Ok(observed) if observed == snapshot.original_fingerprint => {
                    let receipt = RestoreReceipt {
                        mutation_id,
                        restored_fingerprint: observed,
                        verified: true,
                    };
                    if let Err(error) = record.record_restore(mutation_id, receipt) {
                        failures.push(error);
                        uncertain = true;
                    } else if let Err(error) = self.persist(record, Stage::Restore) {
                        record.record_failure(&error);
                        failures.push(error);
                        uncertain = true;
                    }
                    continue;
                }
                Ok(observed) => observed,
                Err(error) => {
                    let error =
                        contextual(error, Stage::Restore, Some(session_id), Some(mutation_id));
                    let _ = record.fail_restore(mutation_id, &error);
                    let _ = self.persist(record, Stage::Restore);
                    failures.push(error);
                    continue;
                }
            };
            if current != ownership {
                let error = SysboostError::new(
                    ErrorCode::RestoreConflict,
                    "target changed outside the session; compare-and-restore refused to overwrite it",
                )
                .with_stage(Stage::Restore)
                .with_session(session_id)
                .with_mutation(mutation_id);
                let _ = record.fail_restore(mutation_id, &error);
                let _ = self.persist(record, Stage::Restore);
                failures.push(error);
                continue;
            }
            match self
                .backend
                .restore(&self.execution, &mutation, &snapshot, ownership)
            {
                Ok(receipt)
                    if receipt.mutation_id == mutation_id
                        && receipt.verified
                        && receipt.restored_fingerprint == snapshot.original_fingerprint =>
                {
                    if let Err(error) = record.record_restore(mutation_id, receipt) {
                        failures.push(error);
                        uncertain = true;
                    } else if let Err(error) = self.persist(record, Stage::Restore) {
                        record.record_failure(&error);
                        failures.push(error);
                        uncertain = true;
                    }
                }
                Ok(_) => {
                    let error = SysboostError::new(
                        ErrorCode::RestoreError,
                        "backend restore did not prove the original fingerprint",
                    )
                    .with_stage(Stage::Restore)
                    .with_session(session_id)
                    .with_mutation(mutation_id);
                    let _ = record.fail_restore(mutation_id, &error);
                    let _ = self.persist(record, Stage::Restore);
                    failures.push(error);
                }
                Err(error) => {
                    let error =
                        contextual(error, Stage::Restore, Some(session_id), Some(mutation_id));
                    let _ = record.fail_restore(mutation_id, &error);
                    let _ = self.persist(record, Stage::Restore);
                    failures.push(error);
                }
            }
        }

        if failures.is_empty() && record.restoration_proven() && !uncertain {
            if record.session.state != SessionState::Restored {
                let transition = if record.session.state == SessionState::Restoring {
                    SessionState::Restored
                } else {
                    // RollingBack is the normal partial-apply terminal path.
                    SessionState::Restored
                };
                record.transition(transition, now, "all captured originals verified")?;
            }
            self.persist(record, Stage::Restore)?;
            self.release_if_restored(session_id);
            return Ok(SessionState::Restored);
        }

        for error in &failures {
            record.record_failure(error);
        }
        if record.session.state == SessionState::Restoring
            || record.session.state == SessionState::RollingBack
        {
            record.transition(
                SessionState::Degraded,
                now,
                "one or more originals remain unproven",
            )?;
        }
        if uncertain {
            record.transition(
                SessionState::RecoveryPending,
                now,
                "crash or durability boundary left recovery uncertain",
            )?;
        }
        if let Err(error) = self.persist(record, Stage::Recovery) {
            failures.push(error);
        }
        let failure = failures.into_iter().next().unwrap_or_else(|| {
            SysboostError::new(
                ErrorCode::RestoreError,
                "original state could not be proven restored",
            )
            .with_stage(Stage::Restore)
            .with_session(session_id)
        });
        Err(failure)
    }

    fn release_if_restored(&mut self, session_id: SessionId) {
        if self
            .active
            .as_ref()
            .is_some_and(|active| active.session_id == session_id)
        {
            self.active = None;
        }
    }
}

fn validate_snapshot(
    mutation: &sysboost_core::PlannedMutation,
    snapshot: &Snapshot,
) -> Result<(), SysboostError> {
    if snapshot.mutation_id != mutation.mutation_id
        || snapshot.target != mutation.target
        || snapshot.equality != mutation.equality
    {
        return Err(SysboostError::new(
            ErrorCode::SnapshotError,
            "backend snapshot does not satisfy the typed mutation contract",
        )
        .with_stage(Stage::Snapshot)
        .with_mutation(mutation.mutation_id)
        .with_target(mutation.target.clone()));
    }
    Ok(())
}

fn contextual(
    error: SysboostError,
    stage: Stage,
    session_id: Option<SessionId>,
    mutation_id: Option<MutationId>,
) -> SysboostError {
    let error = error.with_stage(stage);
    let error = session_id.map_or(error.clone(), |session_id| error.with_session(session_id));
    mutation_id.map_or(error.clone(), |mutation_id| {
        error.with_mutation(mutation_id)
    })
}

fn combine_failure(
    trigger: SysboostError,
    rollback: SysboostError,
    session_id: SessionId,
) -> SysboostError {
    SysboostError::new(
        match rollback.code {
            ErrorCode::JournalCorrupt => ErrorCode::JournalCorrupt,
            ErrorCode::RestoreConflict => ErrorCode::RestoreConflict,
            _ => ErrorCode::RestoreError,
        },
        format!(
            "transaction failed with {}; rollback also failed with {}",
            trigger.code, rollback.code
        ),
    )
    .with_stage(Stage::Recovery)
    .with_session(session_id)
    .retryable(Retryability::AfterRecovery)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{FileSessionLock, FileStateStore, SystemSessionIdSource};

    // The deterministic executor and complete plans live in sysboost-testkit;
    // platform-level tests only verify the public wiring and state port types.
    #[test]
    fn status_type_keeps_session_identity_and_state_together() {
        let status = TransactionStatus {
            session_id: SessionId::from_bytes([1; 16]),
            state: SessionState::IntentDurable,
        };
        assert_eq!(status.session_id, SessionId::from_bytes([1; 16]));
        assert_eq!(status.state, SessionState::IntentDurable);
    }

    #[allow(dead_code)]
    fn production_types_are_constructible() {
        let _ = FileStateStore::production();
        let _ = FileSessionLock::production();
        let _ = SystemSessionIdSource::new();
    }
}
