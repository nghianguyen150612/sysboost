//! Durable transaction records and operation-level state.
//!
//! This module deliberately contains no filesystem or Linux knowledge.  It
//! owns the data that a trusted transaction coordinator must persist before a
//! typed mutation is allowed to run.  The binary codec is intentionally
//! closed: a state file can contain only the session, typed mutations,
//! snapshots, receipts, and bounded failure records represented here.

use crate::capability::EqualityKind;
use crate::error::{ErrorCode, Stage, SysboostError};
use crate::ids::{CapabilityId, MutationId, SessionId, TargetId};
use crate::mutation::{
    ApplyReceipt, ApprovedSysctlKey, ApprovedSysctlValue, BoundedBytes, CgroupGroupKind, CgroupId,
    CgroupName, CpuBoostState, CpuPeriod, CpuPolicyId, CpuQuota, CpuSet, CpuWeight,
    EnergyPreference, FrequencyKHz, GovernorId, GpuId, GpuProfile, IoPriority, IoPriorityClass,
    IoWeight, IrqId, MutationKind, NiceValue, PlannedMutation, PlatformProfileId, PowerMilliwatts,
    ProcessId, RestoreReceipt, Snapshot, StateFingerprint, TargetIdentity, TypedValue, UclampValue,
};
use crate::session::{Session, SessionHeader, SessionState, TransitionRecord};
use crate::time::Timestamp;

/// State-file format version.
pub const STATE_FORMAT_VERSION: u16 = 1;

/// Maximum encoded session record accepted by the decoder.
pub const MAX_SESSION_RECORD_BYTES: usize = 1_048_576;

const MAGIC: [u8; 8] = *b"SYSBST01";
const MAX_OPERATIONS: usize = 4096;
const MAX_TRANSITIONS: usize = 16_384;
const MAX_TARGETS: usize = 4096;
const MAX_DEPENDENCIES: usize = 4096;
const MAX_FAILURES: usize = 4096;
const MAX_STRING_BYTES: usize = 4096;
const MAX_REASON_BYTES: usize = 1024;

/// Explicit lifecycle of one typed operation inside a session.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OperationState {
    /// Operation exists in the pure plan.
    Planned,
    /// Its complete original preimage has been captured.
    Snapshotted,
    /// The snapshot and operation intent are durable.
    IntentRecorded,
    /// The backend call is in flight or its completion is not yet durable.
    Applying,
    /// The backend returned an apply receipt.
    Applied,
    /// The postcondition was read back and matched the receipt.
    Verified,
    /// Restoration is in progress.
    Restoring,
    /// The original value was read back and proven.
    Restored,
    /// Apply or verification failed.  A receipt, if present, remains
    /// authoritative for deciding whether rollback is required.
    Failed,
    /// Restoration failed and must be retried or reported as degraded.
    RestoreFailed,
}

impl OperationState {
    /// Check the legal operation-level lifecycle transitions.
    pub const fn can_transition(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Planned, Self::Snapshotted)
                | (Self::Snapshotted, Self::IntentRecorded)
                | (Self::IntentRecorded, Self::Applying)
                | (Self::Applying, Self::Applied)
                | (Self::Applying, Self::Failed)
                | (Self::Applied, Self::Verified)
                | (Self::Applied, Self::Failed)
                | (Self::Verified, Self::Restoring)
                | (Self::Applied, Self::Restoring)
                | (Self::Applying, Self::Restoring)
                | (Self::Failed, Self::Restoring)
                | (Self::Restoring, Self::Restored)
                | (Self::Restoring, Self::RestoreFailed)
                | (Self::RestoreFailed, Self::Restoring)
        )
    }

    /// Whether this state proves the operation's original value was restored.
    pub const fn is_restored(self) -> bool {
        matches!(self, Self::Restored)
    }
}

/// Result of a separate postcondition or ownership readback.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct VerificationResult {
    /// Mutation that was read.
    pub mutation_id: MutationId,
    /// Fingerprint the caller expected.
    pub expected: StateFingerprint,
    /// Fingerprint observed, when the backend completed a read.
    pub observed: Option<StateFingerprint>,
    /// Whether the declared equality contract matched.
    pub matched: bool,
}

/// A bounded, serializable failure attached to a session or operation.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct FailureRecord {
    /// Stable category.
    pub code: ErrorCode,
    /// Transaction stage.
    pub stage: Stage,
    /// Mutation involved, if any.
    pub mutation_id: Option<MutationId>,
    /// Bounded explanation without raw host paths or commands.
    pub message: String,
}

impl FailureRecord {
    /// Create a bounded failure record from a structured domain error.
    pub fn from_error(error: &SysboostError) -> Self {
        let message = truncate_text(&error.message, MAX_REASON_BYTES);
        Self {
            code: error.code,
            stage: error.context.stage.unwrap_or(Stage::Recovery),
            mutation_id: error.context.mutation_id,
            message,
        }
    }
}

fn truncate_text(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

/// Persisted state for one planned operation.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct OperationRecord {
    /// Typed operation and immutable precondition.
    pub mutation: PlannedMutation,
    /// Current operation lifecycle state.
    pub state: OperationState,
    /// Complete original snapshot, once captured.
    pub snapshot: Option<Snapshot>,
    /// Apply receipt, once the backend reports an apply.
    pub apply_receipt: Option<ApplyReceipt>,
    /// Last postcondition/ownership verification result.
    pub verification: Option<VerificationResult>,
    /// Restore receipt, once the original is proven.
    pub restore_receipt: Option<RestoreReceipt>,
    /// Operation-local failure, if one occurred.
    pub failure: Option<FailureRecord>,
}

impl OperationRecord {
    /// Construct a planned operation record.
    pub fn planned(mutation: PlannedMutation) -> Self {
        Self {
            mutation,
            state: OperationState::Planned,
            snapshot: None,
            apply_receipt: None,
            verification: None,
            restore_receipt: None,
            failure: None,
        }
    }

    /// Apply a legal operation-state transition.
    pub fn transition(&mut self, next: OperationState) -> Result<(), SysboostError> {
        if !self.state.can_transition(next) {
            return Err(invariant_error(
                "illegal operation state transition",
                self.mutation.mutation_id,
            ));
        }
        self.state = next;
        Ok(())
    }

    /// Whether this operation may need restoration after a crash or failure.
    pub fn needs_restore(&self) -> bool {
        self.apply_receipt.is_some() && !self.state.is_restored()
    }

    /// Return a failure-aware error for this operation.
    pub fn failure_error(&self) -> Option<SysboostError> {
        self.failure.as_ref().map(|failure| {
            SysboostError::new(failure.code, failure.message.clone())
                .with_stage(failure.stage)
                .with_mutation(self.mutation.mutation_id)
        })
    }
}

/// Complete durable state for one boost session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionRecord {
    /// Session header and overall state.
    pub session: Session,
    /// Ordered operation records.  Their order is the apply order.
    pub operations: Vec<OperationRecord>,
    /// Append-only session state transitions.
    pub transitions: Vec<TransitionRecord>,
    /// All failures observed while applying or recovering.
    pub failures: Vec<FailureRecord>,
}

impl SessionRecord {
    /// Construct a record from a planned mutation list.
    pub fn new(session: Session, mutations: Vec<PlannedMutation>) -> Result<Self, SysboostError> {
        if mutations.is_empty() {
            return Err(SysboostError::new(
                ErrorCode::PlanningError,
                "a durable transaction must contain at least one mutation",
            )
            .with_stage(Stage::Plan));
        }
        if mutations.len() > MAX_OPERATIONS {
            return Err(SysboostError::new(
                ErrorCode::PlanningError,
                "transaction contains too many mutations",
            )
            .with_stage(Stage::Plan));
        }
        let mut seen = Vec::with_capacity(mutations.len());
        let operations = mutations
            .into_iter()
            .map(|mutation| {
                if seen.contains(&mutation.mutation_id) {
                    return Err(invariant_error(
                        "durable transaction contains duplicate mutation IDs",
                        mutation.mutation_id,
                    ));
                }
                seen.push(mutation.mutation_id);
                Ok(OperationRecord::planned(mutation))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            session,
            operations,
            transitions: Vec::new(),
            failures: Vec::new(),
        })
    }

    /// Append one overall session transition and retain its sequence.
    pub fn transition(
        &mut self,
        next: SessionState,
        at: Timestamp,
        reason: impl Into<String>,
    ) -> Result<(), SysboostError> {
        let reason = reason.into();
        if reason.is_empty() || reason.len() > MAX_REASON_BYTES || reason.contains('\0') {
            return Err(SysboostError::new(
                ErrorCode::InvalidInput,
                "session transition reason is empty or oversized",
            )
            .with_stage(Stage::Recovery)
            .with_session(self.session.header.session_id));
        }
        let from = self.session.state;
        self.session.transition(next)?;
        let sequence = self
            .transitions
            .last()
            .map_or(1, |transition| transition.sequence.saturating_add(1));
        self.transitions.push(TransitionRecord {
            sequence,
            session_id: self.session.header.session_id,
            from,
            to: next,
            at,
            reason,
        });
        Ok(())
    }

    /// Capture one complete original state.
    pub fn capture_snapshot(&mut self, snapshot: Snapshot) -> Result<(), SysboostError> {
        let operation = self.operation_mut(snapshot.mutation_id)?;
        if snapshot.target != operation.mutation.target
            || snapshot.equality != operation.mutation.equality
            || snapshot.original_fingerprint != operation.mutation.precondition
            || snapshot.target_identity.as_bytes() == &[0; 16]
        {
            return Err(SysboostError::new(
                ErrorCode::SnapshotError,
                "snapshot identity, equality, precondition, or target token is invalid",
            )
            .with_stage(Stage::Snapshot)
            .with_mutation(snapshot.mutation_id)
            .with_target(operation.mutation.target.clone()));
        }
        if operation.snapshot.is_some() || operation.state != OperationState::Planned {
            return Err(invariant_error(
                "operation snapshot was captured more than once or at the wrong stage",
                snapshot.mutation_id,
            ));
        }
        operation.snapshot = Some(snapshot);
        operation.transition(OperationState::Snapshotted)
    }

    /// Mark all captured operations as part of durable intent.
    pub fn record_intent(&mut self) -> Result<(), SysboostError> {
        if self
            .operations
            .iter()
            .any(|operation| operation.state != OperationState::Snapshotted)
        {
            return Err(SysboostError::new(
                ErrorCode::InvariantViolation,
                "durable intent requires a complete snapshot for every operation",
            )
            .with_stage(Stage::DurableIntent)
            .with_session(self.session.header.session_id));
        }
        for operation in &mut self.operations {
            operation.transition(OperationState::IntentRecorded)?;
        }
        Ok(())
    }

    /// Attach an apply receipt to an operation.
    pub fn record_apply(
        &mut self,
        mutation_id: MutationId,
        receipt: ApplyReceipt,
    ) -> Result<(), SysboostError> {
        let operation = self.operation_mut(mutation_id)?;
        if receipt.mutation_id != mutation_id {
            return Err(invariant_error(
                "apply receipt mutation ID does not match the operation",
                mutation_id,
            ));
        }
        operation.apply_receipt = Some(receipt);
        operation.transition(OperationState::Applied)
    }

    /// Attach a postcondition readback result and advance to verified state.
    pub fn record_verification(
        &mut self,
        mutation_id: MutationId,
        verification: VerificationResult,
    ) -> Result<(), SysboostError> {
        let operation = self.operation_mut(mutation_id)?;
        if verification.mutation_id != mutation_id {
            return Err(invariant_error(
                "verification mutation ID does not match the operation",
                mutation_id,
            ));
        }
        operation.verification = Some(verification.clone());
        if verification.matched {
            operation.transition(OperationState::Verified)
        } else {
            operation.transition(OperationState::Failed)
        }
    }

    /// Mark one operation as failed and retain the structured reason.
    pub fn fail_operation(
        &mut self,
        mutation_id: MutationId,
        error: &SysboostError,
    ) -> Result<(), SysboostError> {
        let operation = self.operation_mut(mutation_id)?;
        operation.failure = Some(FailureRecord::from_error(error));
        if operation.state != OperationState::Failed {
            operation.transition(OperationState::Failed)?;
        }
        self.failures.push(FailureRecord::from_error(error));
        Ok(())
    }

    /// Move one applied operation into restoration.
    pub fn begin_restore_operation(
        &mut self,
        mutation_id: MutationId,
    ) -> Result<(), SysboostError> {
        let operation = self.operation_mut(mutation_id)?;
        if operation.state == OperationState::Restored {
            return Ok(());
        }
        operation.transition(OperationState::Restoring)
    }

    /// Record a successful original-state verification.
    pub fn record_restore(
        &mut self,
        mutation_id: MutationId,
        receipt: RestoreReceipt,
    ) -> Result<(), SysboostError> {
        let operation = self.operation_mut(mutation_id)?;
        if receipt.mutation_id != mutation_id || !receipt.verified {
            return Err(invariant_error(
                "restore receipt is not a verified receipt for the operation",
                mutation_id,
            ));
        }
        operation.restore_receipt = Some(receipt);
        operation.transition(OperationState::Restored)
    }

    /// Mark a restore failure while retaining the apply receipt for retry.
    pub fn fail_restore(
        &mut self,
        mutation_id: MutationId,
        error: &SysboostError,
    ) -> Result<(), SysboostError> {
        let operation = self.operation_mut(mutation_id)?;
        operation.failure = Some(FailureRecord::from_error(error));
        if operation.state != OperationState::RestoreFailed {
            operation.transition(OperationState::RestoreFailed)?;
        }
        self.failures.push(FailureRecord::from_error(error));
        Ok(())
    }

    /// Retain a session-level failure.
    pub fn record_failure(&mut self, error: &SysboostError) {
        self.failures.push(FailureRecord::from_error(error));
    }

    /// Look up an operation by ID.
    pub fn operation(&self, mutation_id: MutationId) -> Result<&OperationRecord, SysboostError> {
        self.operations
            .iter()
            .find(|operation| operation.mutation.mutation_id == mutation_id)
            .ok_or_else(|| {
                invariant_error(
                    "operation ID is absent from the session record",
                    mutation_id,
                )
            })
    }

    /// Look up a mutable operation by ID.
    pub fn operation_mut(
        &mut self,
        mutation_id: MutationId,
    ) -> Result<&mut OperationRecord, SysboostError> {
        self.operations
            .iter_mut()
            .find(|operation| operation.mutation.mutation_id == mutation_id)
            .ok_or_else(|| {
                invariant_error(
                    "operation ID is absent from the session record",
                    mutation_id,
                )
            })
    }

    /// Return whether every operation with a receipt is proven restored and no
    /// operation is left in the crash-ambiguous `Applying` state.
    pub fn restoration_proven(&self) -> bool {
        self.operations.iter().all(|operation| {
            !operation.needs_restore()
                && operation.state != OperationState::Applying
                && operation.state != OperationState::RestoreFailed
        })
    }

    /// Encode a bounded, checksummed state record.
    pub fn encode(&self) -> Result<Vec<u8>, SysboostError> {
        self.validate_for_serialization()?;
        let mut payload = Encoder::default();
        encode_session(&mut payload, &self.session)?;
        put_count(&mut payload, self.operations.len(), MAX_OPERATIONS)?;
        for operation in &self.operations {
            encode_operation(&mut payload, operation)?;
        }
        put_count(&mut payload, self.transitions.len(), MAX_TRANSITIONS)?;
        for transition in &self.transitions {
            encode_transition(&mut payload, transition)?;
        }
        put_count(&mut payload, self.failures.len(), MAX_FAILURES)?;
        for failure in &self.failures {
            encode_failure(&mut payload, failure)?;
        }

        let payload = payload.finish();
        let total = MAGIC.len() + 2 + 4 + payload.len() + 32;
        if total > MAX_SESSION_RECORD_BYTES {
            return Err(SysboostError::new(
                ErrorCode::DurabilityError,
                "session record exceeds the durable state-file bound",
            )
            .with_stage(Stage::DurableIntent)
            .with_session(self.session.header.session_id));
        }
        let mut output = Vec::with_capacity(total);
        output.extend_from_slice(&MAGIC);
        output.extend_from_slice(&STATE_FORMAT_VERSION.to_be_bytes());
        output.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        output.extend_from_slice(&payload);
        output.extend_from_slice(&checksum(&payload));
        Ok(output)
    }

    /// Decode and validate a checksummed state record.
    pub fn decode(bytes: &[u8]) -> Result<Self, SysboostError> {
        if bytes.len() > MAX_SESSION_RECORD_BYTES || bytes.len() < MAGIC.len() + 2 + 4 + 32 {
            return Err(corrupt("state record length is invalid"));
        }
        if bytes[..MAGIC.len()] != MAGIC {
            return Err(corrupt("state record magic is invalid"));
        }
        let version_offset = MAGIC.len();
        let version = u16::from_be_bytes([bytes[version_offset], bytes[version_offset + 1]]);
        if version != STATE_FORMAT_VERSION {
            return Err(corrupt("state record version is unsupported"));
        }
        let length_offset = version_offset + 2;
        let payload_len = u32::from_be_bytes([
            bytes[length_offset],
            bytes[length_offset + 1],
            bytes[length_offset + 2],
            bytes[length_offset + 3],
        ]) as usize;
        let payload_start = length_offset + 4;
        let payload_end = payload_start
            .checked_add(payload_len)
            .ok_or_else(|| corrupt("state payload length overflows"))?;
        if payload_end + 32 != bytes.len() {
            return Err(corrupt("state payload length does not match the file"));
        }
        let payload = &bytes[payload_start..payload_end];
        if checksum(payload) != bytes[payload_end..] {
            return Err(corrupt("state record checksum does not match"));
        }

        let mut decoder = Decoder::new(payload);
        let session = decode_session(&mut decoder)?;
        let operation_count = decoder.count(MAX_OPERATIONS)?;
        let mut operations = Vec::with_capacity(operation_count);
        for _ in 0..operation_count {
            operations.push(decode_operation(&mut decoder)?);
        }
        let transition_count = decoder.count(MAX_TRANSITIONS)?;
        let mut transitions = Vec::with_capacity(transition_count);
        for _ in 0..transition_count {
            transitions.push(decode_transition(&mut decoder)?);
        }
        let failure_count = decoder.count(MAX_FAILURES)?;
        let mut failures = Vec::with_capacity(failure_count);
        for _ in 0..failure_count {
            failures.push(decode_failure(&mut decoder)?);
        }
        decoder.finish()?;
        let record = Self {
            session,
            operations,
            transitions,
            failures,
        };
        record.validate_for_serialization()?;
        Ok(record)
    }

    fn validate_for_serialization(&self) -> Result<(), SysboostError> {
        if self.operations.is_empty() || self.operations.len() > MAX_OPERATIONS {
            return Err(corrupt("session record has an invalid operation count"));
        }
        if self.transitions.len() > MAX_TRANSITIONS || self.failures.len() > MAX_FAILURES {
            return Err(corrupt("session record has too many journal records"));
        }
        if self.session.header.targets.len() > MAX_TARGETS {
            return Err(corrupt("session record has too many target leases"));
        }
        let mut ids = Vec::with_capacity(self.operations.len());
        for operation in &self.operations {
            if ids.contains(&operation.mutation.mutation_id) {
                return Err(corrupt("session record contains duplicate mutation IDs"));
            }
            ids.push(operation.mutation.mutation_id);
            if let Some(snapshot) = &operation.snapshot {
                if snapshot.mutation_id != operation.mutation.mutation_id
                    || snapshot.target != operation.mutation.target
                    || snapshot.equality != operation.mutation.equality
                {
                    return Err(corrupt("snapshot does not match its operation"));
                }
            }
            if let Some(receipt) = &operation.apply_receipt {
                if receipt.mutation_id != operation.mutation.mutation_id {
                    return Err(corrupt("apply receipt does not match its operation"));
                }
            }
            if let Some(verification) = &operation.verification {
                if verification.mutation_id != operation.mutation.mutation_id {
                    return Err(corrupt("verification does not match its operation"));
                }
            }
            if let Some(receipt) = &operation.restore_receipt {
                if receipt.mutation_id != operation.mutation.mutation_id {
                    return Err(corrupt("restore receipt does not match its operation"));
                }
            }
            validate_operation_record(operation)?;
        }
        if self.session.header.targets.len() != self.operations.len() {
            return Err(corrupt(
                "session target leases do not match the operation count",
            ));
        }
        for (target, operation) in self.session.header.targets.iter().zip(&self.operations) {
            if target != &operation.mutation.target {
                return Err(corrupt("session target lease does not match its operation"));
            }
        }
        for transition in &self.transitions {
            if transition.session_id != self.session.header.session_id {
                return Err(corrupt("transition belongs to another session"));
            }
        }
        let mut state = SessionState::New;
        let mut sequence = 1_u64;
        for transition in &self.transitions {
            if transition.sequence != sequence
                || transition.from != state
                || !state.can_transition(transition.to)
            {
                return Err(corrupt("session transition sequence or state is invalid"));
            }
            state = transition.to;
            sequence = sequence
                .checked_add(1)
                .ok_or_else(|| corrupt("session transition sequence overflows"))?;
        }
        if state != self.session.state {
            return Err(corrupt(
                "session state does not match the durable transition chain",
            ));
        }
        Ok(())
    }
}

fn validate_operation_record(operation: &OperationRecord) -> Result<(), SysboostError> {
    let snapshot = operation.snapshot.as_ref();
    let apply = operation.apply_receipt.as_ref();
    let verification = operation.verification.as_ref();
    let restore = operation.restore_receipt.as_ref();

    if let Some(snapshot) = snapshot {
        if snapshot.original_fingerprint != operation.mutation.precondition
            || snapshot.target_identity.as_bytes() == &[0; 16]
        {
            return Err(corrupt(
                "operation snapshot does not preserve its planned precondition or identity",
            ));
        }
    }
    if let Some(receipt) = apply {
        if snapshot.is_none()
            || receipt.observed_precondition != operation.mutation.precondition
            || receipt.observed_postcondition != receipt.ownership_fingerprint
        {
            return Err(corrupt(
                "apply receipt is not bound to the operation preimage",
            ));
        }
    }
    if let Some(verification) = verification {
        let Some(receipt) = apply else {
            return Err(corrupt("verification exists without an apply receipt"));
        };
        if verification.expected != receipt.ownership_fingerprint
            || (verification.matched && verification.observed != Some(verification.expected))
            || (!verification.matched && verification.observed == Some(verification.expected))
        {
            return Err(corrupt(
                "verification result is not bound to its apply receipt",
            ));
        }
    }
    if let Some(restore) = restore {
        let Some(snapshot) = snapshot else {
            return Err(corrupt("restore receipt exists without a snapshot"));
        };
        if apply.is_none()
            || !restore.verified
            || restore.restored_fingerprint != snapshot.original_fingerprint
        {
            return Err(corrupt(
                "restore receipt does not prove the captured original",
            ));
        }
    }

    match operation.state {
        OperationState::Planned => {
            if snapshot.is_some() || apply.is_some() || verification.is_some() || restore.is_some()
            {
                return Err(corrupt("planned operation contains post-plan state"));
            }
        }
        OperationState::Snapshotted | OperationState::IntentRecorded => {
            if snapshot.is_none() || apply.is_some() || verification.is_some() || restore.is_some()
            {
                return Err(corrupt(
                    "snapshotted operation does not have the expected durable shape",
                ));
            }
        }
        OperationState::Applying => {
            if snapshot.is_none() || apply.is_some() || verification.is_some() || restore.is_some()
            {
                return Err(corrupt("ambiguous applying operation has invalid receipts"));
            }
        }
        OperationState::Applied => {
            if snapshot.is_none() || apply.is_none() || verification.is_some() || restore.is_some()
            {
                return Err(corrupt(
                    "applied operation does not have the expected receipt shape",
                ));
            }
        }
        OperationState::Verified => {
            if snapshot.is_none()
                || apply.is_none()
                || verification.is_none()
                || !verification.is_some_and(|value| value.matched)
                || restore.is_some()
            {
                return Err(corrupt("verified operation is not fully read back"));
            }
        }
        OperationState::Restoring => {
            if snapshot.is_none() || apply.is_none() || restore.is_some() {
                return Err(corrupt("restoring operation lacks its apply ownership"));
            }
        }
        OperationState::Restored => {
            if snapshot.is_none() || apply.is_none() || restore.is_none() {
                return Err(corrupt("restored operation lacks a proven original"));
            }
        }
        OperationState::Failed => {
            if snapshot.is_none()
                || restore.is_some()
                || verification.is_some_and(|value| value.matched)
            {
                return Err(corrupt(
                    "failed operation has an invalid preimage/restore shape",
                ));
            }
        }
        OperationState::RestoreFailed => {
            if snapshot.is_none() || apply.is_none() || restore.is_some() {
                return Err(corrupt("restore-failed operation lacks retry ownership"));
            }
        }
    }
    Ok(())
}

fn invariant_error(message: &str, mutation_id: MutationId) -> SysboostError {
    SysboostError::new(ErrorCode::InvariantViolation, message)
        .with_stage(Stage::Recovery)
        .with_mutation(mutation_id)
}

fn corrupt(message: &str) -> SysboostError {
    SysboostError::new(ErrorCode::JournalCorrupt, message).with_stage(Stage::Recovery)
}

#[derive(Default)]
struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u128(&mut self, value: u128) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn i64(&mut self, value: i64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn fixed<const N: usize>(&mut self, value: &[u8; N]) {
        self.bytes.extend_from_slice(value);
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), SysboostError> {
        if value.len() > u32::MAX as usize {
            return Err(corrupt("encoded byte field exceeds the u32 bound"));
        }
        self.u32(value.len() as u32);
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn string(&mut self, value: &str, max: usize) -> Result<(), SysboostError> {
        if value.is_empty() || value.len() > max || value.contains('\0') {
            return Err(corrupt(
                "encoded string is empty, oversized, or contains NUL",
            ));
        }
        self.bytes(value.as_bytes())
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], SysboostError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or_else(|| corrupt("state cursor overflow"))?;
        if end > self.bytes.len() {
            return Err(corrupt("state record is truncated"));
        }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, SysboostError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, SysboostError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32, SysboostError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u64(&mut self) -> Result<u64, SysboostError> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn u128(&mut self) -> Result<u128, SysboostError> {
        let bytes = self.take(16)?;
        Ok(u128::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]))
    }

    fn i64(&mut self) -> Result<i64, SysboostError> {
        Ok(i64::from_be_bytes(
            self.take(8)?.try_into().expect("fixed-size state field"),
        ))
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], SysboostError> {
        Ok(self.take(N)?.try_into().expect("fixed-size state field"))
    }

    fn bytes(&mut self, max: usize) -> Result<Vec<u8>, SysboostError> {
        let length = self.u32()? as usize;
        if length > max {
            return Err(corrupt("state byte field exceeds its bound"));
        }
        Ok(self.take(length)?.to_vec())
    }

    fn string(&mut self, max: usize) -> Result<String, SysboostError> {
        let bytes = self.bytes(max)?;
        let value = String::from_utf8(bytes).map_err(|_| corrupt("state string is not UTF-8"))?;
        if value.is_empty() || value.contains('\0') {
            return Err(corrupt("state string is empty or contains NUL"));
        }
        Ok(value)
    }

    fn count(&mut self, max: usize) -> Result<usize, SysboostError> {
        let count = self.u32()? as usize;
        if count > max {
            return Err(corrupt("state collection exceeds its bound"));
        }
        Ok(count)
    }

    fn finish(&self) -> Result<(), SysboostError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(corrupt("state record contains trailing bytes"))
        }
    }
}

fn put_count(encoder: &mut Encoder, count: usize, max: usize) -> Result<(), SysboostError> {
    if count > max || count > u32::MAX as usize {
        return Err(corrupt("state collection exceeds its bound"));
    }
    encoder.u32(count as u32);
    Ok(())
}

fn encode_session(encoder: &mut Encoder, session: &Session) -> Result<(), SysboostError> {
    encoder.fixed(session.header.session_id.as_bytes());
    encoder.fixed(session.header.plan_id.as_bytes());
    encoder.fixed(&session.header.plan_digest);
    encoder.u128(session.header.created_at.as_unix_millis());
    encode_session_state(encoder, session.state);
    put_count(encoder, session.header.targets.len(), MAX_TARGETS)?;
    for target in &session.header.targets {
        encoder.string(target.as_str(), MAX_STRING_BYTES)?;
    }
    Ok(())
}

fn decode_session(decoder: &mut Decoder<'_>) -> Result<Session, SysboostError> {
    let session_id = SessionId::from_bytes(decoder.fixed()?);
    let plan_id = crate::ids::PlanId::from_bytes(decoder.fixed()?);
    let plan_digest = decoder.fixed()?;
    let created_at = Timestamp::from_unix_millis(decoder.u128()?);
    let state = decode_session_state(decoder.u8()?)?;
    let count = decoder.count(MAX_TARGETS)?;
    let mut targets = Vec::with_capacity(count);
    for _ in 0..count {
        targets.push(
            TargetId::new(decoder.string(MAX_STRING_BYTES)?)
                .map_err(|_| corrupt("state target identifier is invalid"))?,
        );
    }
    Ok(Session {
        header: SessionHeader {
            session_id,
            plan_id,
            plan_digest,
            created_at,
            targets,
        },
        state,
    })
}

fn encode_operation(
    encoder: &mut Encoder,
    operation: &OperationRecord,
) -> Result<(), SysboostError> {
    encode_mutation(encoder, &operation.mutation)?;
    encode_operation_state(encoder, operation.state);
    encode_optional(encoder, operation.snapshot.is_some());
    if let Some(snapshot) = &operation.snapshot {
        encode_snapshot(encoder, snapshot)?;
    }
    encode_optional(encoder, operation.apply_receipt.is_some());
    if let Some(receipt) = &operation.apply_receipt {
        encode_apply_receipt(encoder, receipt);
    }
    encode_optional(encoder, operation.verification.is_some());
    if let Some(verification) = &operation.verification {
        encode_verification(encoder, verification);
    }
    encode_optional(encoder, operation.restore_receipt.is_some());
    if let Some(receipt) = &operation.restore_receipt {
        encode_restore_receipt(encoder, receipt);
    }
    encode_optional(encoder, operation.failure.is_some());
    if let Some(failure) = &operation.failure {
        encode_failure(encoder, failure)?;
    }
    Ok(())
}

fn decode_operation(decoder: &mut Decoder<'_>) -> Result<OperationRecord, SysboostError> {
    let mutation = decode_mutation(decoder)?;
    let state = decode_operation_state(decoder.u8()?)?;
    let snapshot = if decoder.u8()? != 0 {
        Some(decode_snapshot(decoder)?)
    } else {
        None
    };
    let apply_receipt = if decoder.u8()? != 0 {
        Some(decode_apply_receipt(decoder)?)
    } else {
        None
    };
    let verification = if decoder.u8()? != 0 {
        Some(decode_verification(decoder)?)
    } else {
        None
    };
    let restore_receipt = if decoder.u8()? != 0 {
        Some(decode_restore_receipt(decoder)?)
    } else {
        None
    };
    let failure = if decoder.u8()? != 0 {
        Some(decode_failure(decoder)?)
    } else {
        None
    };
    Ok(OperationRecord {
        mutation,
        state,
        snapshot,
        apply_receipt,
        verification,
        restore_receipt,
        failure,
    })
}

fn encode_mutation(encoder: &mut Encoder, mutation: &PlannedMutation) -> Result<(), SysboostError> {
    encoder.u32(mutation.mutation_id.get());
    encoder.string(mutation.capability.as_str(), MAX_STRING_BYTES)?;
    encoder.string(mutation.target.as_str(), MAX_STRING_BYTES)?;
    encode_mutation_kind(encoder, &mutation.kind)?;
    encode_typed_value(encoder, &mutation.desired)?;
    encoder.fixed(mutation.precondition.as_bytes());
    encode_equality(encoder, mutation.equality);
    put_count(encoder, mutation.dependencies.len(), MAX_DEPENDENCIES)?;
    for dependency in &mutation.dependencies {
        encoder.u32(dependency.get());
    }
    Ok(())
}

fn decode_mutation(decoder: &mut Decoder<'_>) -> Result<PlannedMutation, SysboostError> {
    let mutation_id = crate::ids::MutationId::new(decoder.u32()?);
    let capability = CapabilityId::new(decoder.string(MAX_STRING_BYTES)?)
        .map_err(|_| corrupt("state capability identifier is invalid"))?;
    let target = TargetId::new(decoder.string(MAX_STRING_BYTES)?)
        .map_err(|_| corrupt("state target identifier is invalid"))?;
    let kind = decode_mutation_kind(decoder)?;
    let desired = decode_typed_value(decoder)?;
    let precondition = StateFingerprint::from_bytes(decoder.fixed()?);
    let equality = decode_equality(decoder.u8()?)?;
    let dependency_count = decoder.count(MAX_DEPENDENCIES)?;
    let mut dependencies = Vec::with_capacity(dependency_count);
    for _ in 0..dependency_count {
        dependencies.push(MutationId::new(decoder.u32()?));
    }
    PlannedMutation::new(
        mutation_id,
        capability,
        target,
        kind,
        desired,
        precondition,
        equality,
        dependencies,
    )
    .map_err(|_| corrupt("state mutation is not a valid typed mutation"))
}

fn encode_snapshot(encoder: &mut Encoder, snapshot: &Snapshot) -> Result<(), SysboostError> {
    encoder.u32(snapshot.mutation_id.get());
    encoder.string(snapshot.target.as_str(), MAX_STRING_BYTES)?;
    encoder.bytes(snapshot.original_raw.as_slice())?;
    encode_typed_value(encoder, &snapshot.original_typed)?;
    encoder.fixed(snapshot.original_fingerprint.as_bytes());
    encode_equality(encoder, snapshot.equality);
    encoder.fixed(snapshot.target_identity.as_bytes());
    encoder.u128(snapshot.captured_at.as_unix_millis());
    Ok(())
}

fn decode_snapshot(decoder: &mut Decoder<'_>) -> Result<Snapshot, SysboostError> {
    let mutation_id = MutationId::new(decoder.u32()?);
    let target = TargetId::new(decoder.string(MAX_STRING_BYTES)?)
        .map_err(|_| corrupt("state snapshot target is invalid"))?;
    let original_raw = BoundedBytes::new(decoder.bytes(crate::mutation::MAX_PREIMAGE_BYTES)?)
        .map_err(|_| corrupt("state snapshot raw preimage is oversized"))?;
    let original_typed = decode_typed_value(decoder)?;
    let original_fingerprint = StateFingerprint::from_bytes(decoder.fixed()?);
    let equality = decode_equality(decoder.u8()?)?;
    let target_identity = TargetIdentity::from_bytes(decoder.fixed()?);
    let captured_at = Timestamp::from_unix_millis(decoder.u128()?);
    Ok(Snapshot {
        mutation_id,
        target,
        original_raw,
        original_typed,
        original_fingerprint,
        equality,
        target_identity,
        captured_at,
    })
}

fn encode_apply_receipt(encoder: &mut Encoder, receipt: &ApplyReceipt) {
    encoder.u32(receipt.mutation_id.get());
    encoder.fixed(receipt.observed_precondition.as_bytes());
    encoder.fixed(receipt.observed_postcondition.as_bytes());
    encoder.fixed(receipt.ownership_fingerprint.as_bytes());
}

fn decode_apply_receipt(decoder: &mut Decoder<'_>) -> Result<ApplyReceipt, SysboostError> {
    Ok(ApplyReceipt {
        mutation_id: MutationId::new(decoder.u32()?),
        observed_precondition: StateFingerprint::from_bytes(decoder.fixed()?),
        observed_postcondition: StateFingerprint::from_bytes(decoder.fixed()?),
        ownership_fingerprint: StateFingerprint::from_bytes(decoder.fixed()?),
    })
}

fn encode_verification(encoder: &mut Encoder, verification: &VerificationResult) {
    encoder.u32(verification.mutation_id.get());
    encoder.fixed(verification.expected.as_bytes());
    encode_optional(encoder, verification.observed.is_some());
    if let Some(observed) = verification.observed {
        encoder.fixed(observed.as_bytes());
    }
    encode_optional(encoder, verification.matched);
}

fn decode_verification(decoder: &mut Decoder<'_>) -> Result<VerificationResult, SysboostError> {
    let mutation_id = MutationId::new(decoder.u32()?);
    let expected = StateFingerprint::from_bytes(decoder.fixed()?);
    let observed = if decoder.u8()? != 0 {
        Some(StateFingerprint::from_bytes(decoder.fixed()?))
    } else {
        None
    };
    let matched = decoder.u8()? != 0;
    Ok(VerificationResult {
        mutation_id,
        expected,
        observed,
        matched,
    })
}

fn encode_restore_receipt(encoder: &mut Encoder, receipt: &RestoreReceipt) {
    encoder.u32(receipt.mutation_id.get());
    encoder.fixed(receipt.restored_fingerprint.as_bytes());
    encode_optional(encoder, receipt.verified);
}

fn decode_restore_receipt(decoder: &mut Decoder<'_>) -> Result<RestoreReceipt, SysboostError> {
    Ok(RestoreReceipt {
        mutation_id: MutationId::new(decoder.u32()?),
        restored_fingerprint: StateFingerprint::from_bytes(decoder.fixed()?),
        verified: decoder.u8()? != 0,
    })
}

fn encode_transition(
    encoder: &mut Encoder,
    transition: &TransitionRecord,
) -> Result<(), SysboostError> {
    encoder.u64(transition.sequence);
    encoder.fixed(transition.session_id.as_bytes());
    encode_session_state(encoder, transition.from);
    encode_session_state(encoder, transition.to);
    encoder.u128(transition.at.as_unix_millis());
    encoder.string(&transition.reason, MAX_REASON_BYTES)
}

fn decode_transition(decoder: &mut Decoder<'_>) -> Result<TransitionRecord, SysboostError> {
    Ok(TransitionRecord {
        sequence: decoder.u64()?,
        session_id: SessionId::from_bytes(decoder.fixed()?),
        from: decode_session_state(decoder.u8()?)?,
        to: decode_session_state(decoder.u8()?)?,
        at: Timestamp::from_unix_millis(decoder.u128()?),
        reason: decoder.string(MAX_REASON_BYTES)?,
    })
}

fn encode_failure(encoder: &mut Encoder, failure: &FailureRecord) -> Result<(), SysboostError> {
    encode_error_code(encoder, failure.code);
    encode_stage(encoder, failure.stage);
    encode_optional(encoder, failure.mutation_id.is_some());
    if let Some(mutation_id) = failure.mutation_id {
        encoder.u32(mutation_id.get());
    }
    encoder.string(&failure.message, MAX_REASON_BYTES)
}

fn decode_failure(decoder: &mut Decoder<'_>) -> Result<FailureRecord, SysboostError> {
    let code = decode_error_code(decoder.u16()?)?;
    let stage = decode_stage(decoder.u8()?)?;
    let mutation_id = if decoder.u8()? != 0 {
        Some(MutationId::new(decoder.u32()?))
    } else {
        None
    };
    Ok(FailureRecord {
        code,
        stage,
        mutation_id,
        message: decoder.string(MAX_REASON_BYTES)?,
    })
}

fn encode_optional(encoder: &mut Encoder, present: bool) {
    encoder.u8(u8::from(present));
}

fn encode_session_state(encoder: &mut Encoder, state: SessionState) {
    encoder.u8(match state {
        SessionState::New => 0,
        SessionState::Detected => 1,
        SessionState::Planned => 2,
        SessionState::Snapshotted => 3,
        SessionState::IntentDurable => 4,
        SessionState::Applying => 5,
        SessionState::Active => 6,
        SessionState::Restoring => 7,
        SessionState::Restored => 8,
        SessionState::RollingBack => 9,
        SessionState::Degraded => 10,
        SessionState::RecoveryPending => 11,
    });
}

fn decode_session_state(tag: u8) -> Result<SessionState, SysboostError> {
    match tag {
        0 => Ok(SessionState::New),
        1 => Ok(SessionState::Detected),
        2 => Ok(SessionState::Planned),
        3 => Ok(SessionState::Snapshotted),
        4 => Ok(SessionState::IntentDurable),
        5 => Ok(SessionState::Applying),
        6 => Ok(SessionState::Active),
        7 => Ok(SessionState::Restoring),
        8 => Ok(SessionState::Restored),
        9 => Ok(SessionState::RollingBack),
        10 => Ok(SessionState::Degraded),
        11 => Ok(SessionState::RecoveryPending),
        _ => Err(corrupt("unknown session state tag")),
    }
}

fn encode_operation_state(encoder: &mut Encoder, state: OperationState) {
    encoder.u8(match state {
        OperationState::Planned => 0,
        OperationState::Snapshotted => 1,
        OperationState::IntentRecorded => 2,
        OperationState::Applying => 3,
        OperationState::Applied => 4,
        OperationState::Verified => 5,
        OperationState::Restoring => 6,
        OperationState::Restored => 7,
        OperationState::Failed => 8,
        OperationState::RestoreFailed => 9,
    });
}

fn decode_operation_state(tag: u8) -> Result<OperationState, SysboostError> {
    match tag {
        0 => Ok(OperationState::Planned),
        1 => Ok(OperationState::Snapshotted),
        2 => Ok(OperationState::IntentRecorded),
        3 => Ok(OperationState::Applying),
        4 => Ok(OperationState::Applied),
        5 => Ok(OperationState::Verified),
        6 => Ok(OperationState::Restoring),
        7 => Ok(OperationState::Restored),
        8 => Ok(OperationState::Failed),
        9 => Ok(OperationState::RestoreFailed),
        _ => Err(corrupt("unknown operation state tag")),
    }
}

fn encode_equality(encoder: &mut Encoder, equality: EqualityKind) {
    encoder.u8(match equality {
        EqualityKind::ByteExact => 0,
        EqualityKind::ScalarExact => 1,
        EqualityKind::SetExact => 2,
    });
}

fn decode_equality(tag: u8) -> Result<EqualityKind, SysboostError> {
    match tag {
        0 => Ok(EqualityKind::ByteExact),
        1 => Ok(EqualityKind::ScalarExact),
        2 => Ok(EqualityKind::SetExact),
        _ => Err(corrupt("unknown equality tag")),
    }
}

fn encode_stage(encoder: &mut Encoder, stage: Stage) {
    encoder.u8(match stage {
        Stage::Detect => 0,
        Stage::Plan => 1,
        Stage::Snapshot => 2,
        Stage::DurableIntent => 3,
        Stage::Apply => 4,
        Stage::Verify => 5,
        Stage::Restore => 6,
        Stage::Recovery => 7,
        Stage::Transport => 8,
        Stage::Config => 9,
    });
}

fn decode_stage(tag: u8) -> Result<Stage, SysboostError> {
    match tag {
        0 => Ok(Stage::Detect),
        1 => Ok(Stage::Plan),
        2 => Ok(Stage::Snapshot),
        3 => Ok(Stage::DurableIntent),
        4 => Ok(Stage::Apply),
        5 => Ok(Stage::Verify),
        6 => Ok(Stage::Restore),
        7 => Ok(Stage::Recovery),
        8 => Ok(Stage::Transport),
        9 => Ok(Stage::Config),
        _ => Err(corrupt("unknown stage tag")),
    }
}

fn encode_error_code(encoder: &mut Encoder, code: ErrorCode) {
    encoder.u16(match code {
        ErrorCode::ConfigError => 1,
        ErrorCode::CapabilityError => 2,
        ErrorCode::Unsupported => 3,
        ErrorCode::AuthorizationError => 4,
        ErrorCode::TargetError => 5,
        ErrorCode::PlanningError => 6,
        ErrorCode::SnapshotError => 7,
        ErrorCode::DurabilityError => 8,
        ErrorCode::TransportError => 9,
        ErrorCode::ApplyError => 10,
        ErrorCode::VerificationError => 11,
        ErrorCode::RestoreConflict => 12,
        ErrorCode::RestoreError => 13,
        ErrorCode::JournalCorrupt => 14,
        ErrorCode::InvariantViolation => 15,
        ErrorCode::InvalidInput => 16,
    });
}

fn decode_error_code(tag: u16) -> Result<ErrorCode, SysboostError> {
    match tag {
        1 => Ok(ErrorCode::ConfigError),
        2 => Ok(ErrorCode::CapabilityError),
        3 => Ok(ErrorCode::Unsupported),
        4 => Ok(ErrorCode::AuthorizationError),
        5 => Ok(ErrorCode::TargetError),
        6 => Ok(ErrorCode::PlanningError),
        7 => Ok(ErrorCode::SnapshotError),
        8 => Ok(ErrorCode::DurabilityError),
        9 => Ok(ErrorCode::TransportError),
        10 => Ok(ErrorCode::ApplyError),
        11 => Ok(ErrorCode::VerificationError),
        12 => Ok(ErrorCode::RestoreConflict),
        13 => Ok(ErrorCode::RestoreError),
        14 => Ok(ErrorCode::JournalCorrupt),
        15 => Ok(ErrorCode::InvariantViolation),
        16 => Ok(ErrorCode::InvalidInput),
        _ => Err(corrupt("unknown error-code tag")),
    }
}

fn encode_mutation_kind(encoder: &mut Encoder, kind: &MutationKind) -> Result<(), SysboostError> {
    match kind {
        MutationKind::CpuFrequency {
            policy,
            min_khz,
            max_khz,
        } => {
            encoder.u8(0);
            encoder.u32(policy.get());
            encode_frequency(encoder, *min_khz);
            encode_frequency(encoder, *max_khz);
        }
        MutationKind::CpuGovernor { policy, governor } => {
            encoder.u8(1);
            encoder.u32(policy.get());
            encoder.string(governor.as_str(), MAX_STRING_BYTES)?;
        }
        MutationKind::CpuEnergyPreference { policy, value } => {
            encoder.u8(2);
            encoder.u32(policy.get());
            encoder.u8(energy_tag(*value));
        }
        MutationKind::CpuBoost { state } => {
            encoder.u8(10);
            encoder.u8(cpu_boost_tag(*state));
        }
        MutationKind::PlatformProfile { profile } => {
            encoder.u8(11);
            encoder.string(profile.as_str(), MAX_STRING_BYTES)?;
        }
        MutationKind::CgroupCpuWeight { cgroup, weight } => {
            encoder.u8(3);
            encode_cgroup(encoder, cgroup)?;
            encoder.u16(weight.get());
        }
        MutationKind::CgroupCpuMax {
            cgroup,
            quota,
            period,
        } => {
            encoder.u8(4);
            encode_cgroup(encoder, cgroup)?;
            encode_quota(encoder, *quota);
            encoder.u64(period.get());
        }
        MutationKind::CgroupCpuset { cgroup, cpus } => {
            encoder.u8(5);
            encode_cgroup(encoder, cgroup)?;
            encode_cpuset(encoder, cpus)?;
        }
        MutationKind::CgroupIoWeight { cgroup, weight } => {
            encoder.u8(12);
            encode_cgroup(encoder, cgroup)?;
            encoder.u16(weight.get());
        }
        MutationKind::CgroupUclampMin { cgroup, value } => {
            encoder.u8(13);
            encode_cgroup(encoder, cgroup)?;
            encode_uclamp(encoder, *value);
        }
        MutationKind::CgroupUclampMax { cgroup, value } => {
            encoder.u8(14);
            encode_cgroup(encoder, cgroup)?;
            encode_uclamp(encoder, *value);
        }
        MutationKind::CgroupWorkload { parent, name } => {
            encoder.u8(15);
            encode_cgroup(encoder, parent)?;
            encoder.string(name.as_str(), MAX_STRING_BYTES)?;
        }
        MutationKind::CgroupBackground { parent, name } => {
            encoder.u8(16);
            encode_cgroup(encoder, parent)?;
            encoder.string(name.as_str(), MAX_STRING_BYTES)?;
        }
        MutationKind::ProcessPlacement { process, cgroup } => {
            encoder.u8(17);
            encode_process(encoder, *process);
            encode_cgroup(encoder, cgroup)?;
        }
        MutationKind::ProcessNice { process, nice } => {
            encoder.u8(18);
            encode_process(encoder, *process);
            encoder.i64(i64::from(nice.get()));
        }
        MutationKind::ProcessIoPriority { process, priority } => {
            encoder.u8(19);
            encode_process(encoder, *process);
            encode_ioprio(encoder, *priority);
        }
        MutationKind::GpuPerformanceProfile { device, profile } => {
            encoder.u8(6);
            encoder.u32(device.get());
            encoder.u8(gpu_profile_tag(*profile));
        }
        MutationKind::GpuPowerLimit { device, milliwatts } => {
            encoder.u8(7);
            encoder.u32(device.get());
            encoder.u32(milliwatts.get());
        }
        MutationKind::IrqAffinity { irq, cpus } => {
            encoder.u8(8);
            encoder.u32(irq.get());
            encode_cpuset(encoder, cpus)?;
        }
        MutationKind::RuntimeSysctl { key, value } => {
            encoder.u8(9);
            encoder.u8(sysctl_key_tag(*key));
            encoder.i64(value.get());
        }
    }
    Ok(())
}

fn decode_mutation_kind(decoder: &mut Decoder<'_>) -> Result<MutationKind, SysboostError> {
    match decoder.u8()? {
        0 => Ok(MutationKind::CpuFrequency {
            policy: CpuPolicyId::new(decoder.u32()?),
            min_khz: decode_frequency(decoder)?,
            max_khz: decode_frequency(decoder)?,
        }),
        1 => Ok(MutationKind::CpuGovernor {
            policy: CpuPolicyId::new(decoder.u32()?),
            governor: GovernorId::new(decoder.string(MAX_STRING_BYTES)?)
                .map_err(|_| corrupt("state governor is invalid"))?,
        }),
        2 => Ok(MutationKind::CpuEnergyPreference {
            policy: CpuPolicyId::new(decoder.u32()?),
            value: decode_energy(decoder.u8()?)?,
        }),
        3 => Ok(MutationKind::CgroupCpuWeight {
            cgroup: decode_cgroup(decoder)?,
            weight: CpuWeight::new(decoder.u16()?)
                .map_err(|_| corrupt("state CPU weight is invalid"))?,
        }),
        4 => Ok(MutationKind::CgroupCpuMax {
            cgroup: decode_cgroup(decoder)?,
            quota: decode_quota(decoder)?,
            period: CpuPeriod::new(decoder.u64()?)
                .map_err(|_| corrupt("state CPU period is invalid"))?,
        }),
        5 => Ok(MutationKind::CgroupCpuset {
            cgroup: decode_cgroup(decoder)?,
            cpus: decode_cpuset(decoder)?,
        }),
        12 => Ok(MutationKind::CgroupIoWeight {
            cgroup: decode_cgroup(decoder)?,
            weight: IoWeight::new(decoder.u16()?)
                .map_err(|_| corrupt("state I/O weight is invalid"))?,
        }),
        13 => Ok(MutationKind::CgroupUclampMin {
            cgroup: decode_cgroup(decoder)?,
            value: decode_uclamp(decoder)?,
        }),
        14 => Ok(MutationKind::CgroupUclampMax {
            cgroup: decode_cgroup(decoder)?,
            value: decode_uclamp(decoder)?,
        }),
        15 => Ok(MutationKind::CgroupWorkload {
            parent: decode_cgroup(decoder)?,
            name: CgroupName::new(decoder.string(MAX_STRING_BYTES)?)
                .map_err(|_| corrupt("state workload cgroup name is invalid"))?,
        }),
        16 => Ok(MutationKind::CgroupBackground {
            parent: decode_cgroup(decoder)?,
            name: CgroupName::new(decoder.string(MAX_STRING_BYTES)?)
                .map_err(|_| corrupt("state background cgroup name is invalid"))?,
        }),
        17 => Ok(MutationKind::ProcessPlacement {
            process: decode_process(decoder)?,
            cgroup: decode_cgroup(decoder)?,
        }),
        18 => Ok(MutationKind::ProcessNice {
            process: decode_process(decoder)?,
            nice: NiceValue::new(
                decoder
                    .i64()?
                    .try_into()
                    .map_err(|_| corrupt("state nice value is invalid"))?,
            )
            .map_err(|_| corrupt("state nice value is invalid"))?,
        }),
        19 => Ok(MutationKind::ProcessIoPriority {
            process: decode_process(decoder)?,
            priority: decode_ioprio(decoder)?,
        }),
        6 => Ok(MutationKind::GpuPerformanceProfile {
            device: GpuId::new(decoder.u32()?),
            profile: decode_gpu_profile(decoder.u8()?)?,
        }),
        7 => Ok(MutationKind::GpuPowerLimit {
            device: GpuId::new(decoder.u32()?),
            milliwatts: PowerMilliwatts::new(decoder.u32()?)
                .map_err(|_| corrupt("state GPU power limit is invalid"))?,
        }),
        8 => Ok(MutationKind::IrqAffinity {
            irq: IrqId::new(decoder.u32()?),
            cpus: decode_cpuset(decoder)?,
        }),
        9 => Ok(MutationKind::RuntimeSysctl {
            key: decode_sysctl_key(decoder.u8()?)?,
            value: ApprovedSysctlValue::new(decoder.i64()?),
        }),
        10 => Ok(MutationKind::CpuBoost {
            state: decode_cpu_boost(decoder.u8()?)?,
        }),
        11 => Ok(MutationKind::PlatformProfile {
            profile: PlatformProfileId::new(decoder.string(MAX_STRING_BYTES)?)
                .map_err(|_| corrupt("state platform profile is invalid"))?,
        }),
        _ => Err(corrupt("unknown mutation kind tag")),
    }
}

fn encode_typed_value(encoder: &mut Encoder, value: &TypedValue) -> Result<(), SysboostError> {
    match value {
        TypedValue::CpuFrequency { min_khz, max_khz } => {
            encoder.u8(0);
            encode_frequency(encoder, *min_khz);
            encode_frequency(encoder, *max_khz);
        }
        TypedValue::Governor(governor) => {
            encoder.u8(1);
            encoder.string(governor.as_str(), MAX_STRING_BYTES)?;
        }
        TypedValue::EnergyPreference(value) => {
            encoder.u8(2);
            encoder.u8(energy_tag(*value));
        }
        TypedValue::CpuBoost(state) => {
            encoder.u8(10);
            encoder.u8(cpu_boost_tag(*state));
        }
        TypedValue::PlatformProfile(profile) => {
            encoder.u8(11);
            encoder.string(profile.as_str(), MAX_STRING_BYTES)?;
        }
        TypedValue::CgroupCpuWeight(weight) => {
            encoder.u8(3);
            encoder.u16(weight.get());
        }
        TypedValue::CgroupCpuMax { quota, period } => {
            encoder.u8(4);
            encode_quota(encoder, *quota);
            encoder.u64(period.get());
        }
        TypedValue::CgroupCpuset(cpus) => {
            encoder.u8(5);
            encode_cpuset(encoder, cpus)?;
        }
        TypedValue::CgroupIoWeight(weight) => {
            encoder.u8(12);
            encoder.u16(weight.get());
        }
        TypedValue::CgroupUclamp(value) => {
            encoder.u8(13);
            encode_uclamp(encoder, *value);
        }
        TypedValue::CgroupLifecycle {
            kind,
            name,
            present,
        } => {
            encoder.u8(14);
            encoder.u8(cgroup_kind_tag(*kind));
            encoder.string(name.as_str(), MAX_STRING_BYTES)?;
            encoder.u8(u8::from(*present));
        }
        TypedValue::ProcessPlacement(cgroup) => {
            encoder.u8(15);
            encode_cgroup(encoder, cgroup)?;
        }
        TypedValue::Nice(value) => {
            encoder.u8(16);
            encoder.i64(i64::from(value.get()));
        }
        TypedValue::IoPriority(value) => {
            encoder.u8(17);
            encode_ioprio(encoder, *value);
        }
        TypedValue::GpuPerformanceProfile(profile) => {
            encoder.u8(6);
            encoder.u8(gpu_profile_tag(*profile));
        }
        TypedValue::GpuPowerLimit(limit) => {
            encoder.u8(7);
            encoder.u32(limit.get());
        }
        TypedValue::IrqAffinity(cpus) => {
            encoder.u8(8);
            encode_cpuset(encoder, cpus)?;
        }
        TypedValue::RuntimeSysctl { key, value } => {
            encoder.u8(9);
            encoder.u8(sysctl_key_tag(*key));
            encoder.i64(value.get());
        }
    }
    Ok(())
}

fn decode_typed_value(decoder: &mut Decoder<'_>) -> Result<TypedValue, SysboostError> {
    match decoder.u8()? {
        0 => Ok(TypedValue::CpuFrequency {
            min_khz: decode_frequency(decoder)?,
            max_khz: decode_frequency(decoder)?,
        }),
        1 => Ok(TypedValue::Governor(
            GovernorId::new(decoder.string(MAX_STRING_BYTES)?)
                .map_err(|_| corrupt("state typed governor is invalid"))?,
        )),
        2 => Ok(TypedValue::EnergyPreference(decode_energy(decoder.u8()?)?)),
        3 => Ok(TypedValue::CgroupCpuWeight(
            CpuWeight::new(decoder.u16()?)
                .map_err(|_| corrupt("state typed CPU weight is invalid"))?,
        )),
        4 => Ok(TypedValue::CgroupCpuMax {
            quota: decode_quota(decoder)?,
            period: CpuPeriod::new(decoder.u64()?)
                .map_err(|_| corrupt("state typed CPU period is invalid"))?,
        }),
        5 => Ok(TypedValue::CgroupCpuset(decode_cpuset(decoder)?)),
        12 => Ok(TypedValue::CgroupIoWeight(
            IoWeight::new(decoder.u16()?)
                .map_err(|_| corrupt("state typed I/O weight is invalid"))?,
        )),
        13 => Ok(TypedValue::CgroupUclamp(decode_uclamp(decoder)?)),
        14 => Ok(TypedValue::CgroupLifecycle {
            kind: decode_cgroup_kind(decoder.u8()?)?,
            name: CgroupName::new(decoder.string(MAX_STRING_BYTES)?)
                .map_err(|_| corrupt("state typed cgroup name is invalid"))?,
            present: decoder.u8()? != 0,
        }),
        15 => Ok(TypedValue::ProcessPlacement(decode_cgroup(decoder)?)),
        16 => Ok(TypedValue::Nice(
            NiceValue::new(
                decoder
                    .i64()?
                    .try_into()
                    .map_err(|_| corrupt("state typed nice value is invalid"))?,
            )
            .map_err(|_| corrupt("state typed nice value is invalid"))?,
        )),
        17 => Ok(TypedValue::IoPriority(decode_ioprio(decoder)?)),
        6 => Ok(TypedValue::GpuPerformanceProfile(decode_gpu_profile(
            decoder.u8()?,
        )?)),
        7 => Ok(TypedValue::GpuPowerLimit(
            PowerMilliwatts::new(decoder.u32()?)
                .map_err(|_| corrupt("state typed GPU power limit is invalid"))?,
        )),
        8 => Ok(TypedValue::IrqAffinity(decode_cpuset(decoder)?)),
        9 => Ok(TypedValue::RuntimeSysctl {
            key: decode_sysctl_key(decoder.u8()?)?,
            value: ApprovedSysctlValue::new(decoder.i64()?),
        }),
        10 => Ok(TypedValue::CpuBoost(decode_cpu_boost(decoder.u8()?)?)),
        11 => Ok(TypedValue::PlatformProfile(
            PlatformProfileId::new(decoder.string(MAX_STRING_BYTES)?)
                .map_err(|_| corrupt("state typed platform profile is invalid"))?,
        )),
        _ => Err(corrupt("unknown typed-value tag")),
    }
}

fn encode_frequency(encoder: &mut Encoder, frequency: Option<FrequencyKHz>) {
    encode_optional(encoder, frequency.is_some());
    if let Some(frequency) = frequency {
        encoder.u64(frequency.get());
    }
}

fn decode_frequency(decoder: &mut Decoder<'_>) -> Result<Option<FrequencyKHz>, SysboostError> {
    if decoder.u8()? == 0 {
        Ok(None)
    } else {
        Ok(Some(
            FrequencyKHz::new(decoder.u64()?).map_err(|_| corrupt("state frequency is invalid"))?,
        ))
    }
}

fn encode_cgroup(encoder: &mut Encoder, cgroup: &CgroupId) -> Result<(), SysboostError> {
    encoder.u64(cgroup.mount_id);
    encoder.u64(cgroup.inode);
    encoder.string(cgroup.handle.as_str(), MAX_STRING_BYTES)
}

fn decode_cgroup(decoder: &mut Decoder<'_>) -> Result<CgroupId, SysboostError> {
    Ok(CgroupId::new(
        decoder.u64()?,
        decoder.u64()?,
        TargetId::new(decoder.string(MAX_STRING_BYTES)?)
            .map_err(|_| corrupt("state cgroup handle is invalid"))?,
    ))
}

fn encode_process(encoder: &mut Encoder, process: ProcessId) {
    encoder.u32(process.pid());
    encoder.u64(process.start_time_ticks());
}

fn decode_process(decoder: &mut Decoder<'_>) -> Result<ProcessId, SysboostError> {
    ProcessId::new(decoder.u32()?, decoder.u64()?)
        .map_err(|_| corrupt("state process identity is invalid"))
}

fn encode_uclamp(encoder: &mut Encoder, value: UclampValue) {
    match value {
        UclampValue::Value(value) => {
            encoder.u8(0);
            encoder.u16(value);
        }
        UclampValue::Max => encoder.u8(1),
    }
}

fn decode_uclamp(decoder: &mut Decoder<'_>) -> Result<UclampValue, SysboostError> {
    match decoder.u8()? {
        0 => UclampValue::new(decoder.u16()?)
            .map_err(|_| corrupt("state utilization clamp is invalid")),
        1 => Ok(UclampValue::Max),
        _ => Err(corrupt("unknown utilization clamp tag")),
    }
}

fn cgroup_kind_tag(kind: CgroupGroupKind) -> u8 {
    match kind {
        CgroupGroupKind::Workload => 0,
        CgroupGroupKind::ConservativeBackground => 1,
    }
}

fn decode_cgroup_kind(tag: u8) -> Result<CgroupGroupKind, SysboostError> {
    match tag {
        0 => Ok(CgroupGroupKind::Workload),
        1 => Ok(CgroupGroupKind::ConservativeBackground),
        _ => Err(corrupt("unknown managed cgroup kind tag")),
    }
}

fn ioprio_class_tag(class: IoPriorityClass) -> u8 {
    match class {
        IoPriorityClass::None => 0,
        IoPriorityClass::BestEffort => 1,
        IoPriorityClass::Idle => 2,
    }
}

fn decode_ioprio_class(tag: u8) -> Result<IoPriorityClass, SysboostError> {
    match tag {
        0 => Ok(IoPriorityClass::None),
        1 => Ok(IoPriorityClass::BestEffort),
        2 => Ok(IoPriorityClass::Idle),
        _ => Err(corrupt("unknown I/O priority class tag")),
    }
}

fn encode_ioprio(encoder: &mut Encoder, priority: IoPriority) {
    encoder.u8(ioprio_class_tag(priority.class()));
    encoder.u8(priority.level());
}

fn decode_ioprio(decoder: &mut Decoder<'_>) -> Result<IoPriority, SysboostError> {
    IoPriority::new(decode_ioprio_class(decoder.u8()?)?, decoder.u8()?)
        .map_err(|_| corrupt("state I/O priority is invalid"))
}

fn encode_cpuset(encoder: &mut Encoder, cpus: &CpuSet) -> Result<(), SysboostError> {
    put_count(encoder, cpus.as_slice().len(), MAX_DEPENDENCIES)?;
    for cpu in cpus.as_slice() {
        encoder.u32(*cpu);
    }
    Ok(())
}

fn decode_cpuset(decoder: &mut Decoder<'_>) -> Result<CpuSet, SysboostError> {
    let count = decoder.count(MAX_DEPENDENCIES)?;
    let mut cpus = Vec::with_capacity(count);
    for _ in 0..count {
        cpus.push(decoder.u32()?);
    }
    CpuSet::new(cpus).map_err(|_| corrupt("state CPU set is invalid"))
}

fn encode_quota(encoder: &mut Encoder, quota: CpuQuota) {
    match quota {
        CpuQuota::Max => encoder.u8(0),
        CpuQuota::Micros(value) => {
            encoder.u8(1);
            encoder.u64(value);
        }
    }
}

fn decode_quota(decoder: &mut Decoder<'_>) -> Result<CpuQuota, SysboostError> {
    match decoder.u8()? {
        0 => Ok(CpuQuota::Max),
        1 => CpuQuota::micros(decoder.u64()?).map_err(|_| corrupt("state CPU quota is invalid")),
        _ => Err(corrupt("unknown CPU quota tag")),
    }
}

fn energy_tag(value: EnergyPreference) -> u8 {
    match value {
        EnergyPreference::Performance => 0,
        EnergyPreference::BalancePerformance => 1,
        EnergyPreference::BalancePower => 2,
        EnergyPreference::Power => 3,
    }
}

fn decode_energy(tag: u8) -> Result<EnergyPreference, SysboostError> {
    match tag {
        0 => Ok(EnergyPreference::Performance),
        1 => Ok(EnergyPreference::BalancePerformance),
        2 => Ok(EnergyPreference::BalancePower),
        3 => Ok(EnergyPreference::Power),
        _ => Err(corrupt("unknown energy preference tag")),
    }
}

fn cpu_boost_tag(value: CpuBoostState) -> u8 {
    match value {
        CpuBoostState::Enabled => 0,
        CpuBoostState::Disabled => 1,
    }
}

fn decode_cpu_boost(tag: u8) -> Result<CpuBoostState, SysboostError> {
    match tag {
        0 => Ok(CpuBoostState::Enabled),
        1 => Ok(CpuBoostState::Disabled),
        _ => Err(corrupt("unknown CPU boost state tag")),
    }
}

fn gpu_profile_tag(value: GpuProfile) -> u8 {
    match value {
        GpuProfile::Performance => 0,
        GpuProfile::Balanced => 1,
        GpuProfile::PowerSave => 2,
    }
}

fn decode_gpu_profile(tag: u8) -> Result<GpuProfile, SysboostError> {
    match tag {
        0 => Ok(GpuProfile::Performance),
        1 => Ok(GpuProfile::Balanced),
        2 => Ok(GpuProfile::PowerSave),
        _ => Err(corrupt("unknown GPU profile tag")),
    }
}

fn sysctl_key_tag(value: ApprovedSysctlKey) -> u8 {
    match value {
        ApprovedSysctlKey::SchedulerUtilClamping => 0,
    }
}

fn decode_sysctl_key(tag: u8) -> Result<ApprovedSysctlKey, SysboostError> {
    match tag {
        0 => Ok(ApprovedSysctlKey::SchedulerUtilClamping),
        _ => Err(corrupt("unknown approved sysctl key tag")),
    }
}

fn checksum(bytes: &[u8]) -> [u8; 32] {
    // This is an integrity checksum for accidental/truncated state files, not
    // an authentication primitive.  The privileged service owns the state
    // directory and its permissions provide the trust boundary.
    let mut lanes = [
        0xcbf29ce484222325_u64,
        0x84222325cbf29ce4_u64,
        0x9e3779b185ebca87_u64,
        0x517cc1b727220a95_u64,
    ];
    for (index, byte) in bytes.iter().copied().enumerate() {
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
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::EqualityKind;
    use crate::ids::{CapabilityId, MutationId, PlanId};
    use crate::mutation::{GovernorId, MutationKind};

    fn record() -> SessionRecord {
        let kind = MutationKind::CpuGovernor {
            policy: CpuPolicyId::new(0),
            governor: GovernorId::new("performance").expect("valid governor"),
        };
        let mutation = PlannedMutation::new(
            MutationId::new(1),
            CapabilityId::new("cpu.policy.governor").expect("valid capability"),
            TargetId::new("cpu.policy.0").expect("valid target"),
            kind.clone(),
            kind.typed_value(),
            StateFingerprint::from_bytes([1; 32]),
            EqualityKind::ScalarExact,
            Vec::new(),
        )
        .expect("valid mutation");
        SessionRecord::new(
            Session::new(
                SessionId::from_bytes([2; 16]),
                &crate::plan::Plan::new(
                    PlanId::from_bytes([3; 16]),
                    [4; 32],
                    [5; 32],
                    [6; 32],
                    vec![mutation.clone()],
                )
                .expect("valid plan"),
                Timestamp::from_unix_millis(7),
            ),
            vec![mutation],
        )
        .expect("valid record")
    }

    #[test]
    fn operation_lifecycle_is_explicit() {
        assert!(OperationState::Planned.can_transition(OperationState::Snapshotted));
        assert!(OperationState::Applied.can_transition(OperationState::Verified));
        assert!(!OperationState::Planned.can_transition(OperationState::Verified));
    }

    #[test]
    fn state_record_round_trips_and_corruption_is_rejected() {
        let mut record = record();
        record
            .transition(
                SessionState::Detected,
                Timestamp::from_unix_millis(8),
                "fixture detection",
            )
            .expect("legal transition");
        let bytes = record.encode().expect("record encodes");
        let decoded = SessionRecord::decode(&bytes).expect("record decodes");
        assert_eq!(decoded, record);

        let mut corrupt_bytes = bytes;
        let index = corrupt_bytes.len() - 1;
        corrupt_bytes[index] ^= 1;
        assert_eq!(
            SessionRecord::decode(&corrupt_bytes).unwrap_err().code,
            ErrorCode::JournalCorrupt
        );
    }
}
