//! Session state machine and journal transition records.

use crate::error::{ErrorCode, Stage, SysboostError};
use crate::ids::{PlanId, SessionId, TargetId};
use crate::plan::Plan;
use crate::time::Timestamp;

/// Durable transaction/session state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SessionState {
    /// Session allocated but no detection completed.
    New,
    /// Capability evidence collected.
    Detected,
    /// Pure plan accepted.
    Planned,
    /// All mutation preimages captured.
    Snapshotted,
    /// Intent and snapshots are durable.
    IntentDurable,
    /// Apply is in progress.
    Applying,
    /// All intended applies have been verified.
    Active,
    /// Normal restore is in progress.
    Restoring,
    /// Every original state has been verified.
    Restored,
    /// Reverse rollback is in progress after a failure.
    RollingBack,
    /// At least one target is not proven restored.
    Degraded,
    /// Recovery requires service/operator attention.
    RecoveryPending,
}

impl SessionState {
    /// Whether this state is terminal for normal operation.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Restored | Self::Degraded | Self::RecoveryPending
        )
    }

    /// Check the frozen legal state transition table.
    pub const fn can_transition(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::New, Self::Detected)
                | (Self::Detected, Self::Planned)
                | (Self::Planned, Self::Snapshotted)
                | (Self::Snapshotted, Self::IntentDurable)
                | (Self::IntentDurable, Self::Applying)
                | (Self::IntentDurable, Self::RollingBack)
                | (Self::Applying, Self::Active)
                | (Self::Applying, Self::RollingBack)
                | (Self::Active, Self::Restoring)
                | (Self::Restoring, Self::Restored)
                | (Self::Restoring, Self::Degraded)
                | (Self::RollingBack, Self::Restored)
                | (Self::RollingBack, Self::Degraded)
                | (Self::Degraded, Self::RecoveryPending)
                | (Self::RecoveryPending, Self::Restoring)
                | (Self::RecoveryPending, Self::Degraded)
        )
    }
}

/// Header persisted before mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionHeader {
    /// Unique session identity.
    pub session_id: SessionId,
    /// Plan identity.
    pub plan_id: PlanId,
    /// Plan digest bound to the helper session.
    pub plan_digest: [u8; 32],
    /// Session creation time.
    pub created_at: Timestamp,
    /// Target leases owned by this session.
    pub targets: Vec<TargetId>,
}

/// In-memory authoritative session state owned by the helper.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Session {
    /// Durable header.
    pub header: SessionHeader,
    /// Current legal state.
    pub state: SessionState,
}

impl Session {
    /// Create a new session in `New` state from a planned transaction.
    pub fn new(session_id: SessionId, plan: &Plan, created_at: Timestamp) -> Self {
        let targets = plan
            .mutations
            .iter()
            .map(|mutation| mutation.target.clone())
            .collect();
        Self {
            header: SessionHeader {
                session_id,
                plan_id: plan.id,
                plan_digest: plan.plan_digest,
                created_at,
                targets,
            },
            state: SessionState::New,
        }
    }

    /// Apply one legal state transition.
    pub fn transition(&mut self, next: SessionState) -> Result<(), SysboostError> {
        if !self.state.can_transition(next) {
            return Err(SysboostError::new(
                ErrorCode::InvariantViolation,
                "illegal session state transition",
            )
            .with_stage(stage_for_state(next))
            .with_session(self.header.session_id));
        }
        self.state = next;
        Ok(())
    }
}

/// One append-only journal state transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransitionRecord {
    /// Monotonic journal sequence.
    pub sequence: u64,
    /// Session identity.
    pub session_id: SessionId,
    /// Previous state.
    pub from: SessionState,
    /// New state.
    pub to: SessionState,
    /// Transition timestamp.
    pub at: Timestamp,
    /// Bounded audit explanation.
    pub reason: String,
}

fn stage_for_state(state: SessionState) -> Stage {
    match state {
        SessionState::New | SessionState::Detected => Stage::Detect,
        SessionState::Planned => Stage::Plan,
        SessionState::Snapshotted => Stage::Snapshot,
        SessionState::IntentDurable => Stage::DurableIntent,
        SessionState::Applying => Stage::Apply,
        SessionState::Active => Stage::Verify,
        SessionState::Restoring | SessionState::Restored => Stage::Restore,
        SessionState::RollingBack | SessionState::Degraded | SessionState::RecoveryPending => {
            Stage::Recovery
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::EqualityKind;
    use crate::error::ErrorCode;
    use crate::ids::{CapabilityId, MutationId, PlanId, TargetId};
    use crate::mutation::{
        CpuPolicyId, GovernorId, MutationKind, PlannedMutation, StateFingerprint,
    };

    fn plan() -> Plan {
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
        Plan::new(
            PlanId::from_bytes([2; 16]),
            [3; 32],
            [4; 32],
            [5; 32],
            vec![mutation],
        )
        .expect("valid plan")
    }

    #[test]
    fn legal_session_sequence_reaches_active() {
        let mut session = Session::new(
            SessionId::from_bytes([6; 16]),
            &plan(),
            Timestamp::from_unix_millis(7),
        );
        for state in [
            SessionState::Detected,
            SessionState::Planned,
            SessionState::Snapshotted,
            SessionState::IntentDurable,
            SessionState::Applying,
            SessionState::Active,
        ] {
            session.transition(state).expect("legal transition");
        }
        assert_eq!(session.state, SessionState::Active);
    }

    #[test]
    fn illegal_transition_is_an_invariant_error() {
        let mut session = Session::new(
            SessionId::from_bytes([8; 16]),
            &plan(),
            Timestamp::from_unix_millis(9),
        );
        let error = session
            .transition(SessionState::Active)
            .expect_err("New cannot become Active");
        assert_eq!(error.code, ErrorCode::InvariantViolation);
    }
}
