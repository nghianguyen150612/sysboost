//! Pure policy and planning contracts.

use crate::capability::{CapabilityInventory, RiskClass};
use crate::error::{ErrorCode, Stage, SysboostError};
use crate::ids::{CapabilityId, MutationId, PlanId, TargetId};
use crate::mutation::{MutationKind, PlannedMutation};

/// Runtime mode selected by policy.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PolicyMode {
    /// Detect and describe changes without mutation.
    Report,
    /// Permit only mutations admitted by the helper policy.
    Boost,
}

/// One user/configuration request before capability planning.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PolicyRequest {
    /// Requested semantic capability.
    pub capability: CapabilityId,
    /// Opaque target selector.
    pub target: TargetId,
    /// Closed desired operation.
    pub operation: MutationKind,
    /// Whether inability to admit this request rejects the whole plan.
    pub required: bool,
}

impl PolicyRequest {
    /// Construct an optional policy request.
    pub fn optional(capability: CapabilityId, target: TargetId, operation: MutationKind) -> Self {
        Self {
            capability,
            target,
            operation,
            required: false,
        }
    }

    /// Mark this request as required.
    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }
}

/// Effective policy consumed by the pure planner.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Policy {
    /// Report or mutation intent.
    pub mode: PolicyMode,
    /// Highest risk admitted by the trusted policy.
    pub max_risk: RiskClass,
    /// Whether experimental classes can be selected.
    pub allow_experimental: bool,
    /// Default requiredness for requests created by a parser.
    pub required_default: bool,
    /// Requested operations.
    pub requests: Vec<PolicyRequest>,
    /// Bounded heartbeat/liveness timeout in milliseconds.
    pub session_timeout_ms: u64,
}

impl Policy {
    /// Safe report-only baseline.
    pub fn safe_defaults() -> Self {
        Self {
            mode: PolicyMode::Report,
            // No requests exist at this baseline. Explicit policy selection
            // is still required before any capability can be considered.
            max_risk: RiskClass::Critical,
            allow_experimental: true,
            required_default: false,
            requests: Vec::new(),
            session_timeout_ms: 30_000,
        }
    }
}

/// Pure planner input. Detection and configuration are complete before this
/// value is constructed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanRequest {
    /// Effective policy.
    pub policy: Policy,
    /// Advisory or helper-refreshed capability evidence.
    pub inventory: CapabilityInventory,
}

/// Deterministic mutation plan and evidence digests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Plan {
    /// Stable plan identity.
    pub id: PlanId,
    /// Digest of the complete ordered plan and its evidence.
    pub plan_digest: [u8; 32],
    /// Digest of the effective policy.
    pub policy_digest: [u8; 32],
    /// Digest of capability evidence and backend versions.
    pub capability_digest: [u8; 32],
    /// Topologically ordered mutation units.
    pub mutations: Vec<PlannedMutation>,
}

impl Plan {
    /// Construct and validate a plan from already ordered mutations.
    pub fn new(
        id: PlanId,
        plan_digest: [u8; 32],
        policy_digest: [u8; 32],
        capability_digest: [u8; 32],
        mutations: Vec<PlannedMutation>,
    ) -> Result<Self, SysboostError> {
        let plan = Self {
            id,
            plan_digest,
            policy_digest,
            capability_digest,
            mutations,
        };
        plan.validate()?;
        Ok(plan)
    }

    /// Validate uniqueness and dependency references. A later planner may add
    /// a full topological sort, but no malformed dependency graph is accepted.
    pub fn validate(&self) -> Result<(), SysboostError> {
        for (index, mutation) in self.mutations.iter().enumerate() {
            if self.mutations[..index]
                .iter()
                .any(|other| other.mutation_id == mutation.mutation_id)
            {
                return Err(SysboostError::new(
                    ErrorCode::PlanningError,
                    "plan contains duplicate mutation IDs",
                )
                .with_stage(Stage::Plan)
                .with_mutation(mutation.mutation_id));
            }
            for dependency in &mutation.dependencies {
                if !self
                    .mutations
                    .iter()
                    .any(|other| other.mutation_id == *dependency)
                {
                    return Err(SysboostError::new(
                        ErrorCode::PlanningError,
                        "plan dependency does not refer to a mutation in the plan",
                    )
                    .with_stage(Stage::Plan)
                    .with_mutation(mutation.mutation_id));
                }
            }
        }

        for mutation in &self.mutations {
            if reaches_cycle(mutation.mutation_id, &self.mutations, &mut Vec::new()) {
                return Err(SysboostError::new(
                    ErrorCode::PlanningError,
                    "plan dependency graph contains a cycle",
                )
                .with_stage(Stage::Plan)
                .with_mutation(mutation.mutation_id));
            }
        }
        Ok(())
    }
}

fn reaches_cycle(
    current: MutationId,
    mutations: &[PlannedMutation],
    stack: &mut Vec<MutationId>,
) -> bool {
    if stack.contains(&current) {
        return true;
    }
    let Some(mutation) = mutations.iter().find(|item| item.mutation_id == current) else {
        return false;
    };
    stack.push(current);
    let result = mutation
        .dependencies
        .iter()
        .any(|dependency| reaches_cycle(*dependency, mutations, stack));
    stack.pop();
    result
}

/// Pure planner port. Implementations must not perform host I/O.
pub trait Planner {
    /// Build a deterministic plan from policy and capability evidence.
    fn build(&self, request: &PlanRequest) -> Result<Plan, SysboostError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::EqualityKind;
    use crate::ids::{CapabilityId, MutationId, PlanId, TargetId};
    use crate::mutation::{
        CpuPolicyId, GovernorId, MutationKind, PlannedMutation, StateFingerprint,
    };

    #[test]
    fn plan_rejects_unknown_dependencies() {
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
            StateFingerprint::from_bytes([0; 32]),
            EqualityKind::ScalarExact,
            vec![MutationId::new(99)],
        )
        .expect("mutation dependency is structurally representable");
        let result = Plan::new(
            PlanId::from_bytes([1; 16]),
            [2; 32],
            [3; 32],
            [4; 32],
            vec![mutation],
        );
        assert_eq!(result.unwrap_err().code, ErrorCode::PlanningError);
    }
}
