//! Typed backend and registry ports.

use sysboost_core::{
    ApplyReceipt, BackendId, CapabilityId, CapabilityInventory, OperationId, Plan, PlannedMutation,
    RestoreReceipt, SessionId, Snapshot, StateFingerprint, SysboostError, TargetIdentity,
    Timestamp,
};

use crate::clock::Clock;
pub use crate::transaction::BackendExecutionToken;

/// Compiled-in backend metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendDescriptor {
    /// Stable backend ID.
    pub id: BackendId,
    /// Human-readable implementation version.
    pub version: String,
    /// Capabilities owned by this backend.
    pub capabilities: Vec<CapabilityId>,
    /// Typed operations owned by this backend.
    pub operations: Vec<OperationId>,
}

/// Capability detection port. Implementations must not probe by writing.
pub trait CapabilityDetector {
    /// Detect live capability evidence.
    fn detect(&self, clock: &dyn Clock) -> Result<CapabilityInventory, SysboostError>;
}

/// Typed mutation backend port. There is no raw path or command operation.
pub trait MutationBackend {
    /// Return compiled-in backend metadata.
    fn descriptor(&self) -> &BackendDescriptor;

    /// Whether this backend (or a reviewed backend set) owns the supplied
    /// compiled-in backend identity.
    fn owns_backend(&self, backend: &BackendId) -> bool {
        self.descriptor().id == *backend
    }

    /// Detect evidence through read-only adapters.
    fn detect(&self, clock: &dyn Clock) -> Result<CapabilityInventory, SysboostError>;

    /// Capture a complete preimage before any apply.
    fn snapshot(
        &self,
        execution: &BackendExecutionToken,
        mutation: &PlannedMutation,
        now: Timestamp,
    ) -> Result<Snapshot, SysboostError>;

    /// Apply one typed operation after durable intent exists.
    ///
    /// The execution capability is created and retained by
    /// [`crate::transaction::TransactionEngine`].
    fn apply(
        &self,
        execution: &BackendExecutionToken,
        mutation: &PlannedMutation,
        snapshot: &Snapshot,
    ) -> Result<ApplyReceipt, SysboostError>;

    /// Verify a typed postcondition by readback.
    fn verify(
        &self,
        execution: &BackendExecutionToken,
        mutation: &PlannedMutation,
        expected: StateFingerprint,
        expected_target_identity: TargetIdentity,
    ) -> Result<StateFingerprint, SysboostError>;

    /// Restore one complete preimage.
    fn restore(
        &self,
        execution: &BackendExecutionToken,
        mutation: &PlannedMutation,
        snapshot: &Snapshot,
        expected_ownership: StateFingerprint,
    ) -> Result<RestoreReceipt, SysboostError>;

    /// Revalidate operation ownership and the backend-owned target allowlist
    /// immediately before snapshot admission.
    ///
    /// The default implementation performs the closed operation/capability
    /// ownership check and then fails closed because a backend has not supplied
    /// a target resolver.  A real backend must override
    /// [`MutationBackend::validate_target`] with an allowlist that maps the
    /// opaque target ID to its own internal interface identity.
    fn validate_admission(
        &self,
        mutation: &PlannedMutation,
        expected_target_identity: TargetIdentity,
    ) -> Result<(), SysboostError> {
        let descriptor = self.descriptor();
        let operation = mutation.kind.operation_id();
        if !descriptor.operations.contains(&operation) {
            return Err(SysboostError::new(
                sysboost_core::ErrorCode::Unsupported,
                "backend does not own the requested typed operation",
            )
            .with_backend(descriptor.id.clone())
            .with_mutation(mutation.mutation_id));
        }
        if !descriptor.capabilities.contains(&mutation.capability) {
            return Err(SysboostError::new(
                sysboost_core::ErrorCode::Unsupported,
                "backend does not own the requested capability",
            )
            .with_backend(descriptor.id.clone())
            .with_capability(mutation.capability.clone())
            .with_mutation(mutation.mutation_id));
        }
        self.validate_target(mutation, expected_target_identity)
    }

    /// Validate one opaque target against a compiled-in backend allowlist.
    ///
    /// This method never receives a filesystem path.  Backends should reject
    /// target IDs they did not discover themselves and bind the target to the
    /// expected [`TargetIdentity`] before any snapshot or apply call.
    fn validate_target(
        &self,
        mutation: &PlannedMutation,
        _expected_target_identity: TargetIdentity,
    ) -> Result<(), SysboostError> {
        Err(SysboostError::new(
            sysboost_core::ErrorCode::Unsupported,
            "backend has no target allowlist for this operation",
        )
        .with_mutation(mutation.mutation_id))
    }
}

/// Registry of reviewed, compiled-in backends.
pub struct BackendRegistry {
    backends: Vec<Box<dyn MutationBackend>>,
    descriptor: BackendDescriptor,
}

impl Default for BackendRegistry {
    fn default() -> Self {
        Self {
            backends: Vec::new(),
            descriptor: BackendDescriptor {
                id: BackendId::new("sysboost.registry").expect("static registry ID is valid"),
                version: "1".to_owned(),
                capabilities: Vec::new(),
                operations: Vec::new(),
            },
        }
    }
}

impl BackendRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a backend, rejecting duplicate ownership.
    pub fn register(&mut self, backend: Box<dyn MutationBackend>) -> Result<(), SysboostError> {
        let descriptor = backend.descriptor();
        if self
            .backends
            .iter()
            .any(|existing| existing.descriptor().id.as_str() == descriptor.id.as_str())
        {
            return Err(SysboostError::new(
                sysboost_core::ErrorCode::InvariantViolation,
                "duplicate backend registration",
            ));
        }
        for capability in &descriptor.capabilities {
            if self
                .backends
                .iter()
                .any(|existing| existing.descriptor().capabilities.contains(capability))
            {
                return Err(SysboostError::new(
                    sysboost_core::ErrorCode::InvariantViolation,
                    "duplicate capability ownership",
                )
                .with_capability(capability.clone()));
            }
        }
        for operation in &descriptor.operations {
            if self
                .backends
                .iter()
                .any(|existing| existing.descriptor().operations.contains(operation))
            {
                return Err(SysboostError::new(
                    sysboost_core::ErrorCode::InvariantViolation,
                    "duplicate operation ownership",
                ));
            }
        }
        self.backends.push(backend);
        let descriptor = self
            .backends
            .last()
            .expect("backend was just registered")
            .descriptor();
        self.descriptor
            .capabilities
            .extend(descriptor.capabilities.iter().cloned());
        self.descriptor
            .operations
            .extend(descriptor.operations.iter().cloned());
        self.descriptor.capabilities.sort();
        self.descriptor.operations.sort();
        Ok(())
    }

    /// Number of registered backends.
    pub fn len(&self) -> usize {
        self.backends.len()
    }

    /// Whether no backend is registered.
    pub fn is_empty(&self) -> bool {
        self.backends.is_empty()
    }

    /// Iterate registered backends for composition roots.
    pub fn iter(&self) -> impl Iterator<Item = &dyn MutationBackend> {
        self.backends.iter().map(|backend| backend.as_ref())
    }
}

impl MutationBackend for BackendRegistry {
    fn descriptor(&self) -> &BackendDescriptor {
        &self.descriptor
    }

    fn owns_backend(&self, backend: &BackendId) -> bool {
        self.backends
            .iter()
            .any(|candidate| candidate.owns_backend(backend))
    }

    fn detect(&self, clock: &dyn Clock) -> Result<CapabilityInventory, SysboostError> {
        let mut capabilities = Vec::new();
        let mut observed_at: Option<Timestamp> = None;
        for backend in &self.backends {
            let inventory = backend.detect(clock)?;
            observed_at = Some(observed_at.map_or(inventory.observed_at, |current| {
                current.max(inventory.observed_at)
            }));
            capabilities.extend(inventory.capabilities);
        }
        Ok(CapabilityInventory {
            observed_at: observed_at.unwrap_or_else(|| {
                clock
                    .now()
                    .unwrap_or_else(|_| sysboost_core::Timestamp::from_unix_millis(0))
            }),
            capabilities,
        })
    }

    fn snapshot(
        &self,
        execution: &BackendExecutionToken,
        mutation: &PlannedMutation,
        now: Timestamp,
    ) -> Result<Snapshot, SysboostError> {
        self.backend_for(mutation)?
            .snapshot(execution, mutation, now)
    }

    fn apply(
        &self,
        execution: &BackendExecutionToken,
        mutation: &PlannedMutation,
        snapshot: &Snapshot,
    ) -> Result<ApplyReceipt, SysboostError> {
        self.backend_for(mutation)?
            .apply(execution, mutation, snapshot)
    }

    fn verify(
        &self,
        execution: &BackendExecutionToken,
        mutation: &PlannedMutation,
        expected: StateFingerprint,
        expected_target_identity: TargetIdentity,
    ) -> Result<StateFingerprint, SysboostError> {
        self.backend_for(mutation)?
            .verify(execution, mutation, expected, expected_target_identity)
    }

    fn restore(
        &self,
        execution: &BackendExecutionToken,
        mutation: &PlannedMutation,
        snapshot: &Snapshot,
        expected_ownership: StateFingerprint,
    ) -> Result<RestoreReceipt, SysboostError> {
        self.backend_for(mutation)?
            .restore(execution, mutation, snapshot, expected_ownership)
    }

    fn validate_admission(
        &self,
        mutation: &PlannedMutation,
        expected_target_identity: TargetIdentity,
    ) -> Result<(), SysboostError> {
        self.backend_for(mutation)?
            .validate_admission(mutation, expected_target_identity)
    }

    fn validate_target(
        &self,
        mutation: &PlannedMutation,
        expected_target_identity: TargetIdentity,
    ) -> Result<(), SysboostError> {
        self.backend_for(mutation)?
            .validate_target(mutation, expected_target_identity)
    }
}

impl BackendRegistry {
    fn backend_for(
        &self,
        mutation: &PlannedMutation,
    ) -> Result<&dyn MutationBackend, SysboostError> {
        let operation = mutation.kind.operation_id();
        self.backends
            .iter()
            .find(|backend| {
                backend.descriptor().operations.contains(&operation)
                    && backend
                        .descriptor()
                        .capabilities
                        .contains(&mutation.capability)
            })
            .map(|backend| backend.as_ref())
            .ok_or_else(|| {
                SysboostError::new(
                    sysboost_core::ErrorCode::Unsupported,
                    "no registered backend owns the typed operation",
                )
                .with_capability(mutation.capability.clone())
                .with_mutation(mutation.mutation_id)
            })
    }
}

/// Prevent accidental unused import changes when protocol implementations are
/// added; plan/session types remain part of this port's contract.
#[allow(dead_code)]
fn _protocol_contract_types(_plan: &Plan, _session: SessionId) {}

#[cfg(test)]
mod tests {
    use super::*;
    use sysboost_core::{BackendId, ErrorCode, OperationId};

    struct StubBackend {
        descriptor: BackendDescriptor,
    }

    impl MutationBackend for StubBackend {
        fn descriptor(&self) -> &BackendDescriptor {
            &self.descriptor
        }

        fn detect(&self, _clock: &dyn Clock) -> Result<CapabilityInventory, SysboostError> {
            Err(SysboostError::new(
                ErrorCode::Unsupported,
                "registry test backend has no detector",
            ))
        }

        fn snapshot(
            &self,
            _execution: &BackendExecutionToken,
            _mutation: &PlannedMutation,
            _now: Timestamp,
        ) -> Result<Snapshot, SysboostError> {
            Err(SysboostError::new(
                ErrorCode::Unsupported,
                "registry test backend has no snapshotter",
            ))
        }

        fn apply(
            &self,
            _execution: &BackendExecutionToken,
            _mutation: &PlannedMutation,
            _snapshot: &Snapshot,
        ) -> Result<ApplyReceipt, SysboostError> {
            Err(SysboostError::new(
                ErrorCode::Unsupported,
                "registry test backend has no applier",
            ))
        }

        fn verify(
            &self,
            _execution: &BackendExecutionToken,
            _mutation: &PlannedMutation,
            _expected: StateFingerprint,
            _expected_target_identity: TargetIdentity,
        ) -> Result<StateFingerprint, SysboostError> {
            Err(SysboostError::new(
                ErrorCode::Unsupported,
                "registry test backend has no verifier",
            ))
        }

        fn restore(
            &self,
            _execution: &BackendExecutionToken,
            _mutation: &PlannedMutation,
            _snapshot: &Snapshot,
            _expected_ownership: StateFingerprint,
        ) -> Result<RestoreReceipt, SysboostError> {
            Err(SysboostError::new(
                ErrorCode::Unsupported,
                "registry test backend has no restorer",
            ))
        }
    }

    fn stub_backend(name: &str, capability: &str, operation: &str) -> StubBackend {
        StubBackend {
            descriptor: BackendDescriptor {
                id: BackendId::new(name).expect("valid backend ID"),
                version: "test".to_owned(),
                capabilities: vec![CapabilityId::new(capability).expect("valid capability ID")],
                operations: vec![OperationId::new(operation).expect("valid operation ID")],
            },
        }
    }

    #[test]
    fn registry_rejects_duplicate_capability_ownership() {
        let mut registry = BackendRegistry::new();
        registry
            .register(Box::new(stub_backend(
                "test.first",
                "shared.capability",
                "first.operation",
            )))
            .expect("first backend is unique");

        let error = registry
            .register(Box::new(stub_backend(
                "test.second",
                "shared.capability",
                "second.operation",
            )))
            .expect_err("capability ownership must be unique");
        assert_eq!(error.code, ErrorCode::InvariantViolation);
    }

    #[test]
    fn registry_rejects_duplicate_operation_ownership() {
        let mut registry = BackendRegistry::new();
        registry
            .register(Box::new(stub_backend(
                "test.first",
                "first.capability",
                "shared.operation",
            )))
            .expect("first backend is unique");

        let error = registry
            .register(Box::new(stub_backend(
                "test.second",
                "second.capability",
                "shared.operation",
            )))
            .expect_err("operation ownership must be unique");
        assert_eq!(error.code, ErrorCode::InvariantViolation);
    }
}
