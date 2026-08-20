//! Typed backend and registry ports.

use sysboost_core::{
    ApplyReceipt, BackendId, CapabilityId, CapabilityInventory, OperationId, Plan, PlannedMutation,
    RestoreReceipt, SessionId, Snapshot, StateFingerprint, SysboostError, Timestamp,
};

use crate::clock::Clock;

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

    /// Detect evidence through read-only adapters.
    fn detect(&self, clock: &dyn Clock) -> Result<CapabilityInventory, SysboostError>;

    /// Capture a complete preimage before any apply.
    fn snapshot(
        &self,
        mutation: &PlannedMutation,
        now: Timestamp,
    ) -> Result<Snapshot, SysboostError>;

    /// Apply one typed operation after durable intent exists.
    fn apply(
        &self,
        mutation: &PlannedMutation,
        snapshot: &Snapshot,
    ) -> Result<ApplyReceipt, SysboostError>;

    /// Verify a typed postcondition by readback.
    fn verify(
        &self,
        mutation: &PlannedMutation,
        expected: StateFingerprint,
    ) -> Result<StateFingerprint, SysboostError>;

    /// Restore one complete preimage.
    fn restore(
        &self,
        mutation: &PlannedMutation,
        snapshot: &Snapshot,
    ) -> Result<RestoreReceipt, SysboostError>;
}

/// Registry of reviewed, compiled-in backends.
#[derive(Default)]
pub struct BackendRegistry {
    backends: Vec<Box<dyn MutationBackend>>,
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
            _mutation: &PlannedMutation,
            _expected: StateFingerprint,
        ) -> Result<StateFingerprint, SysboostError> {
            Err(SysboostError::new(
                ErrorCode::Unsupported,
                "registry test backend has no verifier",
            ))
        }

        fn restore(
            &self,
            _mutation: &PlannedMutation,
            _snapshot: &Snapshot,
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
