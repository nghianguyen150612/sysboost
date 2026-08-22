//! Safe report-only backend placeholder.

use sysboost_core::{
    ApplyReceipt, CapabilityInventory, ErrorCode, PlannedMutation, RestoreReceipt, Snapshot,
    StateFingerprint, SysboostError, Timestamp,
};
use sysboost_platform::{BackendDescriptor, BackendExecutionToken, Clock, MutationBackend};

/// A compiled-in backend that advertises no mutations and always remains
/// report-only. It proves the registry/trait shape without touching hardware.
#[derive(Clone, Debug)]
pub struct ReportOnlyBackend {
    descriptor: BackendDescriptor,
}

impl ReportOnlyBackend {
    /// Construct the empty Linux foundation backend.
    pub fn new() -> Self {
        Self {
            descriptor: BackendDescriptor {
                id: sysboost_core::BackendId::new("linux.report_only")
                    .expect("static backend ID is valid"),
                version: "0.1.0-foundation".to_owned(),
                capabilities: Vec::new(),
                operations: Vec::new(),
            },
        }
    }
}

impl Default for ReportOnlyBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MutationBackend for ReportOnlyBackend {
    fn descriptor(&self) -> &BackendDescriptor {
        &self.descriptor
    }

    fn detect(&self, clock: &dyn Clock) -> Result<CapabilityInventory, SysboostError> {
        Ok(CapabilityInventory {
            observed_at: clock.now()?,
            capabilities: Vec::new(),
        })
    }

    fn snapshot(
        &self,
        _execution: &BackendExecutionToken,
        _mutation: &PlannedMutation,
        _now: Timestamp,
    ) -> Result<Snapshot, SysboostError> {
        Err(unsupported())
    }

    fn apply(
        &self,
        _execution: &BackendExecutionToken,
        _mutation: &PlannedMutation,
        _snapshot: &Snapshot,
    ) -> Result<ApplyReceipt, SysboostError> {
        Err(unsupported())
    }

    fn verify(
        &self,
        _execution: &BackendExecutionToken,
        _mutation: &PlannedMutation,
        _expected: StateFingerprint,
        _expected_target_identity: sysboost_core::TargetIdentity,
    ) -> Result<StateFingerprint, SysboostError> {
        Err(unsupported())
    }

    fn restore(
        &self,
        _execution: &BackendExecutionToken,
        _mutation: &PlannedMutation,
        _snapshot: &Snapshot,
        _expected_ownership: StateFingerprint,
    ) -> Result<RestoreReceipt, SysboostError> {
        Err(unsupported())
    }
}

fn unsupported() -> SysboostError {
    SysboostError::new(
        ErrorCode::Unsupported,
        "runtime Linux mutation backends are deferred from the foundation skeleton",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use sysboost_platform::{BackendRegistry, FixedClock};

    #[test]
    fn report_only_backend_registers_without_mutation_operations() {
        let backend = ReportOnlyBackend::new();
        let mut registry = BackendRegistry::new();
        registry
            .register(Box::new(backend))
            .expect("unique backend");
        assert_eq!(registry.len(), 1);
        let inventory = registry
            .iter()
            .next()
            .expect("registered backend")
            .detect(&FixedClock::new(Timestamp::from_unix_millis(1)))
            .expect("report-only detection");
        assert!(inventory.capabilities.is_empty());
    }
}
