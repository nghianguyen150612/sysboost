//! Reviewed Linux CPU power-policy backend.
//!
//! This module is the first Linux backend allowed to mutate host state.  It
//! does not expose a generic sysfs writer: every I/O request is one of the
//! closed [`CpuNode`] families and every value is a domain-typed
//! [`sysboost_core::TypedValue`].  The production adapter derives all paths
//! from those enums and rejects symlinks, unexpected objects, and changed
//! target identities.

use std::collections::{BTreeSet, HashMap};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use sysboost_core::{
    fingerprint_for_value, ApplyReceipt, BackendId, BoundedBytes, CapabilityDescriptor,
    CapabilityEvidence, CapabilityId, CapabilityInventory, CapabilityState, CpuBoostState,
    CpuPolicyId, EnergyPreference, EqualityKind, ErrorCode, EvidenceSource, FeatureClass,
    FrequencyKHz, GovernorId, MutationKind, OperationCatalog, OperationContract,
    OperationDescriptor, OperationId, PlanValue, PlannedMutation, PlatformProfileId,
    PrivilegeRequirement, RestoreReceipt, RiskClass, Snapshot, Stage, StateFingerprint,
    SysboostError, TargetId, TargetIdentity, TargetKind, Timestamp, TypedValue,
};
use sysboost_platform::{BackendDescriptor, BackendExecutionToken, Clock, MutationBackend};

/// Backend identity used by discovery, planning, and helper admission.
pub const CPU_BACKEND_ID: &str = "linux.cpu";

const CPU_BOOST_TARGET: &str = "system.cpu.boost";
const PLATFORM_PROFILE_TARGET: &str = "system.platform.profile";
const MAX_CPU_READ_BYTES: usize = 4096;
const MAX_CPU_POLICIES: usize = 4096;

/// Which kernel interface provided the CPU boost state.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CpuBoostInterface {
    /// Linux `cpufreq/boost`, where `1` means enabled.
    Boost,
    /// Linux `cpufreq/no_turbo`, where `0` means enabled.
    NoTurbo,
}

/// A closed CPU target family.  No path or arbitrary node name is accepted.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CpuNode {
    /// Per-policy governor node.
    Governor(CpuPolicyId),
    /// Per-policy energy-performance preference node.
    EnergyPreference(CpuPolicyId),
    /// Per-policy min/max frequency pair.
    Frequency(CpuPolicyId),
    /// Host-wide boost/turbo node; `None` selects the detected interface and
    /// `Some` pins a write to the interface observed during the read.
    Boost(Option<CpuBoostInterface>),
    /// Host-wide ACPI/platform profile node.
    PlatformProfile,
}

/// Complete typed state returned by a CPU node read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CpuNodeState {
    /// Bounded original bytes retained for the transaction preimage.
    pub raw: BoundedBytes,
    /// Typed interpretation of the current node state.
    pub typed: TypedValue,
    /// Fingerprint of the typed current value.
    pub fingerprint: StateFingerprint,
    /// Backend-owned identity of the policy directory or global node.
    pub target_identity: TargetIdentity,
    /// Selected boost interface for a boost read, when applicable.
    pub boost_interface: Option<CpuBoostInterface>,
}

/// Narrow typed port used only inside the CPU backend.  Implementations cannot
/// receive a controller path or arbitrary bytes; production uses the private
/// [`CpuSysfs`] adapter and tests use [`CpuFixture`].
trait CpuControlIo: Send + Sync {
    /// Enumerate actual CPUFreq policies.
    fn list_policies(&self) -> Result<Vec<CpuPolicyId>, SysboostError>;

    /// Read one closed CPU node and capture its identity.
    fn read(&self, node: CpuNode) -> Result<CpuNodeState, SysboostError>;

    /// Return values explicitly advertised by the selected kernel interface.
    fn choices(&self, node: CpuNode) -> Result<Vec<TypedValue>, SysboostError>;

    /// Validate a desired value against the live typed interface bounds.
    fn validate_desired(&self, node: CpuNode, desired: &TypedValue) -> Result<(), SysboostError>;

    /// Write one closed typed CPU node.
    fn write(&self, node: CpuNode, desired: &TypedValue) -> Result<(), SysboostError>;
}

/// CPU backend whose mutation stages require the platform transaction token.
///
/// ```compile_fail
/// use sysboost_linux::CpuBackend;
///
/// let backend = CpuBackend::production().expect("production backend");
/// backend.io().write((), &());
/// ```
///
/// The inspection handle returned by [`CpuBackend::io`] intentionally has no
/// writable method.  The backend's mutation-stage trait methods similarly
/// require an unforgeable execution token owned by `TransactionEngine`.
///
/// ```compile_fail
/// use sysboost_linux::CpuBackend;
/// use sysboost_platform::MutationBackend;
///
/// let backend = CpuBackend::production().expect("production backend");
/// backend.snapshot(&todo!(), &todo!());
/// ```
pub struct CpuBackend {
    io: Box<dyn CpuControlIo>,
    descriptor: BackendDescriptor,
}

/// Read-only inspection view over the CPU backend's internal adapter.
///
/// The view deliberately has no generic write method and does not expose the
/// private CPU adapter trait.  It is suitable for capability inspection
/// and fixture assertions; all mutation remains behind the transaction-owned
/// [`BackendExecutionToken`].
pub struct CpuInspection<'a> {
    io: &'a dyn CpuControlIo,
}

impl CpuInspection<'_> {
    /// Enumerate actual CPUFreq policies.
    pub fn list_policies(&self) -> Result<Vec<CpuPolicyId>, SysboostError> {
        self.io.list_policies()
    }

    /// Read one closed CPU node and capture its identity.
    pub fn read(&self, node: CpuNode) -> Result<CpuNodeState, SysboostError> {
        self.io.read(node)
    }

    /// Return values advertised by the selected CPU interface.
    pub fn choices(&self, node: CpuNode) -> Result<Vec<TypedValue>, SysboostError> {
        self.io.choices(node)
    }
}

impl CpuBackend {
    /// Construct a CPU backend over a typed CPU I/O adapter.
    fn new(io: Box<dyn CpuControlIo>) -> Self {
        Self {
            io,
            descriptor: backend_descriptor(),
        }
    }

    /// Construct the production backend rooted at the host `/sys` tree.
    pub fn production() -> Result<Self, SysboostError> {
        Ok(Self::new(Box::new(CpuSysfs::new("/sys")?)))
    }

    /// Construct a backend over a deterministic fixture.
    ///
    /// This composition-root helper is intentionally limited to
    /// [`CpuFixture`].  It does not expose the production adapter or its
    /// writable I/O port.
    pub fn from_fixture(fixture: CpuFixture) -> Self {
        Self::new(Box::new(fixture))
    }

    /// Borrow a read-only inspection view of the backend adapter.
    pub fn io(&self) -> CpuInspection<'_> {
        CpuInspection {
            io: self.io.as_ref(),
        }
    }

    fn node_for_mutation(&self, mutation: &PlannedMutation) -> Result<CpuNode, SysboostError> {
        match mutation.kind {
            MutationKind::CpuFrequency { policy, .. } => Ok(CpuNode::Frequency(policy)),
            MutationKind::CpuGovernor { policy, .. } => Ok(CpuNode::Governor(policy)),
            MutationKind::CpuEnergyPreference { policy, .. } => {
                Ok(CpuNode::EnergyPreference(policy))
            }
            MutationKind::CpuBoost { .. } => Ok(CpuNode::Boost(None)),
            MutationKind::PlatformProfile { .. } => Ok(CpuNode::PlatformProfile),
            _ => Err(unsupported("CPU backend does not own this typed operation")),
        }
    }

    fn expected_target(mutation: &PlannedMutation) -> Result<TargetId, SysboostError> {
        match mutation.kind {
            MutationKind::CpuFrequency { policy, .. }
            | MutationKind::CpuGovernor { policy, .. }
            | MutationKind::CpuEnergyPreference { policy, .. } => {
                TargetId::new(format!("cpu.policy.{}", policy.get()))
                    .map_err(|_| target_error("CPU policy target is invalid"))
            }
            MutationKind::CpuBoost { .. } => TargetId::new(CPU_BOOST_TARGET)
                .map_err(|_| target_error("CPU boost target is invalid")),
            MutationKind::PlatformProfile { .. } => TargetId::new(PLATFORM_PROFILE_TARGET)
                .map_err(|_| target_error("platform profile target is invalid")),
            _ => Err(unsupported("CPU backend does not own this typed operation")),
        }
    }

    fn validate_state(
        mutation: &PlannedMutation,
        state: &CpuNodeState,
    ) -> Result<(), SysboostError> {
        if state.target_identity.as_bytes() == &[0; 16]
            || state.fingerprint != fingerprint_for_value(&PlanValue::Typed(state.typed.clone()))
        {
            return Err(SysboostError::new(
                ErrorCode::TargetError,
                "CPU adapter returned invalid target identity or value fingerprint",
            )
            .with_stage(Stage::Snapshot)
            .with_mutation(mutation.mutation_id));
        }
        let matching_shape = matches!(
            (&mutation.kind, &state.typed),
            (
                MutationKind::CpuFrequency { .. },
                TypedValue::CpuFrequency { .. }
            ) | (MutationKind::CpuGovernor { .. }, TypedValue::Governor(_))
                | (
                    MutationKind::CpuEnergyPreference { .. },
                    TypedValue::EnergyPreference(_)
                )
                | (MutationKind::CpuBoost { .. }, TypedValue::CpuBoost(_))
                | (
                    MutationKind::PlatformProfile { .. },
                    TypedValue::PlatformProfile(_)
                )
        );
        if !matching_shape || state.fingerprint != mutation.precondition {
            return Err(SysboostError::new(
                ErrorCode::TargetError,
                "CPU target changed or its typed state does not match the plan precondition",
            )
            .with_stage(Stage::Snapshot)
            .with_mutation(mutation.mutation_id));
        }
        if matches!(mutation.kind, MutationKind::CpuFrequency { .. }) {
            let valid_range = matches!(
                &state.typed,
                TypedValue::CpuFrequency {
                    min_khz: Some(min),
                    max_khz: Some(max),
                } if min <= max
            );
            if !valid_range {
                return Err(target_error(
                    "CPU frequency snapshot does not contain a complete valid range",
                )
                .with_stage(Stage::Snapshot)
                .with_mutation(mutation.mutation_id));
            }
        }
        let desired = Self::effective_desired(mutation, &state.typed)?;
        if desired == state.typed {
            return Err(SysboostError::new(
                ErrorCode::InvariantViolation,
                "CPU mutation is already equal to its current typed state",
            )
            .with_stage(Stage::Plan)
            .with_mutation(mutation.mutation_id));
        }
        Ok(())
    }

    fn effective_desired(
        mutation: &PlannedMutation,
        current: &TypedValue,
    ) -> Result<TypedValue, SysboostError> {
        match (&mutation.kind, &mutation.desired, current) {
            (
                MutationKind::CpuFrequency { .. },
                TypedValue::CpuFrequency {
                    min_khz: desired_min,
                    max_khz: desired_max,
                },
                TypedValue::CpuFrequency {
                    min_khz: current_min,
                    max_khz: current_max,
                },
            ) => {
                let min_khz = desired_min.as_ref().copied().or(*current_min);
                let max_khz = desired_max.as_ref().copied().or(*current_max);
                if min_khz.is_none() || max_khz.is_none() {
                    return Err(target_error(
                        "CPU frequency state is incomplete for a reversible mutation",
                    ));
                }
                Ok(TypedValue::CpuFrequency { min_khz, max_khz })
            }
            (_, desired, _) => Ok(desired.clone()),
        }
    }

    fn validate_target_state(
        &self,
        mutation: &PlannedMutation,
        expected_target_identity: TargetIdentity,
    ) -> Result<(CpuNode, CpuNodeState), SysboostError> {
        let expected_target = Self::expected_target(mutation)?;
        if mutation.target != expected_target {
            return Err(
                target_error("CPU mutation target is not the canonical backend target")
                    .with_mutation(mutation.mutation_id),
            );
        }
        let node = self.node_for_mutation(mutation)?;
        let state = self.io.read(node)?;
        if state.target_identity != expected_target_identity {
            return Err(target_error("CPU target identity changed since planning")
                .with_mutation(mutation.mutation_id)
                .with_target(mutation.target.clone()));
        }
        self.io
            .validate_desired(node, &mutation.desired)
            .map_err(|error| error.with_mutation(mutation.mutation_id))?;
        Ok((node, state))
    }

    fn resolved_node(node: CpuNode, state: &CpuNodeState) -> CpuNode {
        match node {
            CpuNode::Boost(None) => CpuNode::Boost(state.boost_interface),
            other => other,
        }
    }

    fn restore_after_failed_apply(
        &self,
        node: CpuNode,
        snapshot: &Snapshot,
    ) -> Result<(), SysboostError> {
        let current = self.io.read(node)?;
        if current.target_identity != snapshot.target_identity {
            return Err(target_error(
                "CPU target identity changed during failed apply",
            ));
        }
        let resolved = Self::resolved_node(node, &current);
        self.io.write(resolved, &snapshot.original_typed)?;
        let restored = self.io.read(resolved)?;
        if restored.target_identity != snapshot.target_identity
            || restored.fingerprint != snapshot.original_fingerprint
        {
            return Err(SysboostError::new(
                ErrorCode::RestoreError,
                "CPU backend could not prove its internal failed-apply restore",
            ));
        }
        Ok(())
    }

    fn snapshot_internal(
        &self,
        mutation: &PlannedMutation,
        now: Timestamp,
    ) -> Result<Snapshot, SysboostError> {
        let node = self.node_for_mutation(mutation)?;
        let state = self.io.read(node)?;
        Self::validate_state(mutation, &state)?;
        Ok(Snapshot {
            mutation_id: mutation.mutation_id,
            target: mutation.target.clone(),
            original_raw: state.raw,
            original_typed: state.typed,
            original_fingerprint: state.fingerprint,
            equality: EqualityKind::ScalarExact,
            target_identity: state.target_identity,
            captured_at: now,
        })
    }

    fn apply_internal(
        &self,
        mutation: &PlannedMutation,
        snapshot: &Snapshot,
    ) -> Result<ApplyReceipt, SysboostError> {
        let node = self.node_for_mutation(mutation)?;
        let current = self.io.read(node)?;
        if current.target_identity != snapshot.target_identity
            || current.fingerprint != mutation.precondition
        {
            return Err(target_error("CPU target changed before apply"));
        }
        self.io.validate_desired(node, &mutation.desired)?;
        let effective_desired = Self::effective_desired(mutation, &current.typed)?;
        let resolved = Self::resolved_node(node, &current);
        if let Err(error) = self.io.write(resolved, &mutation.desired) {
            let recovery = self.restore_after_failed_apply(node, snapshot);
            return Err(match recovery {
                Ok(()) => error.retryable(sysboost_core::Retryability::Retry),
                Err(_) => error.retryable(sysboost_core::Retryability::Unknown),
            });
        }
        let after = match self.io.read(resolved) {
            Ok(after) => after,
            Err(error) => {
                let recovery = self.restore_after_failed_apply(node, snapshot);
                return Err(match recovery {
                    Ok(()) => error.retryable(sysboost_core::Retryability::Retry),
                    Err(_) => error.retryable(sysboost_core::Retryability::Unknown),
                });
            }
        };
        if after.target_identity != snapshot.target_identity
            || after.fingerprint != fingerprint_for_value(&PlanValue::Typed(effective_desired))
        {
            let error = SysboostError::new(
                ErrorCode::VerificationError,
                "CPU apply readback did not prove the desired typed value",
            );
            let recovery = self.restore_after_failed_apply(node, snapshot);
            return Err(match recovery {
                Ok(()) => error.retryable(sysboost_core::Retryability::Retry),
                Err(_) => error.retryable(sysboost_core::Retryability::Unknown),
            });
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
        let node = self.node_for_mutation(mutation)?;
        let state = self.io.read(node)?;
        if state.target_identity != expected_target_identity {
            return Err(target_error(
                "CPU target identity changed during verification",
            ));
        }
        Ok(state.fingerprint)
    }

    fn restore_internal(
        &self,
        mutation: &PlannedMutation,
        snapshot: &Snapshot,
        expected_ownership: StateFingerprint,
    ) -> Result<RestoreReceipt, SysboostError> {
        let node = self.node_for_mutation(mutation)?;
        let current = self.io.read(node)?;
        if current.target_identity != snapshot.target_identity {
            return Err(target_error("CPU target identity changed before restore"));
        }
        if current.fingerprint != expected_ownership {
            return Err(SysboostError::new(
                ErrorCode::RestoreConflict,
                "CPU target changed outside this session; restore refused",
            ));
        }
        let resolved = Self::resolved_node(node, &current);
        self.io.write(resolved, &snapshot.original_typed)?;
        let restored = self.io.read(resolved)?;
        if restored.target_identity != snapshot.target_identity
            || restored.fingerprint != snapshot.original_fingerprint
        {
            return Err(SysboostError::new(
                ErrorCode::RestoreError,
                "CPU restore readback did not prove the captured original",
            ));
        }
        Ok(RestoreReceipt {
            mutation_id: mutation.mutation_id,
            restored_fingerprint: restored.fingerprint,
            verified: true,
        })
    }
}

impl MutationBackend for CpuBackend {
    fn descriptor(&self) -> &BackendDescriptor {
        &self.descriptor
    }

    fn detect(&self, clock: &dyn Clock) -> Result<CapabilityInventory, SysboostError> {
        let policies = match self.io.list_policies() {
            Ok(policies) => policies,
            Err(error) if error.code == ErrorCode::Unsupported => Vec::new(),
            Err(error) => return Err(error),
        };
        let governor_available = policies.iter().any(|policy| {
            self.io.read(CpuNode::Governor(*policy)).is_ok()
                && self
                    .io
                    .choices(CpuNode::Governor(*policy))
                    .is_ok_and(|choices| !choices.is_empty())
        });
        let epp_available = policies.iter().any(|policy| {
            self.io.read(CpuNode::EnergyPreference(*policy)).is_ok()
                && self
                    .io
                    .choices(CpuNode::EnergyPreference(*policy))
                    .is_ok_and(|choices| !choices.is_empty())
        });
        let frequency_available = policies
            .iter()
            .any(|policy| self.io.read(CpuNode::Frequency(*policy)).is_ok());
        let boost_available = self.io.read(CpuNode::Boost(None)).is_ok();
        let profile_available = self.io.read(CpuNode::PlatformProfile).is_ok()
            && self
                .io
                .choices(CpuNode::PlatformProfile)
                .is_ok_and(|choices| !choices.is_empty());
        let observed_at = clock.now()?;
        let mut capabilities = Vec::new();
        for (capability, operation, target_kind, available, class) in [
            (
                "cpu.policy.frequency.min",
                "cpu.frequency",
                TargetKind::CpuPolicy,
                frequency_available,
                FeatureClass::RuntimeMutable,
            ),
            (
                "cpu.policy.frequency.max",
                "cpu.frequency",
                TargetKind::CpuPolicy,
                frequency_available,
                FeatureClass::RuntimeMutable,
            ),
            (
                "cpu.policy.governor",
                "cpu.governor",
                TargetKind::CpuPolicy,
                governor_available,
                FeatureClass::RuntimeMutable,
            ),
            (
                "cpu.policy.energy_preference",
                "cpu.energy_preference",
                TargetKind::CpuPolicy,
                epp_available,
                FeatureClass::RuntimeMutable,
            ),
            (
                "cpu.policy.boost",
                "cpu.boost",
                TargetKind::CpuSystem,
                boost_available,
                FeatureClass::RuntimeMutable,
            ),
            (
                "platform.profile",
                "platform.profile",
                TargetKind::CpuSystem,
                profile_available,
                FeatureClass::Conditional,
            ),
        ] {
            capabilities.push(cpu_capability_descriptor(
                capability_id(capability),
                operation_id(operation),
                target_kind,
                available,
                class,
            ));
        }
        Ok(CapabilityInventory {
            observed_at,
            capabilities,
        })
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

    fn validate_admission(
        &self,
        mutation: &PlannedMutation,
        expected_target_identity: TargetIdentity,
    ) -> Result<(), SysboostError> {
        let capability_owned = match mutation.kind {
            MutationKind::CpuFrequency { .. } => {
                mutation.capability == capability_id("cpu.policy.frequency.min")
                    || mutation.capability == capability_id("cpu.policy.frequency.max")
            }
            MutationKind::CpuGovernor { .. } => {
                mutation.capability == capability_id("cpu.policy.governor")
            }
            MutationKind::CpuEnergyPreference { .. } => {
                mutation.capability == capability_id("cpu.policy.energy_preference")
            }
            MutationKind::CpuBoost { .. } => {
                mutation.capability == capability_id("cpu.policy.boost")
            }
            MutationKind::PlatformProfile { .. } => {
                mutation.capability == capability_id("platform.profile")
            }
            _ => {
                return Err(unsupported("CPU backend does not own this typed operation")
                    .with_mutation(mutation.mutation_id));
            }
        };
        if !self
            .descriptor
            .operations
            .contains(&mutation.kind.operation_id())
            || !capability_owned
        {
            return Err(
                unsupported("CPU operation and capability ownership do not match")
                    .with_capability(mutation.capability.clone())
                    .with_mutation(mutation.mutation_id),
            );
        }
        self.validate_target(mutation, expected_target_identity)
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

    fn validate_target(
        &self,
        mutation: &PlannedMutation,
        expected_target_identity: TargetIdentity,
    ) -> Result<(), SysboostError> {
        let (_, state) = self.validate_target_state(mutation, expected_target_identity)?;
        if state.fingerprint == mutation.precondition {
            Ok(())
        } else {
            Err(target_error("CPU target value changed since planning"))
        }
    }
}

/// Production CPU adapter.  The root is canonicalized once, and every
/// operation revalidates all fixed path components before opening the final
/// typed node.
#[derive(Clone, Debug)]
struct CpuSysfs {
    root: PathBuf,
}

impl CpuSysfs {
    /// Open an approved sysfs root.
    fn new(root: impl AsRef<Path>) -> Result<Self, SysboostError> {
        let supplied_metadata = fs::symlink_metadata(root.as_ref())
            .map_err(|_| target_error("CPU sysfs root cannot be inspected"))?;
        if supplied_metadata.file_type().is_symlink() || !supplied_metadata.file_type().is_dir() {
            return Err(target_error("CPU sysfs root is not a real directory"));
        }
        let root = fs::canonicalize(root.as_ref())
            .map_err(|_| target_error("CPU sysfs root cannot be resolved"))?;
        let metadata = fs::symlink_metadata(&root)
            .map_err(|_| target_error("CPU sysfs root cannot be inspected"))?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err(target_error("CPU sysfs root is not a directory"));
        }
        Ok(Self { root })
    }

    fn cpufreq_dir(&self) -> Result<PathBuf, SysboostError> {
        let components = ["devices", "system", "cpu", "cpufreq"];
        let mut current = self.root.clone();
        for component in components {
            current.push(component);
            match fs::symlink_metadata(&current) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                        return Err(target_error(
                            "CPU sysfs cpufreq path has an unexpected type",
                        ));
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Err(unsupported("CPUFreq policy interface is unavailable"));
                }
                Err(_) => return Err(target_error("CPU sysfs cpufreq path cannot be inspected")),
            }
        }
        Ok(current)
    }

    fn policy_dir(&self, policy: CpuPolicyId) -> Result<PathBuf, SysboostError> {
        self.checked_component_path(
            &[
                "devices",
                "system",
                "cpu",
                "cpufreq",
                &format!("policy{}", policy.get()),
            ],
            true,
        )
    }

    fn checked_component_path(
        &self,
        components: &[&str],
        final_directory: bool,
    ) -> Result<PathBuf, SysboostError> {
        let mut current = self.root.clone();
        let root_metadata = fs::symlink_metadata(&current)
            .map_err(|_| target_error("CPU sysfs root disappeared"))?;
        if root_metadata.file_type().is_symlink() || !root_metadata.file_type().is_dir() {
            return Err(target_error("CPU sysfs root has an unexpected type"));
        }
        for (index, component) in components.iter().enumerate() {
            if component.is_empty() || *component == "." || *component == ".." {
                return Err(target_error("CPU backend component is not allowlisted"));
            }
            current.push(component);
            let metadata = fs::symlink_metadata(&current)
                .map_err(|_| target_error("CPU sysfs target disappeared"))?;
            if metadata.file_type().is_symlink()
                || (index + 1 < components.len() && !metadata.file_type().is_dir())
                || (index + 1 == components.len()
                    && final_directory
                    && !metadata.file_type().is_dir())
            {
                return Err(target_error("CPU sysfs target has an unexpected type"));
            }
        }
        Ok(current)
    }

    fn node_path(
        &self,
        node: CpuNode,
    ) -> Result<(PathBuf, Option<CpuBoostInterface>), SysboostError> {
        match node {
            CpuNode::Governor(policy) => Ok((self.policy_file(policy, "scaling_governor")?, None)),
            CpuNode::EnergyPreference(policy) => Ok((
                self.policy_file(policy, "energy_performance_preference")?,
                None,
            )),
            CpuNode::Frequency(policy) => Ok((self.policy_dir(policy)?, None)),
            CpuNode::Boost(interface) => {
                let directory = self.cpufreq_dir()?;
                let candidates = match interface {
                    Some(CpuBoostInterface::Boost) => {
                        vec![("boost", CpuBoostInterface::Boost)]
                    }
                    Some(CpuBoostInterface::NoTurbo) => {
                        vec![("no_turbo", CpuBoostInterface::NoTurbo)]
                    }
                    None => vec![
                        ("boost", CpuBoostInterface::Boost),
                        ("no_turbo", CpuBoostInterface::NoTurbo),
                    ],
                };
                for (name, selected) in candidates {
                    let path = directory.join(name);
                    match fs::symlink_metadata(&path) {
                        Ok(metadata) if metadata.file_type().is_symlink() => {
                            return Err(target_error("CPU boost node is a symlink"));
                        }
                        Ok(metadata) if metadata.file_type().is_file() => {
                            return Ok((path, Some(selected)))
                        }
                        Ok(_) => return Err(target_error("CPU boost node has an unexpected type")),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(_) => return Err(target_error("CPU boost node cannot be inspected")),
                    }
                }
                Err(unsupported("CPU boost/turbo interface is unavailable"))
            }
            CpuNode::PlatformProfile => Ok((
                self.checked_component_path(&["firmware", "acpi"], true)?
                    .join("platform_profile"),
                None,
            )),
        }
    }

    fn policy_file(&self, policy: CpuPolicyId, file: &str) -> Result<PathBuf, SysboostError> {
        if !matches!(
            file,
            "scaling_governor"
                | "energy_performance_preference"
                | "scaling_min_freq"
                | "scaling_max_freq"
                | "scaling_cur_freq"
                | "scaling_available_governors"
                | "energy_performance_available_preferences"
                | "cpuinfo_min_freq"
                | "cpuinfo_max_freq"
        ) {
            return Err(target_error("CPU policy file is not allowlisted"));
        }
        let directory = self.policy_dir(policy)?;
        let path = directory.join(file);
        validate_final_file(&path)?;
        Ok(path)
    }

    fn read_file(&self, path: &Path) -> Result<Vec<u8>, SysboostError> {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(target_os = "linux")]
        std::os::unix::fs::OpenOptionsExt::custom_flags(
            &mut options,
            open_cloexec_flags() | open_nofollow_flags(),
        );
        let file = options
            .open(path)
            .map_err(|_| target_error("CPU kernel interface cannot be opened"))?;
        let metadata = file
            .metadata()
            .map_err(|_| target_error("CPU kernel interface cannot be inspected"))?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err(target_error("CPU kernel interface is not a regular node"));
        }
        let mut bytes = Vec::new();
        file.take((MAX_CPU_READ_BYTES as u64).saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| target_error("CPU kernel interface cannot be read"))?;
        if bytes.len() > MAX_CPU_READ_BYTES {
            return Err(target_error("CPU kernel interface value is oversized"));
        }
        Ok(bytes)
    }

    fn write_file(&self, path: &Path, value: &str) -> Result<(), SysboostError> {
        if value.is_empty() || value.len() > 128 || value.contains('\0') || value.contains('\n') {
            return Err(SysboostError::new(
                ErrorCode::InvalidInput,
                "CPU backend generated an invalid kernel value",
            ));
        }
        validate_final_file(path)?;
        let mut options = OpenOptions::new();
        options.write(true);
        #[cfg(target_os = "linux")]
        std::os::unix::fs::OpenOptionsExt::custom_flags(
            &mut options,
            open_cloexec_flags() | open_nofollow_flags(),
        );
        let mut file = options
            .open(path)
            .map_err(|_| target_error("CPU kernel interface cannot be opened for writing"))?;
        file.write_all(value.as_bytes())
            .map_err(|_| SysboostError::new(ErrorCode::ApplyError, "CPU kernel write failed"))
    }

    fn raw_node(
        &self,
        node: CpuNode,
    ) -> Result<(Vec<u8>, TargetIdentity, Option<CpuBoostInterface>), SysboostError> {
        let (path, interface) = self.node_path(node)?;
        let raw = if matches!(node, CpuNode::Frequency(_)) {
            let policy = match node {
                CpuNode::Frequency(policy) => policy,
                _ => unreachable!(),
            };
            let min = self.read_file(&self.policy_file(policy, "scaling_min_freq")?)?;
            let max = self.read_file(&self.policy_file(policy, "scaling_max_freq")?)?;
            let mut bytes = min;
            bytes.push(0);
            bytes.extend_from_slice(&max);
            bytes
        } else {
            self.read_file(&path)?
        };
        let identity = if let CpuNode::Frequency(policy) = node {
            directory_identity(&self.policy_dir(policy)?)?
        } else {
            node_identity(&path, interface)?
        };
        Ok((raw, identity, interface))
    }

    fn parse_node(
        &self,
        node: CpuNode,
    ) -> Result<
        (
            TypedValue,
            Vec<u8>,
            TargetIdentity,
            Option<CpuBoostInterface>,
        ),
        SysboostError,
    > {
        let (raw, identity, interface) = self.raw_node(node)?;
        let typed = match node {
            CpuNode::Governor(_) => TypedValue::Governor(parse_governor(&raw)?),
            CpuNode::EnergyPreference(_) => TypedValue::EnergyPreference(parse_energy(&raw)?),
            CpuNode::Frequency(_) => {
                let split = raw.split(|byte| *byte == 0);
                let values = split.collect::<Vec<_>>();
                if values.len() != 2 {
                    return Err(target_error("CPU frequency state is malformed"));
                }
                TypedValue::CpuFrequency {
                    min_khz: Some(parse_frequency(values[0])?),
                    max_khz: Some(parse_frequency(values[1])?),
                }
            }
            CpuNode::Boost(_) => TypedValue::CpuBoost(parse_boost(
                interface.ok_or_else(|| target_error("CPU boost interface is unknown"))?,
                &raw,
            )?),
            CpuNode::PlatformProfile => TypedValue::PlatformProfile(parse_profile(&raw)?),
        };
        Ok((typed, raw, identity, interface))
    }

    fn choices_text(&self, node: CpuNode) -> Result<Vec<String>, SysboostError> {
        let bytes = match node {
            CpuNode::Governor(policy) => {
                self.read_file(&self.policy_file(policy, "scaling_available_governors")?)?
            }
            CpuNode::EnergyPreference(policy) => self.read_file(
                &self.policy_file(policy, "energy_performance_available_preferences")?,
            )?,
            CpuNode::PlatformProfile => {
                let path = self
                    .checked_component_path(&["firmware", "acpi"], true)?
                    .join("platform_profile_choices");
                validate_final_file(&path)?;
                self.read_file(&path)?
            }
            CpuNode::Boost(_) | CpuNode::Frequency(_) => return Ok(Vec::new()),
        };
        let value = std::str::from_utf8(&bytes)
            .map_err(|_| target_error("CPU kernel choices are not valid text"))?;
        Ok(value.split_whitespace().map(str::to_owned).collect())
    }

    fn read_optional_frequency(
        &self,
        policy: CpuPolicyId,
        file: &str,
    ) -> Result<Option<FrequencyKHz>, SysboostError> {
        let directory = self.policy_dir(policy)?;
        let path = directory.join(file);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                Err(target_error("CPU hardware-bound node is a symlink"))
            }
            Ok(metadata) if !metadata.file_type().is_file() => Err(target_error(
                "CPU hardware-bound node has an unexpected type",
            )),
            Ok(_) => self
                .read_file(&path)
                .and_then(|raw| parse_frequency(&raw))
                .map(Some),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(target_error("CPU hardware-bound node cannot be inspected")),
        }
    }

    fn write_frequency(
        &self,
        policy: CpuPolicyId,
        desired: &TypedValue,
    ) -> Result<(), SysboostError> {
        let TypedValue::CpuFrequency { min_khz, max_khz } = desired else {
            return Err(target_error(
                "CPU frequency operation has the wrong typed value",
            ));
        };
        let current = self.read(CpuNode::Frequency(policy))?;
        let TypedValue::CpuFrequency {
            min_khz: current_min,
            max_khz: current_max,
        } = current.typed
        else {
            return Err(target_error("CPU frequency current state is malformed"));
        };
        let current_min = current_min.ok_or_else(|| target_error("CPU minimum is unavailable"))?;
        let current_max = current_max.ok_or_else(|| target_error("CPU maximum is unavailable"))?;
        if let (Some(min), Some(max)) = (min_khz, max_khz) {
            if min > max {
                return Err(target_error("CPU desired minimum exceeds maximum"));
            }
        }
        let desired_min = min_khz.unwrap_or(current_min);
        let desired_max = max_khz.unwrap_or(current_max);
        if desired_min > desired_max {
            return Err(target_error("CPU desired frequency range is invalid"));
        }
        // Lowering a maximum below the current minimum requires lowering the
        // minimum first.  All other transitions raise/retain the maximum
        // first so the kernel never observes an invalid transient range.
        let min_first = desired_max < current_min;
        if min_first {
            if let Some(min) = min_khz {
                if *min != current_min {
                    self.write_file(
                        &self.policy_file(policy, "scaling_min_freq")?,
                        &min.get().to_string(),
                    )?;
                }
            }
            if let Some(max) = max_khz {
                if *max != current_max {
                    self.write_file(
                        &self.policy_file(policy, "scaling_max_freq")?,
                        &max.get().to_string(),
                    )?;
                }
            }
        } else {
            if let Some(max) = max_khz {
                if *max != current_max {
                    self.write_file(
                        &self.policy_file(policy, "scaling_max_freq")?,
                        &max.get().to_string(),
                    )?;
                }
            }
            if let Some(min) = min_khz {
                if *min != current_min {
                    self.write_file(
                        &self.policy_file(policy, "scaling_min_freq")?,
                        &min.get().to_string(),
                    )?;
                }
            }
        }
        Ok(())
    }
}

impl CpuControlIo for CpuSysfs {
    fn list_policies(&self) -> Result<Vec<CpuPolicyId>, SysboostError> {
        let directory = self.cpufreq_dir()?;
        let mut policies = Vec::new();
        for entry in fs::read_dir(directory)
            .map_err(|_| target_error("CPU policies cannot be enumerated"))?
        {
            let entry = entry.map_err(|_| target_error("CPU policy entry cannot be inspected"))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(number) = name.strip_prefix("policy") else {
                continue;
            };
            let Ok(number) = number.parse::<u32>() else {
                return Err(target_error("CPU policy directory name is malformed"));
            };
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|_| target_error("CPU policy directory cannot be inspected"))?;
            if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                return Err(target_error("CPU policy directory is not a real directory"));
            }
            policies.push(CpuPolicyId::new(number));
            if policies.len() > MAX_CPU_POLICIES {
                return Err(target_error("CPU policy enumeration exceeds its bound"));
            }
        }
        policies.sort();
        policies.dedup();
        Ok(policies)
    }

    fn read(&self, node: CpuNode) -> Result<CpuNodeState, SysboostError> {
        let (typed, raw, target_identity, boost_interface) = self.parse_node(node)?;
        let fingerprint = fingerprint_for_value(&PlanValue::Typed(typed.clone()));
        Ok(CpuNodeState {
            raw: BoundedBytes::new(raw)?,
            typed,
            fingerprint,
            target_identity,
            boost_interface,
        })
    }

    fn choices(&self, node: CpuNode) -> Result<Vec<TypedValue>, SysboostError> {
        let choices = self.choices_text(node)?;
        match node {
            CpuNode::Governor(_) => choices
                .into_iter()
                .map(|value| GovernorId::new(value).map(TypedValue::Governor))
                .collect::<Result<Vec<_>, _>>(),
            CpuNode::EnergyPreference(_) => choices
                .into_iter()
                .map(|value| parse_energy(value.as_bytes()).map(TypedValue::EnergyPreference))
                .collect(),
            CpuNode::PlatformProfile => choices
                .into_iter()
                .map(|value| PlatformProfileId::new(value).map(TypedValue::PlatformProfile))
                .collect::<Result<Vec<_>, _>>(),
            CpuNode::Boost(_) => Ok(vec![
                TypedValue::CpuBoost(CpuBoostState::Enabled),
                TypedValue::CpuBoost(CpuBoostState::Disabled),
            ]),
            CpuNode::Frequency(_) => Ok(Vec::new()),
        }
    }

    fn validate_desired(&self, node: CpuNode, desired: &TypedValue) -> Result<(), SysboostError> {
        match node {
            CpuNode::Frequency(policy) => {
                let TypedValue::CpuFrequency { min_khz, max_khz } = desired else {
                    return Err(target_error("CPU frequency desired value is not typed"));
                };
                if let (Some(min), Some(max)) = (min_khz, max_khz) {
                    if min > max {
                        return Err(target_error("CPU desired minimum exceeds maximum"));
                    }
                }
                let current = self.read(CpuNode::Frequency(policy))?;
                let TypedValue::CpuFrequency {
                    min_khz: current_min,
                    max_khz: current_max,
                } = current.typed
                else {
                    return Err(target_error("CPU frequency current state is malformed"));
                };
                let current_min =
                    current_min.ok_or_else(|| target_error("CPU minimum is unavailable"))?;
                let current_max =
                    current_max.ok_or_else(|| target_error("CPU maximum is unavailable"))?;
                let hardware_min = self.read_optional_frequency(policy, "cpuinfo_min_freq")?;
                let hardware_max = self.read_optional_frequency(policy, "cpuinfo_max_freq")?;
                let desired_min = min_khz.as_ref().copied().or(Some(current_min));
                let desired_max = max_khz.as_ref().copied().or(Some(current_max));
                if desired_min.is_some_and(|value| {
                    hardware_min.is_some_and(|min| value < min)
                        || hardware_max.is_some_and(|max| value > max)
                }) || desired_max.is_some_and(|value| {
                    hardware_min.is_some_and(|min| value < min)
                        || hardware_max.is_some_and(|max| value > max)
                }) {
                    return Err(target_error(
                        "CPU desired frequency is outside kernel bounds",
                    ));
                }
                Ok(())
            }
            _ => {
                let choices = self.choices(node)?;
                if choices.is_empty() || !choices.contains(desired) {
                    return Err(unsupported(
                        "CPU desired value is not advertised by the kernel",
                    ));
                }
                Ok(())
            }
        }
    }

    fn write(&self, node: CpuNode, desired: &TypedValue) -> Result<(), SysboostError> {
        match node {
            CpuNode::Governor(policy) => {
                let TypedValue::Governor(value) = desired else {
                    return Err(target_error("CPU governor desired value is not typed"));
                };
                self.write_file(
                    &self.policy_file(policy, "scaling_governor")?,
                    value.as_str(),
                )
            }
            CpuNode::EnergyPreference(policy) => {
                let TypedValue::EnergyPreference(value) = desired else {
                    return Err(target_error("CPU EPP desired value is not typed"));
                };
                self.write_file(
                    &self.policy_file(policy, "energy_performance_preference")?,
                    render_energy(*value),
                )
            }
            CpuNode::Frequency(policy) => self.write_frequency(policy, desired),
            CpuNode::Boost(Some(interface)) => {
                let TypedValue::CpuBoost(state) = desired else {
                    return Err(target_error("CPU boost desired value is not typed"));
                };
                let value = match (interface, state) {
                    (CpuBoostInterface::Boost, CpuBoostState::Enabled) => "1",
                    (CpuBoostInterface::Boost, CpuBoostState::Disabled) => "0",
                    (CpuBoostInterface::NoTurbo, CpuBoostState::Enabled) => "0",
                    (CpuBoostInterface::NoTurbo, CpuBoostState::Disabled) => "1",
                };
                let (path, _) = self.node_path(CpuNode::Boost(Some(interface)))?;
                self.write_file(&path, value)
            }
            CpuNode::Boost(None) => Err(target_error("CPU boost write lacks a resolved interface")),
            CpuNode::PlatformProfile => {
                let TypedValue::PlatformProfile(value) = desired else {
                    return Err(target_error("platform profile desired value is not typed"));
                };
                let (path, _) = self.node_path(CpuNode::PlatformProfile)?;
                self.write_file(&path, value.as_str())
            }
        }
    }
}

/// Deterministic in-memory CPU fixture for backend and transaction tests.
#[derive(Clone, Debug, Default)]
pub struct CpuFixture {
    state: Arc<Mutex<CpuFixtureState>>,
}

#[derive(Clone, Debug, Default)]
struct CpuFixtureState {
    policies: HashMap<CpuPolicyId, CpuFixturePolicy>,
    boost: Option<CpuFixtureBoost>,
    platform_profile: Option<CpuFixtureProfile>,
    fail_writes: BTreeSet<CpuNode>,
}

#[derive(Clone, Debug)]
struct CpuFixturePolicy {
    identity: TargetIdentity,
    governor: GovernorId,
    governor_choices: Vec<GovernorId>,
    epp: EnergyPreference,
    epp_choices: Vec<EnergyPreference>,
    min_khz: FrequencyKHz,
    max_khz: FrequencyKHz,
    hardware_min: FrequencyKHz,
    hardware_max: FrequencyKHz,
}

#[derive(Clone, Debug)]
struct CpuFixtureBoost {
    identity: TargetIdentity,
    interface: CpuBoostInterface,
    state: CpuBoostState,
}

#[derive(Clone, Debug)]
struct CpuFixtureProfile {
    identity: TargetIdentity,
    profile: PlatformProfileId,
    choices: Vec<PlatformProfileId>,
}

impl CpuFixture {
    /// Construct an empty fixture.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one actual CPUFreq policy layout.
    #[allow(clippy::too_many_arguments)]
    pub fn add_policy(
        &self,
        policy: CpuPolicyId,
        identity: TargetIdentity,
        governor: GovernorId,
        governor_choices: Vec<GovernorId>,
        epp: EnergyPreference,
        epp_choices: Vec<EnergyPreference>,
        min_khz: FrequencyKHz,
        max_khz: FrequencyKHz,
        hardware_min: FrequencyKHz,
        hardware_max: FrequencyKHz,
    ) {
        self.state
            .lock()
            .expect("CPU fixture lock is healthy")
            .policies
            .insert(
                policy,
                CpuFixturePolicy {
                    identity,
                    governor,
                    governor_choices,
                    epp,
                    epp_choices,
                    min_khz,
                    max_khz,
                    hardware_min,
                    hardware_max,
                },
            );
    }

    /// Add the global boost/turbo interface.
    pub fn set_boost(
        &self,
        identity: TargetIdentity,
        interface: CpuBoostInterface,
        state: CpuBoostState,
    ) {
        self.state
            .lock()
            .expect("CPU fixture lock is healthy")
            .boost = Some(CpuFixtureBoost {
            identity,
            interface,
            state,
        });
    }

    /// Add the global platform-profile interface.
    pub fn set_platform_profile(
        &self,
        identity: TargetIdentity,
        profile: PlatformProfileId,
        choices: Vec<PlatformProfileId>,
    ) {
        self.state
            .lock()
            .expect("CPU fixture lock is healthy")
            .platform_profile = Some(CpuFixtureProfile {
            identity,
            profile,
            choices,
        });
    }

    /// Cause the next write to one typed node to fail.
    pub fn fail_writes_for(&self, node: CpuNode) {
        self.state
            .lock()
            .expect("CPU fixture lock is healthy")
            .fail_writes
            .insert(node);
    }

    /// Replace a discovered policy identity to simulate topology replacement.
    pub fn replace_policy_identity(&self, policy: CpuPolicyId, identity: TargetIdentity) {
        if let Some(policy) = self
            .state
            .lock()
            .expect("CPU fixture lock is healthy")
            .policies
            .get_mut(&policy)
        {
            policy.identity = identity;
        }
    }

    /// Remove a policy to simulate a policy disappearing after discovery.
    pub fn remove_policy(&self, policy: CpuPolicyId) {
        self.state
            .lock()
            .expect("CPU fixture lock is healthy")
            .policies
            .remove(&policy);
    }

    /// Enumerate policies through the fixture's read-only inspection API.
    pub fn list_policies(&self) -> Result<Vec<CpuPolicyId>, SysboostError> {
        <Self as CpuControlIo>::list_policies(self)
    }

    /// Read one fixture node without exposing its backend write capability.
    pub fn read(&self, node: CpuNode) -> Result<CpuNodeState, SysboostError> {
        <Self as CpuControlIo>::read(self, node)
    }

    /// Inspect the fixture's advertised values for one closed node.
    pub fn choices(&self, node: CpuNode) -> Result<Vec<TypedValue>, SysboostError> {
        <Self as CpuControlIo>::choices(self, node)
    }
}

impl CpuControlIo for CpuFixture {
    fn list_policies(&self) -> Result<Vec<CpuPolicyId>, SysboostError> {
        let state = self
            .state
            .lock()
            .map_err(|_| fixture_error("CPU fixture lock failed"))?;
        let mut policies = state.policies.keys().copied().collect::<Vec<_>>();
        policies.sort();
        Ok(policies)
    }

    fn read(&self, node: CpuNode) -> Result<CpuNodeState, SysboostError> {
        let state = self
            .state
            .lock()
            .map_err(|_| fixture_error("CPU fixture lock failed"))?;
        let (typed, identity, interface, raw) = match node {
            CpuNode::Governor(policy) => {
                let value = state.policies.get(&policy).ok_or_else(fixture_missing)?;
                (
                    TypedValue::Governor(value.governor.clone()),
                    value.identity,
                    None,
                    value.governor.as_str().as_bytes().to_vec(),
                )
            }
            CpuNode::EnergyPreference(policy) => {
                let value = state.policies.get(&policy).ok_or_else(fixture_missing)?;
                (
                    TypedValue::EnergyPreference(value.epp),
                    value.identity,
                    None,
                    render_energy(value.epp).as_bytes().to_vec(),
                )
            }
            CpuNode::Frequency(policy) => {
                let value = state.policies.get(&policy).ok_or_else(fixture_missing)?;
                let typed = TypedValue::CpuFrequency {
                    min_khz: Some(value.min_khz),
                    max_khz: Some(value.max_khz),
                };
                (
                    typed,
                    value.identity,
                    None,
                    format!("{}\0{}", value.min_khz.get(), value.max_khz.get()).into_bytes(),
                )
            }
            CpuNode::Boost(_) => {
                let value = state.boost.as_ref().ok_or_else(fixture_missing)?;
                (
                    TypedValue::CpuBoost(value.state),
                    value.identity,
                    Some(value.interface),
                    boost_text(value.interface, value.state).as_bytes().to_vec(),
                )
            }
            CpuNode::PlatformProfile => {
                let value = state
                    .platform_profile
                    .as_ref()
                    .ok_or_else(fixture_missing)?;
                (
                    TypedValue::PlatformProfile(value.profile.clone()),
                    value.identity,
                    None,
                    value.profile.as_str().as_bytes().to_vec(),
                )
            }
        };
        Ok(CpuNodeState {
            raw: BoundedBytes::new(raw)?,
            fingerprint: fingerprint_for_value(&PlanValue::Typed(typed.clone())),
            typed,
            target_identity: identity,
            boost_interface: interface,
        })
    }

    fn choices(&self, node: CpuNode) -> Result<Vec<TypedValue>, SysboostError> {
        let state = self
            .state
            .lock()
            .map_err(|_| fixture_error("CPU fixture lock failed"))?;
        match node {
            CpuNode::Governor(policy) => Ok(state
                .policies
                .get(&policy)
                .ok_or_else(fixture_missing)?
                .governor_choices
                .iter()
                .cloned()
                .map(TypedValue::Governor)
                .collect()),
            CpuNode::EnergyPreference(policy) => Ok(state
                .policies
                .get(&policy)
                .ok_or_else(fixture_missing)?
                .epp_choices
                .iter()
                .copied()
                .map(TypedValue::EnergyPreference)
                .collect()),
            CpuNode::Frequency(_) => Ok(Vec::new()),
            CpuNode::Boost(_) => Ok(vec![
                TypedValue::CpuBoost(CpuBoostState::Enabled),
                TypedValue::CpuBoost(CpuBoostState::Disabled),
            ]),
            CpuNode::PlatformProfile => Ok(state
                .platform_profile
                .as_ref()
                .ok_or_else(fixture_missing)?
                .choices
                .iter()
                .cloned()
                .map(TypedValue::PlatformProfile)
                .collect()),
        }
    }

    fn validate_desired(&self, node: CpuNode, desired: &TypedValue) -> Result<(), SysboostError> {
        let CpuNode::Frequency(policy) = node else {
            let choices = self.choices(node)?;
            return if choices.contains(desired) {
                Ok(())
            } else {
                Err(unsupported("CPU fixture desired value is not advertised"))
            };
        };
        let TypedValue::CpuFrequency { min_khz, max_khz } = desired else {
            return Err(target_error("CPU fixture frequency value is not typed"));
        };
        let state = self
            .state
            .lock()
            .map_err(|_| fixture_error("CPU fixture lock failed"))?;
        let current = state.policies.get(&policy).ok_or_else(fixture_missing)?;
        if let (Some(min), Some(max)) = (min_khz, max_khz) {
            if min > max {
                return Err(target_error("CPU fixture minimum exceeds maximum"));
            }
        }
        let desired_min = min_khz.as_ref().copied().unwrap_or(current.min_khz);
        let desired_max = max_khz.as_ref().copied().unwrap_or(current.max_khz);
        if desired_min > desired_max {
            return Err(target_error("CPU fixture frequency range is invalid"));
        }
        if desired_min < current.hardware_min
            || desired_min > current.hardware_max
            || desired_max < current.hardware_min
            || desired_max > current.hardware_max
        {
            return Err(target_error(
                "CPU fixture frequency is outside hardware bounds",
            ));
        }
        Ok(())
    }

    fn write(&self, node: CpuNode, desired: &TypedValue) -> Result<(), SysboostError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| fixture_error("CPU fixture lock failed"))?;
        if state.fail_writes.remove(&node) {
            return Err(SysboostError::new(
                ErrorCode::ApplyError,
                "CPU fixture write failed",
            ));
        }
        match node {
            CpuNode::Governor(policy) => {
                let TypedValue::Governor(value) = desired else {
                    return Err(target_error("CPU fixture governor value is not typed"));
                };
                state
                    .policies
                    .get_mut(&policy)
                    .ok_or_else(fixture_missing)?
                    .governor = value.clone();
            }
            CpuNode::EnergyPreference(policy) => {
                let TypedValue::EnergyPreference(value) = desired else {
                    return Err(target_error("CPU fixture EPP value is not typed"));
                };
                state
                    .policies
                    .get_mut(&policy)
                    .ok_or_else(fixture_missing)?
                    .epp = *value;
            }
            CpuNode::Frequency(policy) => {
                let TypedValue::CpuFrequency { min_khz, max_khz } = desired else {
                    return Err(target_error("CPU fixture frequency value is not typed"));
                };
                let value = state
                    .policies
                    .get_mut(&policy)
                    .ok_or_else(fixture_missing)?;
                if let Some(min) = min_khz {
                    value.min_khz = *min;
                }
                if let Some(max) = max_khz {
                    value.max_khz = *max;
                }
            }
            CpuNode::Boost(_) => {
                let TypedValue::CpuBoost(value) = desired else {
                    return Err(target_error("CPU fixture boost value is not typed"));
                };
                state.boost.as_mut().ok_or_else(fixture_missing)?.state = *value;
            }
            CpuNode::PlatformProfile => {
                let TypedValue::PlatformProfile(value) = desired else {
                    return Err(target_error("CPU fixture profile value is not typed"));
                };
                state
                    .platform_profile
                    .as_mut()
                    .ok_or_else(fixture_missing)?
                    .profile = value.clone();
            }
        }
        Ok(())
    }
}

/// Return the reviewed CPU operation catalog used by the pure planner.
pub fn cpu_operation_catalog() -> OperationCatalog {
    let backend = BackendId::new(CPU_BACKEND_ID).expect("static CPU backend ID is valid");
    let mut epp = complete_cpu_contract(
        operation_id("cpu.energy_preference"),
        capability_id("cpu.policy.energy_preference"),
        backend.clone(),
        TargetKind::CpuPolicy,
        sysboost_core::ControlId::CpuEnergyPreference,
        EqualityKind::ScalarExact,
        RiskClass::Low,
        FeatureClass::RuntimeMutable,
        false,
    );
    epp.dependencies = vec![operation_id("cpu.governor")];
    OperationCatalog::new(vec![
        complete_cpu_contract(
            operation_id("cpu.frequency"),
            capability_id("cpu.policy.frequency.max"),
            backend.clone(),
            TargetKind::CpuPolicy,
            sysboost_core::ControlId::CpuFrequency,
            EqualityKind::ScalarExact,
            RiskClass::Medium,
            FeatureClass::RuntimeMutable,
            false,
        ),
        complete_cpu_contract(
            operation_id("cpu.governor"),
            capability_id("cpu.policy.governor"),
            backend.clone(),
            TargetKind::CpuPolicy,
            sysboost_core::ControlId::CpuGovernor,
            EqualityKind::ScalarExact,
            RiskClass::Low,
            FeatureClass::RuntimeMutable,
            false,
        ),
        epp,
        complete_cpu_contract(
            operation_id("cpu.boost"),
            capability_id("cpu.policy.boost"),
            backend.clone(),
            TargetKind::CpuSystem,
            sysboost_core::ControlId::CpuBoost,
            EqualityKind::ScalarExact,
            RiskClass::Medium,
            FeatureClass::RuntimeMutable,
            false,
        ),
        complete_cpu_contract(
            operation_id("platform.profile"),
            capability_id("platform.profile"),
            backend,
            TargetKind::CpuSystem,
            sysboost_core::ControlId::PlatformProfile,
            EqualityKind::ScalarExact,
            RiskClass::Medium,
            FeatureClass::Conditional,
            false,
        ),
    ])
}

#[allow(clippy::too_many_arguments)]
fn complete_cpu_contract(
    operation: OperationId,
    capability: CapabilityId,
    backend: BackendId,
    target_kind: TargetKind,
    control: sysboost_core::ControlId,
    equality: EqualityKind,
    risk: RiskClass,
    classification: FeatureClass,
    explicit_opt_in: bool,
) -> OperationContract {
    let mut contract = OperationContract::complete(
        operation,
        capability,
        backend,
        target_kind,
        control,
        equality,
        risk,
        classification,
        explicit_opt_in,
    );
    contract.snapshot.raw_preimage = true;
    contract
}

fn backend_descriptor() -> BackendDescriptor {
    BackendDescriptor {
        id: BackendId::new(CPU_BACKEND_ID).expect("static CPU backend ID is valid"),
        version: "0.1.0-cpu".to_owned(),
        capabilities: [
            "cpu.policy.frequency.min",
            "cpu.policy.frequency.max",
            "cpu.policy.governor",
            "cpu.policy.energy_preference",
            "cpu.policy.boost",
            "platform.profile",
        ]
        .into_iter()
        .map(capability_id)
        .collect(),
        operations: [
            "cpu.frequency",
            "cpu.governor",
            "cpu.energy_preference",
            "cpu.boost",
            "platform.profile",
        ]
        .into_iter()
        .map(operation_id)
        .collect(),
    }
}

fn cpu_capability_descriptor(
    capability: CapabilityId,
    operation: OperationId,
    target_kind: TargetKind,
    available: bool,
    classification: FeatureClass,
) -> CapabilityDescriptor {
    CapabilityDescriptor {
        id: capability,
        backend: BackendId::new(CPU_BACKEND_ID).expect("static CPU backend ID is valid"),
        target_kind,
        state: if available {
            CapabilityState::Available
        } else {
            CapabilityState::Unsupported
        },
        operations: vec![OperationDescriptor {
            id: operation,
            privilege: PrivilegeRequirement::PrivilegedMutation,
            equality: EqualityKind::ScalarExact,
            classification,
        }],
        privilege: PrivilegeRequirement::PrivilegedMutation,
        equality: EqualityKind::ScalarExact,
        risk: if classification == FeatureClass::Conditional {
            RiskClass::Medium
        } else {
            RiskClass::Low
        },
        classification,
        evidence: vec![CapabilityEvidence {
            source: EvidenceSource::Sysfs,
            detail: "reviewed typed CPU backend".to_owned(),
        }],
    }
}

fn capability_id(value: &str) -> CapabilityId {
    CapabilityId::new(value).expect("static CPU capability ID is valid")
}

fn operation_id(value: &str) -> OperationId {
    OperationId::new(value).expect("static CPU operation ID is valid")
}

fn target_error(message: &str) -> SysboostError {
    SysboostError::new(ErrorCode::TargetError, message).with_stage(Stage::Detect)
}

fn unsupported(message: &str) -> SysboostError {
    SysboostError::new(ErrorCode::Unsupported, message).with_stage(Stage::Detect)
}

fn fixture_error(message: &str) -> SysboostError {
    SysboostError::new(ErrorCode::InvariantViolation, message)
}

fn fixture_missing() -> SysboostError {
    SysboostError::new(ErrorCode::Unsupported, "CPU fixture node is unavailable")
}

fn parse_governor(raw: &[u8]) -> Result<GovernorId, SysboostError> {
    let value = text(raw)?;
    GovernorId::new(value).map_err(|_| target_error("CPU governor value is malformed"))
}

fn parse_energy(raw: &[u8]) -> Result<EnergyPreference, SysboostError> {
    match text(raw)?.as_str() {
        "performance" => Ok(EnergyPreference::Performance),
        "balance_performance" => Ok(EnergyPreference::BalancePerformance),
        "balance_power" => Ok(EnergyPreference::BalancePower),
        "power" => Ok(EnergyPreference::Power),
        _ => Err(target_error(
            "CPU EPP value is not in the closed vocabulary",
        )),
    }
}

fn parse_frequency(raw: &[u8]) -> Result<FrequencyKHz, SysboostError> {
    let value = text(raw)?
        .parse::<u64>()
        .map_err(|_| target_error("CPU frequency value is malformed"))?;
    FrequencyKHz::new(value).map_err(|_| target_error("CPU frequency value is invalid"))
}

fn parse_boost(interface: CpuBoostInterface, raw: &[u8]) -> Result<CpuBoostState, SysboostError> {
    match (interface, text(raw)?.as_str()) {
        (CpuBoostInterface::Boost, "1") | (CpuBoostInterface::NoTurbo, "0") => {
            Ok(CpuBoostState::Enabled)
        }
        (CpuBoostInterface::Boost, "0") | (CpuBoostInterface::NoTurbo, "1") => {
            Ok(CpuBoostState::Disabled)
        }
        _ => Err(target_error("CPU boost value is malformed")),
    }
}

fn parse_profile(raw: &[u8]) -> Result<PlatformProfileId, SysboostError> {
    PlatformProfileId::new(text(raw)?).map_err(|_| target_error("platform profile is malformed"))
}

fn text(raw: &[u8]) -> Result<String, SysboostError> {
    std::str::from_utf8(raw)
        .map(|value| value.trim().to_owned())
        .map_err(|_| target_error("CPU kernel value is not valid UTF-8"))
}

fn render_energy(value: EnergyPreference) -> &'static str {
    match value {
        EnergyPreference::Performance => "performance",
        EnergyPreference::BalancePerformance => "balance_performance",
        EnergyPreference::BalancePower => "balance_power",
        EnergyPreference::Power => "power",
    }
}

fn boost_text(interface: CpuBoostInterface, state: CpuBoostState) -> &'static str {
    match (interface, state) {
        (CpuBoostInterface::Boost, CpuBoostState::Enabled)
        | (CpuBoostInterface::NoTurbo, CpuBoostState::Disabled) => "1",
        (CpuBoostInterface::Boost, CpuBoostState::Disabled)
        | (CpuBoostInterface::NoTurbo, CpuBoostState::Enabled) => "0",
    }
}

fn validate_final_file(path: &Path) -> Result<(), SysboostError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| target_error("CPU kernel node disappeared"))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(target_error("CPU kernel node is not a regular file"));
    }
    Ok(())
}

#[cfg(unix)]
fn node_identity(
    path: &Path,
    _interface: Option<CpuBoostInterface>,
) -> Result<TargetIdentity, SysboostError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| target_error("CPU kernel node identity cannot be inspected"))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(target_error(
            "CPU kernel node identity has an unexpected type",
        ));
    }
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&metadata.dev().to_be_bytes());
    bytes[8..].copy_from_slice(&metadata.ino().to_be_bytes());
    Ok(TargetIdentity::from_bytes(bytes))
}

#[cfg(not(unix))]
fn node_identity(
    _path: &Path,
    _interface: Option<CpuBoostInterface>,
) -> Result<TargetIdentity, SysboostError> {
    Err(target_error("CPU identity is unsupported on this platform"))
}

#[cfg(unix)]
fn directory_identity(path: &Path) -> Result<TargetIdentity, SysboostError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| target_error("CPU policy identity cannot be inspected"))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(target_error("CPU policy identity has an unexpected type"));
    }
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&metadata.dev().to_be_bytes());
    bytes[8..].copy_from_slice(&metadata.ino().to_be_bytes());
    Ok(TargetIdentity::from_bytes(bytes))
}

#[cfg(not(unix))]
fn directory_identity(_path: &Path) -> Result<TargetIdentity, SysboostError> {
    Err(target_error("CPU identity is unsupported on this platform"))
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

#[cfg(test)]
mod tests {
    use super::*;
    use sysboost_core::{fingerprint_for_value, CapabilityState, MutationId, PlanValue, Timestamp};
    use sysboost_platform::{FixedClock, MutationBackend};

    fn identity(value: u8) -> TargetIdentity {
        TargetIdentity::from_bytes([value; 16])
    }

    fn governor(value: &str) -> GovernorId {
        GovernorId::new(value).expect("fixture governor is valid")
    }

    fn frequency(value: u64) -> FrequencyKHz {
        FrequencyKHz::new(value).expect("fixture frequency is valid")
    }

    fn policy_fixture() -> CpuFixture {
        let fixture = CpuFixture::new();
        fixture.add_policy(
            CpuPolicyId::new(0),
            identity(1),
            governor("schedutil"),
            vec![governor("schedutil"), governor("performance")],
            EnergyPreference::BalancePerformance,
            vec![
                EnergyPreference::BalancePerformance,
                EnergyPreference::Performance,
            ],
            frequency(800_000),
            frequency(3_600_000),
            frequency(400_000),
            frequency(4_000_000),
        );
        fixture
    }

    fn governor_mutation(
        mutation_id: u32,
        policy: CpuPolicyId,
        original: &str,
        desired: &str,
    ) -> PlannedMutation {
        let kind = MutationKind::CpuGovernor {
            policy,
            governor: governor(desired),
        };
        let original = PlanValue::Typed(TypedValue::Governor(governor(original)));
        PlannedMutation::new(
            MutationId::new(mutation_id),
            capability_id("cpu.policy.governor"),
            TargetId::new(format!("cpu.policy.{}", policy.get())).expect("CPU target is valid"),
            kind.clone(),
            kind.typed_value(),
            fingerprint_for_value(&original),
            EqualityKind::ScalarExact,
            Vec::new(),
        )
        .expect("fixture mutation is valid")
    }

    fn typed_mutation(
        mutation_id: u32,
        capability: &str,
        target: &str,
        kind: MutationKind,
        original: TypedValue,
    ) -> PlannedMutation {
        PlannedMutation::new(
            MutationId::new(mutation_id),
            capability_id(capability),
            TargetId::new(target.to_owned()).expect("typed CPU target is valid"),
            kind.clone(),
            kind.typed_value(),
            fingerprint_for_value(&PlanValue::Typed(original)),
            EqualityKind::ScalarExact,
            Vec::new(),
        )
        .expect("typed CPU mutation is valid")
    }

    #[test]
    fn fixture_supports_multiple_policies_and_partial_global_capabilities() {
        let fixture = policy_fixture();
        fixture.add_policy(
            CpuPolicyId::new(4),
            identity(4),
            governor("powersave"),
            vec![governor("powersave"), governor("performance")],
            EnergyPreference::Power,
            vec![EnergyPreference::Power, EnergyPreference::Performance],
            frequency(600_000),
            frequency(2_400_000),
            frequency(400_000),
            frequency(3_000_000),
        );

        let backend = CpuBackend::new(Box::new(fixture));
        let inventory = backend
            .detect(&FixedClock::new(Timestamp::from_unix_millis(1)))
            .expect("CPU fixture detection succeeds");
        assert_eq!(inventory.capabilities.len(), 6);
        assert!(
            inventory
                .capabilities
                .iter()
                .filter(|capability| capability.state == CapabilityState::Available)
                .count()
                >= 4
        );
        assert_eq!(
            inventory
                .capabilities
                .iter()
                .find(|capability| capability.id.as_str() == "cpu.policy.boost")
                .expect("boost capability is described")
                .state,
            CapabilityState::Unsupported
        );
        assert_eq!(
            inventory
                .capabilities
                .iter()
                .find(|capability| capability.id.as_str() == "platform.profile")
                .expect("platform capability is described")
                .state,
            CapabilityState::Unsupported
        );
    }

    #[test]
    fn backend_inspection_and_fixture_reads_are_read_only() {
        let fixture = policy_fixture();
        let backend = CpuBackend::from_fixture(fixture.clone());
        let inspection = backend.io();

        assert_eq!(
            inspection
                .list_policies()
                .expect("inspection enumerates fixture policies"),
            vec![CpuPolicyId::new(0)]
        );
        assert_eq!(
            inspection
                .read(CpuNode::Governor(CpuPolicyId::new(0)))
                .expect("inspection reads the fixture governor")
                .typed,
            TypedValue::Governor(governor("schedutil"))
        );
        assert_eq!(
            fixture
                .read(CpuNode::Governor(CpuPolicyId::new(0)))
                .expect("fixture exposes read-only state inspection")
                .typed,
            TypedValue::Governor(governor("schedutil"))
        );
    }

    #[test]
    fn typed_cpu_apply_verify_and_restore_use_the_captured_original() {
        let fixture = policy_fixture();
        let backend = CpuBackend::new(Box::new(fixture.clone()));
        let mutation = governor_mutation(1, CpuPolicyId::new(0), "schedutil", "performance");

        backend
            .validate_admission(&mutation, identity(1))
            .expect("typed CPU target is admitted");
        let snapshot = backend
            .snapshot_internal(&mutation, Timestamp::from_unix_millis(2))
            .expect("original governor is snapshotted");
        assert_eq!(
            snapshot.original_typed,
            TypedValue::Governor(governor("schedutil"))
        );
        let receipt = backend
            .apply_internal(&mutation, &snapshot)
            .expect("typed CPU governor applies");
        assert_eq!(
            fixture
                .read(CpuNode::Governor(CpuPolicyId::new(0)))
                .expect("fixture read succeeds")
                .typed,
            TypedValue::Governor(governor("performance"))
        );
        assert_eq!(
            backend
                .verify_internal(&mutation, identity(1))
                .expect("apply readback succeeds"),
            receipt.ownership_fingerprint
        );
        backend
            .restore_internal(&mutation, &snapshot, receipt.ownership_fingerprint)
            .expect("captured original restores exactly");
        assert_eq!(
            fixture
                .read(CpuNode::Governor(CpuPolicyId::new(0)))
                .expect("fixture read succeeds")
                .typed,
            snapshot.original_typed
        );
    }

    #[test]
    fn partial_frequency_policy_updates_verify_and_restore_the_full_range() {
        let fixture = policy_fixture();
        let backend = CpuBackend::new(Box::new(fixture.clone()));
        let original = TypedValue::CpuFrequency {
            min_khz: Some(frequency(800_000)),
            max_khz: Some(frequency(3_600_000)),
        };
        for (mutation_id, min_khz, max_khz, expected_min, expected_max) in [
            (
                10,
                Some(frequency(1_000_000)),
                None,
                frequency(1_000_000),
                frequency(3_600_000),
            ),
            (
                11,
                None,
                Some(frequency(3_000_000)),
                frequency(800_000),
                frequency(3_000_000),
            ),
        ] {
            let mutation = typed_mutation(
                mutation_id,
                "cpu.policy.frequency.max",
                "cpu.policy.0",
                MutationKind::CpuFrequency {
                    policy: CpuPolicyId::new(0),
                    min_khz,
                    max_khz,
                },
                original.clone(),
            );
            backend
                .validate_admission(&mutation, identity(1))
                .expect("partial frequency operation is admitted");
            let snapshot = backend
                .snapshot_internal(&mutation, Timestamp::from_unix_millis(3))
                .expect("full original frequency range is captured");
            let receipt = backend
                .apply_internal(&mutation, &snapshot)
                .expect("partial frequency operation applies");
            assert_eq!(
                fixture
                    .read(CpuNode::Frequency(CpuPolicyId::new(0)))
                    .expect("frequency policy remains readable")
                    .typed,
                TypedValue::CpuFrequency {
                    min_khz: Some(expected_min),
                    max_khz: Some(expected_max),
                }
            );
            assert_eq!(
                backend
                    .verify_internal(&mutation, identity(1))
                    .expect("partial frequency readback succeeds"),
                receipt.ownership_fingerprint
            );
            backend
                .restore_internal(&mutation, &snapshot, receipt.ownership_fingerprint)
                .expect("full original frequency range restores");
            assert_eq!(
                fixture
                    .read(CpuNode::Frequency(CpuPolicyId::new(0)))
                    .expect("frequency policy remains readable after restore")
                    .typed,
                original
            );
        }
    }

    #[test]
    fn frequency_boost_and_platform_profile_are_typed_reversible_operations() {
        let fixture = policy_fixture();
        fixture.set_boost(
            identity(3),
            CpuBoostInterface::Boost,
            CpuBoostState::Enabled,
        );
        fixture.set_platform_profile(
            identity(4),
            PlatformProfileId::new("balanced").expect("valid profile"),
            vec![
                PlatformProfileId::new("balanced").expect("valid profile"),
                PlatformProfileId::new("performance").expect("valid profile"),
            ],
        );
        let backend = CpuBackend::new(Box::new(fixture.clone()));
        let mutations = vec![
            (
                typed_mutation(
                    1,
                    "cpu.policy.frequency.max",
                    "cpu.policy.0",
                    MutationKind::CpuFrequency {
                        policy: CpuPolicyId::new(0),
                        min_khz: Some(frequency(1_000_000)),
                        max_khz: Some(frequency(3_000_000)),
                    },
                    TypedValue::CpuFrequency {
                        min_khz: Some(frequency(800_000)),
                        max_khz: Some(frequency(3_600_000)),
                    },
                ),
                identity(1),
            ),
            (
                typed_mutation(
                    2,
                    "cpu.policy.boost",
                    "system.cpu.boost",
                    MutationKind::CpuBoost {
                        state: CpuBoostState::Disabled,
                    },
                    TypedValue::CpuBoost(CpuBoostState::Enabled),
                ),
                identity(3),
            ),
            (
                typed_mutation(
                    3,
                    "platform.profile",
                    "system.platform.profile",
                    MutationKind::PlatformProfile {
                        profile: PlatformProfileId::new("performance").expect("valid profile"),
                    },
                    TypedValue::PlatformProfile(
                        PlatformProfileId::new("balanced").expect("valid profile"),
                    ),
                ),
                identity(4),
            ),
        ];

        for (mutation, target_identity) in mutations {
            backend
                .validate_admission(&mutation, target_identity)
                .expect("typed CPU operation is admitted");
            let snapshot = backend
                .snapshot_internal(&mutation, Timestamp::from_unix_millis(4))
                .expect("typed original is captured");
            let receipt = backend
                .apply_internal(&mutation, &snapshot)
                .expect("typed operation applies");
            assert_eq!(
                backend
                    .verify_internal(&mutation, target_identity)
                    .expect("typed apply is verified"),
                receipt.ownership_fingerprint
            );
            backend
                .restore_internal(&mutation, &snapshot, receipt.ownership_fingerprint)
                .expect("typed original is restored");
        }
    }

    #[test]
    fn cpu_operation_catalog_declares_complete_backend_contracts() {
        let catalog = cpu_operation_catalog();
        assert_eq!(catalog.contracts().len(), 5);
        for contract in catalog.contracts() {
            contract
                .validate()
                .expect("CPU contract is internally valid");
            assert_eq!(contract.backend.as_str(), CPU_BACKEND_ID);
            assert!(contract.snapshot.is_complete());
            assert!(contract.snapshot.raw_preimage);
            assert!(contract.restore.is_complete());
            assert!(contract.verification.is_complete());
        }
    }

    #[test]
    fn identity_change_or_disappearance_fails_closed_before_write() {
        let fixture = policy_fixture();
        let backend = CpuBackend::new(Box::new(fixture.clone()));
        let mutation = governor_mutation(1, CpuPolicyId::new(0), "schedutil", "performance");

        fixture.replace_policy_identity(CpuPolicyId::new(0), identity(9));
        let error = backend
            .validate_admission(&mutation, identity(1))
            .expect_err("replaced policy identity is not admitted");
        assert_eq!(error.code, ErrorCode::TargetError);
        assert_eq!(
            fixture
                .read(CpuNode::Governor(CpuPolicyId::new(0)))
                .expect("fixture remains readable")
                .typed,
            TypedValue::Governor(governor("schedutil"))
        );

        fixture.remove_policy(CpuPolicyId::new(0));
        assert!(
            backend.validate_admission(&mutation, identity(9)).is_err(),
            "a disappeared policy is never substituted"
        );
    }

    #[test]
    fn operation_and_capability_ownership_are_pairwise_closed() {
        let fixture = policy_fixture();
        let backend = CpuBackend::new(Box::new(fixture));
        let mut mutation = governor_mutation(1, CpuPolicyId::new(0), "schedutil", "performance");
        mutation.capability = capability_id("cpu.policy.energy_preference");
        let error = backend
            .validate_admission(&mutation, identity(1))
            .expect_err("governor operation cannot claim EPP ownership");
        assert_eq!(error.code, ErrorCode::Unsupported);
    }

    #[cfg(unix)]
    mod production_fs {
        use super::*;
        use std::fs;
        use std::os::unix::fs::symlink;
        use std::path::{Path, PathBuf};
        use std::time::{SystemTime, UNIX_EPOCH};

        struct TempTree(PathBuf);

        impl TempTree {
            fn new(label: &str) -> Self {
                let nonce = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("system clock is after Unix epoch")
                    .as_nanos();
                let path = std::env::temp_dir().join(format!(
                    "sysboost-cpu-{label}-{}-{nonce}",
                    std::process::id()
                ));
                fs::create_dir_all(&path).expect("temporary CPU root is created");
                Self(path)
            }

            fn path(&self) -> &Path {
                &self.0
            }
        }

        impl Drop for TempTree {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }

        fn policy_root(root: &Path, policy: u32) -> PathBuf {
            root.join("devices/system/cpu/cpufreq")
                .join(format!("policy{policy}"))
        }

        fn seed_policy(root: &Path, policy: u32) -> PathBuf {
            let directory = policy_root(root, policy);
            fs::create_dir_all(&directory).expect("policy directory is created");
            fs::write(
                directory.join("scaling_available_governors"),
                b"schedutil performance\n",
            )
            .expect("governor choices are seeded");
            fs::write(directory.join("scaling_governor"), b"schedutil\n")
                .expect("governor node is seeded");
            fs::write(directory.join("scaling_min_freq"), b"800000\n")
                .expect("minimum node is seeded");
            fs::write(directory.join("scaling_max_freq"), b"3600000\n")
                .expect("maximum node is seeded");
            directory
        }

        #[test]
        fn production_adapter_rejects_symlink_policy_dirs_and_nodes() {
            let tree = TempTree::new("symlink");
            let cpufreq = tree.path().join("devices/system/cpu/cpufreq");
            fs::create_dir_all(&cpufreq).expect("cpufreq directory is created");
            let outside = tree.path().join("outside-policy");
            fs::create_dir_all(&outside).expect("outside directory is created");
            symlink(&outside, cpufreq.join("policy0")).expect("policy symlink is created");
            let sysfs = CpuSysfs::new(tree.path()).expect("CPU root is valid");
            assert!(
                sysfs.list_policies().is_err(),
                "symlinked policy is rejected"
            );

            let _ = fs::remove_file(cpufreq.join("policy0"));
            let directory = seed_policy(tree.path(), 0);
            let outside_value = tree.path().join("outside-governor");
            fs::write(&outside_value, b"performance\n").expect("outside value is seeded");
            fs::remove_file(directory.join("scaling_governor")).expect("node is removed");
            symlink(&outside_value, directory.join("scaling_governor"))
                .expect("governor symlink is created");
            assert!(
                sysfs.read(CpuNode::Governor(CpuPolicyId::new(0))).is_err(),
                "symlinked kernel node is rejected"
            );
        }

        #[test]
        fn production_adapter_reports_partial_policy_layouts_without_guessing() {
            let tree = TempTree::new("partial");
            seed_policy(tree.path(), 0);
            seed_policy(tree.path(), 4);
            let sysfs = CpuSysfs::new(tree.path()).expect("CPU root is valid");
            let backend = CpuBackend::new(Box::new(sysfs));
            let inventory = backend
                .detect(&FixedClock::new(Timestamp::from_unix_millis(3)))
                .expect("partial CPU layout is detected");
            assert_eq!(
                inventory
                    .capabilities
                    .iter()
                    .find(|capability| capability.id.as_str() == "cpu.policy.governor")
                    .expect("governor descriptor exists")
                    .state,
                CapabilityState::Available
            );
            assert_eq!(
                inventory
                    .capabilities
                    .iter()
                    .find(|capability| capability.id.as_str() == "cpu.policy.energy_preference")
                    .expect("EPP descriptor exists")
                    .state,
                CapabilityState::Unsupported
            );
            assert_eq!(
                backend
                    .io()
                    .list_policies()
                    .expect("policies enumerate deterministically"),
                vec![CpuPolicyId::new(0), CpuPolicyId::new(4)]
            );
        }

        #[test]
        fn production_adapter_reports_missing_cpufreq_as_unsupported() {
            let tree = TempTree::new("missing-cpufreq");
            let sysfs = CpuSysfs::new(tree.path()).expect("CPU root is valid");
            let backend = CpuBackend::new(Box::new(sysfs));
            let inventory = backend
                .detect(&FixedClock::new(Timestamp::from_unix_millis(5)))
                .expect("missing optional CPUFreq is a capability result");
            assert_eq!(inventory.capabilities.len(), 6);
            assert!(inventory
                .capabilities
                .iter()
                .all(|capability| capability.state == CapabilityState::Unsupported));
        }
    }
}
