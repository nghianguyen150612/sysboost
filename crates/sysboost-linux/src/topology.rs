//! Conservative CPU-topology planning for runtime soft isolation.
//!
//! This module is deliberately a planner and mask generator, not a scheduler
//! syscall adapter.  It consumes kernel-exposed topology facts, selects a
//! workload set while retaining a housekeeping set, and produces the existing
//! typed `cgroup.cpuset.cpus` mutation when the caller is ready to submit the
//! result through the normal planner -> privilege -> transaction -> backend
//! path.
//!
//! No boot-time isolation is attempted here.  In particular, this module does
//! not know about `isolcpus`, `nohz_full`, or `rcu_nocbs`, and it never calls
//! `sched_setaffinity` directly.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use sysboost_core::{
    CapabilityId, CgroupId, CpuSet, EqualityKind, ErrorCode, MutationId, MutationKind,
    PlannedMutation, Stage, StateFingerprint, SysboostError, TargetIdentity, TypedValue,
};

use crate::discovery::{CpuTopologyEntry, CpuTopologyFacts, DiscoveryReport, NumaFacts};

/// Output gate emitted by a successful Prompt 9 implementation.
pub const CPU_ISOLATION_OUTPUT_GATE: &str = "SYSBOOST_CPU_ISOLATION_READY";

/// The command-line spelling for capacity-aware workload selection.
pub const PREFER_PERFORMANCE_CORES_FLAG: &str = "--prefer-performance-cores";

const CPUSET_CAPACITY_LIMIT: usize = 1_048_576;

/// How strongly the kernel proved CPU capacity differences.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CpuCapacityMode {
    /// Every online CPU exposed a positive capacity and at least two values
    /// were observed.  Performance/efficiency classification is permitted.
    HeterogeneousProven,
    /// Every online CPU exposed the same positive capacity.  No P/E guess is
    /// made; the topology is treated as homogeneous.
    Homogeneous,
    /// Capacity metadata was absent or incomplete.  No P/E guess is made.
    Unknown,
}

impl fmt::Display for CpuCapacityMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::HeterogeneousProven => "heterogeneous-proven",
            Self::Homogeneous => "homogeneous",
            Self::Unknown => "unknown",
        })
    }
}

/// Per-CPU classification derived only from positive kernel capacity data.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CpuPerformanceClass {
    /// The highest capacity tier observed among online CPUs.
    Performance,
    /// A lower capacity tier observed on a proven heterogeneous topology.
    Efficiency,
    /// Capacity is homogeneous, incomplete, or internally inconsistent.
    Unknown,
}

impl fmt::Display for CpuPerformanceClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Performance => "performance",
            Self::Efficiency => "efficiency",
            Self::Unknown => "unknown",
        })
    }
}

/// One normalized CPU topology observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CpuTopologyCpu {
    /// Logical CPU number.
    pub id: u32,
    /// Kernel physical-package ID, when exposed.
    pub package_id: Option<u32>,
    /// Kernel physical-core ID, when exposed.
    pub core_id: Option<u32>,
    /// Online thread siblings, filtered to the planned online set.
    pub thread_siblings: CpuSet,
    /// Positive kernel capacity hint, when exposed.
    pub capacity: Option<u64>,
    /// Whether this CPU is in the current online set.
    pub online: bool,
    /// NUMA node, when the kernel exposed an unambiguous node membership.
    pub numa_node: Option<u32>,
    /// Conservative capacity classification.
    pub performance_class: CpuPerformanceClass,
}

/// A physical-core planning unit.  SMT siblings stay together so a soft
/// isolation plan does not silently split one physical core between workload
/// and housekeeping.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CpuCoreGroup {
    /// Online logical CPUs belonging to this physical-core unit.
    pub cpus: CpuSet,
    /// Classification of the complete group.
    pub performance_class: CpuPerformanceClass,
    /// NUMA node when every member agrees.
    pub numa_node: Option<u32>,
}

/// A stable revision of the topology used to detect changes between planning
/// and apply.  It is not a security credential; it is a fail-closed change
/// detector.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TopologyRevision([u8; 32]);

impl TopologyRevision {
    /// Return the revision bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Normalized topology evidence used by the placement planner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CpuTopology {
    possible: Option<CpuSet>,
    online: Option<CpuSet>,
    cpus: Vec<CpuTopologyCpu>,
    numa_nodes: BTreeMap<u32, CpuSet>,
    capacity_mode: CpuCapacityMode,
    revision: TopologyRevision,
}

impl CpuTopology {
    /// Normalize discovery facts and NUMA facts into a planning topology.
    ///
    /// The constructor recomputes heterogeneous-capacity proof from the
    /// per-CPU values instead of trusting an aggregate flag.  Missing CPU
    /// records are represented as unknown-capacity CPUs when the online or
    /// possible list is still known; this permits a conservative fallback.
    pub fn from_facts(facts: &CpuTopologyFacts, numa: &NumaFacts) -> Result<Self, SysboostError> {
        let possible = facts.possible.as_deref().map(parse_cpu_list).transpose()?;
        let declared_online = facts.online.as_deref().map(parse_cpu_list).transpose()?;

        let inferred_online = if declared_online.is_none() {
            let ids = facts
                .entries
                .iter()
                .filter(|entry| entry.online)
                .map(|entry| entry.cpu)
                .collect::<Vec<_>>();
            if ids.is_empty() {
                None
            } else {
                Some(CpuSet::new(ids)?)
            }
        } else {
            None
        };
        let online = declared_online.or(inferred_online);

        if let (Some(possible), Some(online)) = (&possible, &online) {
            if online
                .as_slice()
                .iter()
                .any(|cpu| !possible.as_slice().contains(cpu))
            {
                return Err(topology_error(
                    "online CPU list contains a CPU outside the possible CPU list",
                ));
            }
        }

        let mut raw_entries = BTreeMap::<u32, &CpuTopologyEntry>::new();
        for entry in &facts.entries {
            if raw_entries.insert(entry.cpu, entry).is_some() {
                return Err(topology_error(
                    "CPU topology contains duplicate logical CPU IDs",
                ));
            }
        }

        let mut ids = BTreeSet::new();
        if let Some(possible) = &possible {
            ids.extend(possible.as_slice().iter().copied());
        }
        if let Some(online) = &online {
            ids.extend(online.as_slice().iter().copied());
        }
        ids.extend(raw_entries.keys().copied());
        if ids.is_empty() {
            return Err(SysboostError::new(
                ErrorCode::CapabilityError,
                "CPU topology exposes neither possible CPUs nor topology entries",
            )
            .with_stage(Stage::Detect));
        }

        let numa_nodes = normalize_numa(numa)?;
        let mut cpu_to_numa = BTreeMap::<u32, u32>::new();
        for (node, cpus) in &numa_nodes {
            for cpu in cpus.as_slice() {
                if cpu_to_numa.insert(*cpu, *node).is_some() {
                    return Err(topology_error(
                        "NUMA facts assign one CPU to multiple NUMA nodes",
                    ));
                }
            }
        }

        let online_known = online.is_some();
        let mut cpus = Vec::with_capacity(ids.len());
        for id in ids {
            let entry = raw_entries.get(&id).copied();
            let mut siblings = entry
                .and_then(|entry| entry.thread_siblings.as_deref())
                .map(parse_cpu_list)
                .transpose()?;
            if siblings
                .as_ref()
                .is_some_and(|siblings| !siblings.as_slice().contains(&id))
            {
                return Err(topology_error(
                    "CPU thread-sibling metadata does not contain its owning CPU",
                ));
            }
            let is_online = online
                .as_ref()
                .is_some_and(|online| online.as_slice().contains(&id))
                || (!online_known && entry.is_some_and(|entry| entry.online));
            if let Some(online) = &online {
                let filtered = siblings
                    .take()
                    .map(|siblings| {
                        siblings
                            .as_slice()
                            .iter()
                            .copied()
                            .filter(|cpu| online.as_slice().contains(cpu))
                            .collect::<Vec<_>>()
                    })
                    .filter(|siblings| !siblings.is_empty())
                    .unwrap_or_else(|| vec![id]);
                siblings = Some(CpuSet::new(filtered)?);
            }
            let siblings = siblings.unwrap_or(CpuSet::new(vec![id])?);
            cpus.push(CpuTopologyCpu {
                id,
                package_id: entry.and_then(|entry| entry.package_id),
                core_id: entry.and_then(|entry| entry.core_id),
                thread_siblings: siblings,
                capacity: entry.and_then(|entry| entry.capacity.filter(|value| *value > 0)),
                online: is_online,
                numa_node: cpu_to_numa.get(&id).copied(),
                performance_class: CpuPerformanceClass::Unknown,
            });
        }

        let capacity_mode = classify_capacities(&mut cpus, online.as_ref());
        let revision = topology_revision(&possible, &online, &cpus, &numa_nodes);
        Ok(Self {
            possible,
            online,
            cpus,
            numa_nodes,
            capacity_mode,
            revision,
        })
    }

    /// Construct a topology directly from normalized discovery facts.
    pub fn from_discovery(report: &DiscoveryReport) -> Result<Self, SysboostError> {
        Self::from_facts(&report.topology, &report.numa)
    }

    /// Alias for callers that pass a complete discovery report.
    pub fn from_discovery_report(report: &DiscoveryReport) -> Result<Self, SysboostError> {
        Self::from_discovery(report)
    }

    /// Return the possible CPU set when the kernel exposed it.
    pub fn possible(&self) -> Option<&CpuSet> {
        self.possible.as_ref()
    }

    /// Return the online CPU set when the kernel exposed it.
    pub fn online(&self) -> Option<&CpuSet> {
        self.online.as_ref()
    }

    /// Return the current online CPU set under an explicit name.
    pub fn online_cpus(&self) -> Option<&CpuSet> {
        self.online()
    }

    /// Whether the online set was available to the planner.
    pub const fn online_is_known(&self) -> bool {
        self.online.is_some()
    }

    /// Return all normalized CPU records, including offline possible CPUs.
    pub fn cpus(&self) -> &[CpuTopologyCpu] {
        &self.cpus
    }

    /// Return one normalized CPU record.
    pub fn cpu(&self, id: u32) -> Option<&CpuTopologyCpu> {
        self.cpus.iter().find(|cpu| cpu.id == id)
    }

    /// Return NUMA node CPU sets in numeric node order.
    pub fn numa_nodes(&self) -> &BTreeMap<u32, CpuSet> {
        &self.numa_nodes
    }

    /// Return the recomputed capacity classification mode.
    pub const fn capacity_mode(&self) -> CpuCapacityMode {
        self.capacity_mode
    }

    /// Return the capacity classification under an explicit name.
    pub const fn capacity_classification(&self) -> CpuCapacityMode {
        self.capacity_mode()
    }

    /// Return the stable revision captured from all planning-relevant facts.
    pub const fn revision(&self) -> TopologyRevision {
        self.revision
    }

    /// Group online logical CPUs into physical-core planning units.
    pub fn core_groups(&self) -> Vec<CpuCoreGroup> {
        let Some(online) = &self.online else {
            return Vec::new();
        };
        let mut groups = BTreeMap::<CoreKey, Vec<&CpuTopologyCpu>>::new();
        for cpu in &self.cpus {
            if !online.as_slice().contains(&cpu.id) {
                continue;
            }
            let key = if let (Some(package), Some(core)) = (cpu.package_id, cpu.core_id) {
                CoreKey::PackageCore(package, core)
            } else {
                CoreKey::SiblingSet(cpu.thread_siblings.clone())
            };
            groups.entry(key).or_default().push(cpu);
        }

        let mut result = groups
            .into_values()
            .filter_map(|mut members| {
                members.sort_by_key(|cpu| cpu.id);
                let cpus = CpuSet::new(members.iter().map(|cpu| cpu.id).collect()).ok()?;
                let performance_class = members
                    .first()
                    .map(|cpu| cpu.performance_class)
                    .filter(|class| members.iter().all(|cpu| cpu.performance_class == *class))
                    .unwrap_or(CpuPerformanceClass::Unknown);
                let numa_node = members
                    .first()
                    .and_then(|cpu| cpu.numa_node)
                    .filter(|node| members.iter().all(|cpu| cpu.numa_node == Some(*node)));
                Some(CpuCoreGroup {
                    cpus,
                    performance_class,
                    numa_node,
                })
            })
            .collect::<Vec<_>>();
        result.sort_by(|left, right| left.cpus.cmp(&right.cpus));
        result
    }

    /// Select workload and housekeeping CPUs using the conservative policy.
    pub fn select(&self, policy: CpuSelectionPolicy) -> Result<CpuIsolationPlan, SysboostError> {
        self.select_for_target(policy, None)
    }

    /// Select a workload placement using the default conservative policy.
    pub fn select_workload(&self) -> Result<CpuIsolationPlan, SysboostError> {
        self.select(CpuSelectionPolicy::conservative())
    }

    /// Select CPUs and bind the plan to a backend-discovered target identity.
    /// The identity is checked again by [`CpuIsolationPlan::validate_before_apply`].
    pub fn select_for_target(
        &self,
        policy: CpuSelectionPolicy,
        target_identity: Option<TargetIdentity>,
    ) -> Result<CpuIsolationPlan, SysboostError> {
        let online = self.online.clone().ok_or_else(|| {
            SysboostError::new(
                ErrorCode::CapabilityError,
                "current online CPU set is unavailable; soft isolation is report-only",
            )
            .with_stage(Stage::Plan)
        })?;
        let groups = self.core_groups();
        if online.as_slice().len() < 2 || groups.len() < 2 {
            return Err(SysboostError::new(
                ErrorCode::PlanningError,
                "at least two online physical-core groups are required to preserve housekeeping",
            )
            .with_stage(Stage::Plan));
        }

        let housekeeping_group_count = groups.len().div_ceil(2).max(1);
        let max_workload_groups = groups.len().saturating_sub(housekeeping_group_count);
        if max_workload_groups == 0 {
            return Err(SysboostError::new(
                ErrorCode::PlanningError,
                "no workload CPU group remains after the housekeeping reserve",
            )
            .with_stage(Stage::Plan));
        }

        let mut fallbacks = Vec::new();
        if policy.prefer_performance_cores
            && self.capacity_mode != CpuCapacityMode::HeterogeneousProven
        {
            fallbacks.push(match self.capacity_mode {
                CpuCapacityMode::Homogeneous => CpuPlacementFallback::HomogeneousTopology,
                CpuCapacityMode::Unknown => CpuPlacementFallback::CapacityMetadataUnavailable,
                CpuCapacityMode::HeterogeneousProven => unreachable!(),
            });
        }

        let preferred_numa = policy.preferred_numa_node;
        let mut candidates = groups.clone();
        if let Some(node) = preferred_numa {
            let preferred = candidates
                .iter()
                .filter(|group| group.numa_node == Some(node))
                .cloned()
                .collect::<Vec<_>>();
            if preferred.is_empty() {
                fallbacks.push(CpuPlacementFallback::NumaPreferenceUnavailable);
            } else {
                let preferred_ids = preferred
                    .iter()
                    .flat_map(|group| group.cpus.as_slice().iter().copied())
                    .collect::<BTreeSet<_>>();
                let mut remainder = candidates
                    .into_iter()
                    .filter(|group| {
                        !group
                            .cpus
                            .as_slice()
                            .iter()
                            .any(|cpu| preferred_ids.contains(cpu))
                    })
                    .collect::<Vec<_>>();
                candidates = preferred;
                candidates.append(&mut remainder);
            }
        }

        candidates.sort_by(|left, right| {
            let left_preferred = preferred_numa.is_some_and(|node| left.numa_node == Some(node));
            let right_preferred = preferred_numa.is_some_and(|node| right.numa_node == Some(node));
            right_preferred
                .cmp(&left_preferred)
                .then_with(|| {
                    if policy.prefer_performance_cores
                        && self.capacity_mode == CpuCapacityMode::HeterogeneousProven
                    {
                        capacity_rank(left.performance_class)
                            .cmp(&capacity_rank(right.performance_class))
                    } else {
                        core::cmp::Ordering::Equal
                    }
                })
                .then_with(|| left.cpus.cmp(&right.cpus))
        });

        let requested_logical = policy.workload_cpu_count.unwrap_or(usize::MAX);
        if requested_logical == 0 {
            return Err(SysboostError::new(
                ErrorCode::InvalidInput,
                "requested workload CPU count must be positive",
            )
            .with_stage(Stage::Plan));
        }
        if policy.workload_cpu_count.is_some_and(|requested| {
            let maximum_selectable_logical = candidates
                .iter()
                .take(max_workload_groups)
                .map(|group| group.cpus.as_slice().len())
                .sum::<usize>();
            requested > online.as_slice().len().saturating_sub(1)
                || requested > maximum_selectable_logical
        }) {
            fallbacks.push(CpuPlacementFallback::ReducedToPreserveHousekeeping);
        }

        let mut selected_groups = Vec::new();
        let mut selected_logical = 0_usize;
        for group in candidates {
            if selected_groups.len() >= max_workload_groups {
                break;
            }
            if selected_logical >= requested_logical && !selected_groups.is_empty() {
                break;
            }
            selected_logical += group.cpus.as_slice().len();
            selected_groups.push(group);
        }
        if selected_groups.is_empty() {
            return Err(SysboostError::new(
                ErrorCode::PlanningError,
                "the topology produced no eligible workload CPU group",
            )
            .with_stage(Stage::Plan));
        }

        let workload_cpus = CpuSet::new(
            selected_groups
                .iter()
                .flat_map(|group| group.cpus.as_slice().iter().copied())
                .collect(),
        )?;
        let workload_ids = workload_cpus
            .as_slice()
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let housekeeping_cpus = CpuSet::new(
            online
                .as_slice()
                .iter()
                .copied()
                .filter(|cpu| !workload_ids.contains(cpu))
                .collect(),
        )?;
        if workload_cpus.as_slice().len() >= online.as_slice().len()
            || housekeeping_cpus.as_slice().is_empty()
        {
            return Err(SysboostError::new(
                ErrorCode::PlanningError,
                "soft isolation would consume the entire online CPU set",
            )
            .with_stage(Stage::Plan));
        }

        let workload_mask = CpuAffinityMask::from_cpu_set(&workload_cpus)?;
        let housekeeping_mask = CpuAffinityMask::from_cpu_set(&housekeeping_cpus)?;
        Ok(CpuIsolationPlan {
            workload_cpus,
            housekeeping_cpus,
            workload_mask,
            housekeeping_mask,
            capacity_mode: self.capacity_mode,
            fallbacks,
            topology_revision: self.revision,
            online_at_plan: online,
            target_identity,
        })
    }
}

/// Thin planner facade useful when a topology is retained by a composition
/// root for several independent dry-run decisions.
#[derive(Clone, Copy, Debug)]
pub struct CpuTopologyPlanner<'a> {
    topology: &'a CpuTopology,
}

impl<'a> CpuTopologyPlanner<'a> {
    /// Bind a planner to one immutable topology snapshot.
    pub const fn new(topology: &'a CpuTopology) -> Self {
        Self { topology }
    }

    /// Plan with no target identity binding.
    pub fn plan(&self, policy: CpuSelectionPolicy) -> Result<CpuIsolationPlan, SysboostError> {
        self.topology.select(policy)
    }

    /// Plan and bind to an approved backend target identity.
    pub fn plan_for_target(
        &self,
        policy: CpuSelectionPolicy,
        target_identity: Option<TargetIdentity>,
    ) -> Result<CpuIsolationPlan, SysboostError> {
        self.topology.select_for_target(policy, target_identity)
    }
}

/// Alias for callers that use the isolation terminology.
pub type CpuIsolationPlanner<'a> = CpuTopologyPlanner<'a>;

/// Explicit, conservative placement options.  The performance-core option
/// only changes ordering after heterogeneous capacity has been proven.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct CpuSelectionPolicy {
    /// Prefer kernel-proven highest-capacity core groups for the workload.
    pub prefer_performance_cores: bool,
    /// Optional desired logical CPU count.  The planner may round up to keep
    /// an SMT core group intact and caps the result to preserve housekeeping.
    pub workload_cpu_count: Option<usize>,
    /// Optional NUMA node preference.  It is a preference, not permission to
    /// violate the housekeeping reserve.
    pub preferred_numa_node: Option<u32>,
}

impl CpuSelectionPolicy {
    /// Construct the default homogeneous-safe policy.
    pub const fn conservative() -> Self {
        Self {
            prefer_performance_cores: false,
            workload_cpu_count: None,
            preferred_numa_node: None,
        }
    }

    /// Construct the policy represented by `--prefer-performance-cores`.
    pub const fn prefer_performance_cores() -> Self {
        Self {
            prefer_performance_cores: true,
            workload_cpu_count: None,
            preferred_numa_node: None,
        }
    }

    /// Set whether the capacity-aware preference is requested.
    pub const fn with_prefer_performance_cores(mut self, enabled: bool) -> Self {
        self.prefer_performance_cores = enabled;
        self
    }

    /// Request a logical CPU count, subject to SMT and housekeeping safety.
    pub const fn with_workload_cpu_count(mut self, count: usize) -> Self {
        self.workload_cpu_count = Some(count);
        self
    }

    /// Prefer a NUMA node for the workload set.
    pub const fn with_preferred_numa_node(mut self, node: u32) -> Self {
        self.preferred_numa_node = Some(node);
        self
    }

    /// Parse the closed placement flag from command-line-like arguments.
    ///
    /// Non-option arguments are ignored so callers can pass a complete argv;
    /// unknown options are rejected rather than silently changing placement.
    pub fn from_args<I, S>(args: I) -> Result<Self, SysboostError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut policy = Self::conservative();
        for argument in args {
            let argument = argument.as_ref();
            if argument == PREFER_PERFORMANCE_CORES_FLAG {
                policy.prefer_performance_cores = true;
            } else if argument.starts_with('-') {
                return Err(SysboostError::new(
                    ErrorCode::ConfigError,
                    "unknown CPU placement option",
                )
                .with_stage(Stage::Config));
            }
        }
        Ok(policy)
    }
}

/// Backward-friendly name for callers that think in terms of placement.
pub type CpuPlacementPolicy = CpuSelectionPolicy;

/// A software CPU affinity mask.  Bits are encoded little-endian by CPU ID,
/// matching the conventional Linux mask representation.  This value is only
/// generated for a typed plan; it does not perform an affinity syscall.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CpuAffinityMask {
    bytes: Vec<u8>,
}

impl CpuAffinityMask {
    /// Generate a mask from a canonical CPU set.
    pub fn from_cpu_set(cpus: &CpuSet) -> Result<Self, SysboostError> {
        let Some(max_cpu) = cpus.as_slice().last().copied() else {
            return Err(SysboostError::new(
                ErrorCode::InvalidInput,
                "cannot generate an affinity mask for an empty CPU set",
            ));
        };
        let bytes = usize::try_from(max_cpu / 8)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| {
                SysboostError::new(ErrorCode::InvalidInput, "CPU affinity mask size overflowed")
            })?;
        if bytes > CPUSET_CAPACITY_LIMIT / 8 {
            return Err(SysboostError::new(
                ErrorCode::InvalidInput,
                "CPU affinity mask exceeds the bounded planning size",
            ));
        }
        let mut output = vec![0_u8; bytes];
        for cpu in cpus.as_slice() {
            output[usize::try_from(*cpu / 8).expect("bounded CPU index")] |= 1_u8 << (*cpu % 8);
        }
        Ok(Self { bytes: output })
    }

    /// Return the raw little-endian mask bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Return a stable hexadecimal mask representation for dry-run output.
    pub fn to_hex(&self) -> String {
        let mut output = String::with_capacity(self.bytes.len() * 2);
        for byte in self.bytes.iter().rev() {
            let _ = write!(&mut output, "{byte:02x}");
        }
        output
    }
}

/// Why a placement plan fell back from a requested preference.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CpuPlacementFallback {
    /// Capacity was uniform; the planner used deterministic core order.
    HomogeneousTopology,
    /// One or more online CPUs lacked usable capacity metadata.
    CapacityMetadataUnavailable,
    /// The requested NUMA node was not represented by online topology facts.
    NumaPreferenceUnavailable,
    /// The requested workload size was capped to retain housekeeping CPUs.
    ReducedToPreserveHousekeeping,
}

impl fmt::Display for CpuPlacementFallback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::HomogeneousTopology => "homogeneous-topology",
            Self::CapacityMetadataUnavailable => "capacity-metadata-unavailable",
            Self::NumaPreferenceUnavailable => "numa-preference-unavailable",
            Self::ReducedToPreserveHousekeeping => "reduced-to-preserve-housekeeping",
        })
    }
}

/// Reversible runtime soft-isolation decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CpuIsolationPlan {
    /// CPUs assigned to the explicit workload cpuset.
    pub workload_cpus: CpuSet,
    /// CPUs retained for all unclassified/system housekeeping work.
    pub housekeeping_cpus: CpuSet,
    /// Generated workload affinity mask.
    pub workload_mask: CpuAffinityMask,
    /// Generated housekeeping affinity mask.
    pub housekeeping_mask: CpuAffinityMask,
    /// Capacity evidence mode used by the decision.
    pub capacity_mode: CpuCapacityMode,
    /// Deterministic fallback explanations, in decision order.
    pub fallbacks: Vec<CpuPlacementFallback>,
    /// Topology revision captured at planning time.
    pub topology_revision: TopologyRevision,
    /// Online set captured at planning time.
    pub online_at_plan: CpuSet,
    /// Target identity captured at planning time, when bound to a cgroup.
    pub target_identity: Option<TargetIdentity>,
}

impl CpuIsolationPlan {
    /// Return the first fallback reason, if any.
    pub fn primary_fallback(&self) -> Option<CpuPlacementFallback> {
        self.fallbacks.first().copied()
    }

    /// Validate the plan against freshly discovered topology and target
    /// identity immediately before handing it to the privilege boundary.
    ///
    /// A changed online set, topology revision, or target identity is a hard
    /// failure.  The planner is never allowed to silently recompute a new
    /// placement during apply.
    pub fn validate_before_apply(
        &self,
        current: &CpuTopology,
        current_target_identity: Option<TargetIdentity>,
    ) -> Result<(), SysboostError> {
        if current.revision != self.topology_revision
            || current.online.as_ref() != Some(&self.online_at_plan)
        {
            return Err(SysboostError::new(
                ErrorCode::TargetError,
                "CPU topology or online CPU set changed after planning",
            )
            .with_stage(Stage::Apply));
        }
        let current_online = current.online.as_ref().ok_or_else(|| {
            SysboostError::new(
                ErrorCode::TargetError,
                "current online CPU set disappeared after planning",
            )
            .with_stage(Stage::Apply)
        })?;
        if self
            .workload_cpus
            .as_slice()
            .iter()
            .any(|cpu| !current_online.as_slice().contains(cpu))
            || self
                .housekeeping_cpus
                .as_slice()
                .iter()
                .any(|cpu| !current_online.as_slice().contains(cpu))
        {
            return Err(SysboostError::new(
                ErrorCode::TargetError,
                "planned CPU set contains a CPU that is no longer online",
            )
            .with_stage(Stage::Apply));
        }
        if self.target_identity != current_target_identity {
            return Err(SysboostError::new(
                ErrorCode::TargetError,
                "CPU placement target identity changed after planning",
            )
            .with_stage(Stage::Apply));
        }
        Ok(())
    }

    /// Alias emphasizing that this is the final pre-apply gate.
    pub fn revalidate_before_apply(
        &self,
        current: &CpuTopology,
        current_target_identity: Option<TargetIdentity>,
    ) -> Result<(), SysboostError> {
        self.validate_before_apply(current, current_target_identity)
    }

    /// Revalidate the plan and construct the existing typed cgroup cpuset
    /// mutation for transaction submission.  Revalidation is part of this
    /// constructor so a caller cannot serialize a stale plan through this
    /// placement API.
    pub fn to_cgroup_cpuset_mutation(
        &self,
        current: &CpuTopology,
        current_target_identity: TargetIdentity,
        mutation_id: MutationId,
        cgroup: CgroupId,
        current_cpuset_precondition: StateFingerprint,
    ) -> Result<PlannedMutation, SysboostError> {
        self.validate_before_apply(current, Some(current_target_identity))?;
        if self.target_identity != Some(current_target_identity) {
            return Err(SysboostError::new(
                ErrorCode::TargetError,
                "cpuset mutation target identity is not the planned identity",
            )
            .with_stage(Stage::Plan));
        }
        let capability = CapabilityId::new("cgroup.cpuset.cpus")
            .expect("static cgroup cpuset capability is valid");
        let kind = MutationKind::CgroupCpuset {
            cgroup: cgroup.clone(),
            cpus: self.workload_cpus.clone(),
        };
        PlannedMutation::new(
            mutation_id,
            capability,
            cgroup.handle,
            kind,
            TypedValue::CgroupCpuset(self.workload_cpus.clone()),
            current_cpuset_precondition,
            EqualityKind::SetExact,
            Vec::new(),
        )
    }

    /// Render the representative decision for a deterministic dry run.
    pub fn explain(&self) -> String {
        let mut output = String::new();
        let _ = writeln!(&mut output, "capacity: {}", self.capacity_mode);
        let _ = writeln!(
            &mut output,
            "workload CPUs: {} (mask=0x{})",
            render_cpu_set(&self.workload_cpus),
            self.workload_mask.to_hex()
        );
        let _ = writeln!(
            &mut output,
            "housekeeping CPUs: {} (mask=0x{})",
            render_cpu_set(&self.housekeeping_cpus),
            self.housekeeping_mask.to_hex()
        );
        if self.fallbacks.is_empty() {
            output.push_str("fallback: none\n");
        } else {
            let _ = writeln!(
                &mut output,
                "fallback: {}",
                self.fallbacks
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            );
        }
        output
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum CoreKey {
    PackageCore(u32, u32),
    SiblingSet(CpuSet),
}

fn classify_capacities(cpus: &mut [CpuTopologyCpu], online: Option<&CpuSet>) -> CpuCapacityMode {
    let Some(online) = online else {
        return CpuCapacityMode::Unknown;
    };
    let online_cpus = cpus
        .iter()
        .filter(|cpu| online.as_slice().contains(&cpu.id))
        .collect::<Vec<_>>();
    let mut capacities = online_cpus
        .iter()
        .map(|cpu| cpu.capacity)
        .collect::<Option<Vec<_>>>();
    let Some(mut capacities) = capacities.take() else {
        return CpuCapacityMode::Unknown;
    };
    if capacities.contains(&0) {
        return CpuCapacityMode::Unknown;
    }
    capacities.sort_unstable();
    capacities.dedup();
    let mode = if capacities.len() == 1 {
        CpuCapacityMode::Homogeneous
    } else {
        CpuCapacityMode::HeterogeneousProven
    };
    if mode == CpuCapacityMode::HeterogeneousProven {
        let maximum = *capacities.last().expect("capacity list is non-empty");
        for cpu in cpus {
            if !online.as_slice().contains(&cpu.id) {
                continue;
            }
            cpu.performance_class = match cpu.capacity {
                Some(capacity) if capacity == maximum => CpuPerformanceClass::Performance,
                Some(_) => CpuPerformanceClass::Efficiency,
                None => CpuPerformanceClass::Unknown,
            };
        }
    }
    mode
}

fn capacity_rank(class: CpuPerformanceClass) -> u8 {
    match class {
        CpuPerformanceClass::Performance => 0,
        CpuPerformanceClass::Unknown => 1,
        CpuPerformanceClass::Efficiency => 2,
    }
}

fn normalize_numa(numa: &NumaFacts) -> Result<BTreeMap<u32, CpuSet>, SysboostError> {
    let mut nodes = BTreeMap::new();
    for node in &numa.nodes {
        let Some(cpus) = node.cpus.as_deref() else {
            continue;
        };
        nodes.insert(node.id, parse_cpu_list(cpus)?);
    }
    Ok(nodes)
}

/// Parse the kernel's comma-separated CPU list grammar, including ranges.
pub fn parse_cpu_list(value: &str) -> Result<CpuSet, SysboostError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(topology_error("CPU list is empty"));
    }
    let mut cpus = Vec::new();
    for part in value.split(',').map(str::trim) {
        if part.is_empty() {
            return Err(topology_error("CPU list contains an empty component"));
        }
        if let Some((start, end)) = part.split_once('-') {
            let start = start
                .parse::<u32>()
                .map_err(|_| topology_error("CPU list range start is malformed"))?;
            let end = end
                .parse::<u32>()
                .map_err(|_| topology_error("CPU list range end is malformed"))?;
            if start > end {
                return Err(topology_error("CPU list range is reversed"));
            }
            let span = usize::try_from(u64::from(end) - u64::from(start) + 1)
                .unwrap_or(CPUSET_CAPACITY_LIMIT + 1);
            if cpus.len().saturating_add(span) > CPUSET_CAPACITY_LIMIT {
                return Err(topology_error("CPU list exceeds the bounded planning size"));
            }
            cpus.extend(start..=end);
        } else {
            cpus.push(
                part.parse::<u32>()
                    .map_err(|_| topology_error("CPU list member is malformed"))?,
            );
        }
        if cpus.len() > CPUSET_CAPACITY_LIMIT {
            return Err(topology_error("CPU list exceeds the bounded planning size"));
        }
    }
    CpuSet::new(cpus)
}

fn render_cpu_set(cpus: &CpuSet) -> String {
    let values = cpus.as_slice();
    if values.is_empty() {
        return String::new();
    }
    let mut ranges = Vec::new();
    let mut start = values[0];
    let mut end = start;
    for cpu in values.iter().copied().skip(1) {
        if cpu == end.saturating_add(1) {
            end = cpu;
        } else {
            ranges.push(render_range(start, end));
            start = cpu;
            end = cpu;
        }
    }
    ranges.push(render_range(start, end));
    ranges.join(",")
}

fn render_range(start: u32, end: u32) -> String {
    if start == end {
        start.to_string()
    } else {
        format!("{start}-{end}")
    }
}

fn topology_revision(
    possible: &Option<CpuSet>,
    online: &Option<CpuSet>,
    cpus: &[CpuTopologyCpu],
    numa: &BTreeMap<u32, CpuSet>,
) -> TopologyRevision {
    let mut bytes = Vec::new();
    write_option_set(&mut bytes, possible);
    write_option_set(&mut bytes, online);
    for cpu in cpus {
        bytes.extend_from_slice(&cpu.id.to_be_bytes());
        bytes.extend_from_slice(&cpu.package_id.unwrap_or(u32::MAX).to_be_bytes());
        bytes.extend_from_slice(&cpu.core_id.unwrap_or(u32::MAX).to_be_bytes());
        bytes.extend_from_slice(&cpu.capacity.unwrap_or(0).to_be_bytes());
        bytes.push(u8::from(cpu.online));
        bytes.push(capacity_rank(cpu.performance_class));
        write_set(&mut bytes, &cpu.thread_siblings);
        bytes.extend_from_slice(&cpu.numa_node.unwrap_or(u32::MAX).to_be_bytes());
    }
    for (node, cpus) in numa {
        bytes.extend_from_slice(&node.to_be_bytes());
        write_set(&mut bytes, cpus);
    }
    TopologyRevision(stable_digest(&bytes))
}

fn write_option_set(bytes: &mut Vec<u8>, set: &Option<CpuSet>) {
    match set {
        Some(set) => {
            bytes.push(1);
            write_set(bytes, set);
        }
        None => bytes.push(0),
    }
}

fn write_set(bytes: &mut Vec<u8>, set: &CpuSet) {
    bytes.extend_from_slice(&(set.as_slice().len() as u64).to_be_bytes());
    for cpu in set.as_slice() {
        bytes.extend_from_slice(&cpu.to_be_bytes());
    }
}

fn stable_digest(bytes: &[u8]) -> [u8; 32] {
    let mut lanes = [
        0xcbf29ce484222325_u64,
        0x84222325cb29ce4_u64,
        0x9e3779b185ebca87_u64,
        0xd6e8feb86659fd93_u64,
    ];
    for (index, byte) in bytes.iter().copied().enumerate() {
        let lane = index % lanes.len();
        lanes[lane] ^= u64::from(byte);
        lanes[lane] = lanes[lane].wrapping_mul(0x100000001b3);
        lanes[lane] ^= lanes[lane].rotate_left(27);
        lanes[lane] = lanes[lane].wrapping_add((index as u64).wrapping_mul(0x9e37));
    }
    let mut output = [0_u8; 32];
    for (index, lane) in lanes.iter().enumerate() {
        output[index * 8..index * 8 + 8].copy_from_slice(&lane.to_be_bytes());
    }
    output
}

fn topology_error(message: &str) -> SysboostError {
    SysboostError::new(ErrorCode::CapabilityError, message).with_stage(Stage::Detect)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::{NumaFacts, NumaNodeFacts};
    use sysboost_core::TargetId;

    fn facts(
        possible: &str,
        online: &str,
        capacities: &[Option<u64>],
        siblings: &[&str],
    ) -> CpuTopologyFacts {
        CpuTopologyFacts {
            possible: Some(possible.to_owned()),
            online: Some(online.to_owned()),
            entries: capacities
                .iter()
                .enumerate()
                .map(|(id, capacity)| CpuTopologyEntry {
                    cpu: id as u32,
                    package_id: Some(0),
                    core_id: Some(id as u32),
                    thread_siblings: siblings.get(id).map(|value| (*value).to_owned()),
                    capacity: *capacity,
                    online: online.split(',').any(|part| part.trim() == id.to_string()),
                })
                .collect(),
            heterogeneous: false,
        }
    }

    fn topology(
        possible: &str,
        online: &str,
        capacities: &[Option<u64>],
        siblings: &[&str],
        numa_nodes: Vec<NumaNodeFacts>,
    ) -> CpuTopology {
        CpuTopology::from_facts(
            &facts(possible, online, capacities, siblings),
            &NumaFacts { nodes: numa_nodes },
        )
        .expect("valid topology fixture")
    }

    #[test]
    fn homogeneous_four_core_plan_preserves_housekeeping() {
        let planned_topology = topology(
            "0-3",
            "0-3",
            &[Some(1024), Some(1024), Some(1024), Some(1024)],
            &["0", "1", "2", "3"],
            Vec::new(),
        );
        let plan = planned_topology
            .select(CpuSelectionPolicy::conservative())
            .expect("four CPUs can be split conservatively");
        assert_eq!(
            planned_topology.capacity_mode(),
            CpuCapacityMode::Homogeneous
        );
        assert_eq!(plan.workload_cpus.as_slice(), &[0, 1]);
        assert_eq!(plan.housekeeping_cpus.as_slice(), &[2, 3]);
        assert!(plan.workload_cpus.as_slice().len() < 4);
    }

    #[test]
    fn smt_siblings_are_kept_in_one_planning_group() {
        let mut fixture = facts(
            "0-3",
            "0-3",
            &[Some(1024), Some(1024), Some(1024), Some(1024)],
            &["0,2", "1,3", "0,2", "1,3"],
        );
        fixture.entries[2].core_id = Some(0);
        fixture.entries[3].core_id = Some(1);
        let planned_topology = CpuTopology::from_facts(&fixture, &NumaFacts { nodes: Vec::new() })
            .expect("valid SMT topology fixture");
        let groups = planned_topology.core_groups();
        assert_eq!(groups.len(), 2);
        let plan = planned_topology
            .select(CpuSelectionPolicy::conservative())
            .expect("two SMT core groups can be split");
        assert_eq!(plan.workload_cpus.as_slice(), &[0, 2]);
        assert_eq!(plan.housekeeping_cpus.as_slice(), &[1, 3]);
    }

    #[test]
    fn hybrid_preference_uses_kernel_capacity_not_cpu_model() {
        let topology = topology(
            "0-3",
            "0-3",
            &[Some(1024), Some(1024), Some(512), Some(512)],
            &["0", "1", "2", "3"],
            Vec::new(),
        );
        let plan = topology
            .select(CpuSelectionPolicy::prefer_performance_cores())
            .expect("hybrid capacity can be selected");
        assert_eq!(
            topology.capacity_mode(),
            CpuCapacityMode::HeterogeneousProven
        );
        assert_eq!(plan.workload_cpus.as_slice(), &[0, 1]);
        assert_eq!(plan.housekeeping_cpus.as_slice(), &[2, 3]);
        assert!(plan.fallbacks.is_empty());
    }

    #[test]
    fn sparse_online_ids_exclude_offline_possible_cpus() {
        let topology = topology(
            "0-3,7",
            "0,2,7",
            &[
                Some(1024),
                Some(1024),
                Some(1024),
                Some(1024),
                None,
                None,
                None,
                Some(1024),
            ],
            &["0", "1", "2", "3", "4", "5", "6", "7"],
            Vec::new(),
        );
        let plan = topology
            .select(CpuSelectionPolicy::conservative())
            .expect("three sparse online CPUs can be split");
        for cpu in plan
            .workload_cpus
            .as_slice()
            .iter()
            .chain(plan.housekeeping_cpus.as_slice())
        {
            assert!([0, 2, 7].contains(cpu));
        }
        assert!(!plan.workload_cpus.as_slice().contains(&1));
    }

    #[test]
    fn numa_preference_is_deterministic_and_keeps_global_housekeeping() {
        let topology = topology(
            "0-3",
            "0-3",
            &[Some(1024), Some(1024), Some(512), Some(512)],
            &["0", "1", "2", "3"],
            vec![
                NumaNodeFacts {
                    id: 0,
                    cpus: Some("0-1".to_owned()),
                    memory_total_kb: Some(1024),
                },
                NumaNodeFacts {
                    id: 1,
                    cpus: Some("2-3".to_owned()),
                    memory_total_kb: Some(1024),
                },
            ],
        );
        let plan = topology
            .select(CpuSelectionPolicy::conservative().with_preferred_numa_node(1))
            .expect("NUMA preference can be honored");
        assert_eq!(plan.workload_cpus.as_slice(), &[2, 3]);
        assert_eq!(plan.housekeeping_cpus.as_slice(), &[0, 1]);
    }

    #[test]
    fn missing_capacity_metadata_falls_back_without_guessing() {
        let topology = topology(
            "0-3",
            "0-3",
            &[None, None, None, None],
            &["0", "1", "2", "3"],
            Vec::new(),
        );
        let plan = topology
            .select(CpuSelectionPolicy::prefer_performance_cores())
            .expect("unknown capacity uses the conservative fallback");
        assert_eq!(topology.capacity_mode(), CpuCapacityMode::Unknown);
        assert_eq!(
            plan.primary_fallback(),
            Some(CpuPlacementFallback::CapacityMetadataUnavailable)
        );
        assert_eq!(plan.workload_cpus.as_slice(), &[0, 1]);
    }

    #[test]
    fn insufficient_online_cpus_are_rejected() {
        let topology = topology("0", "0", &[Some(1024)], &["0"], Vec::new());
        let error = topology
            .select(CpuSelectionPolicy::conservative())
            .expect_err("one CPU cannot provide housekeeping");
        assert_eq!(error.code, ErrorCode::PlanningError);
    }

    #[test]
    fn affinity_mask_and_flag_parsing_are_closed_and_deterministic() {
        let cpus = parse_cpu_list("0,7").expect("valid sparse CPU list");
        let mask = CpuAffinityMask::from_cpu_set(&cpus).expect("mask is bounded");
        assert_eq!(mask.as_bytes(), &[0x81]);
        assert_eq!(mask.to_hex(), "81");
        let policy = CpuSelectionPolicy::from_args(["sysboost", PREFER_PERFORMANCE_CORES_FLAG])
            .expect("closed flag parses");
        assert!(policy.prefer_performance_cores);
        assert!(CpuSelectionPolicy::from_args(["--unknown"]).is_err());
    }

    #[test]
    fn online_or_target_identity_changes_fail_before_mutation_construction() {
        let target_identity = TargetIdentity::from_bytes([7; 16]);
        let planned_topology = topology(
            "0-3",
            "0-3",
            &[Some(1024), Some(1024), Some(1024), Some(1024)],
            &["0", "1", "2", "3"],
            Vec::new(),
        );
        let plan = planned_topology
            .select_for_target(CpuSelectionPolicy::conservative(), Some(target_identity))
            .expect("plan is valid");
        let changed = topology(
            "0-3",
            "0-2",
            &[Some(1024), Some(1024), Some(1024), Some(1024)],
            &["0", "1", "2", "3"],
            Vec::new(),
        );
        assert_eq!(
            plan.validate_before_apply(&changed, Some(target_identity))
                .expect_err("online changes must fail closed")
                .code,
            ErrorCode::TargetError
        );
        assert!(plan
            .validate_before_apply(&planned_topology, Some(TargetIdentity::from_bytes([8; 16])))
            .is_err());
    }

    #[test]
    fn placement_serializes_only_to_the_existing_typed_cpuset_operation() {
        let target_identity = TargetIdentity::from_bytes([9; 16]);
        let topology = topology(
            "0-3",
            "0-3",
            &[Some(1024), Some(1024), Some(1024), Some(1024)],
            &["0", "1", "2", "3"],
            Vec::new(),
        );
        let plan = topology
            .select_for_target(CpuSelectionPolicy::conservative(), Some(target_identity))
            .expect("plan is valid");
        plan.validate_before_apply(&topology, Some(target_identity))
            .expect("unchanged topology and target pass the final gate");

        let cgroup = CgroupId::new(
            7,
            11,
            TargetId::new("cgroup.workload").expect("valid cgroup target"),
        );
        let mutation = plan
            .to_cgroup_cpuset_mutation(
                &topology,
                target_identity,
                MutationId::new(1),
                cgroup,
                StateFingerprint::from_bytes([3; 32]),
            )
            .expect("planner emits the existing typed operation");
        assert_eq!(mutation.kind.operation_id().as_str(), "cgroup.cpuset.cpus");
        assert_eq!(
            mutation.desired,
            TypedValue::CgroupCpuset(plan.workload_cpus)
        );
    }
}
