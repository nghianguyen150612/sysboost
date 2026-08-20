//! Read-only Linux capability discovery.
//!
//! The discovery engine consumes only injected read ports.  It never writes a
//! pseudo-file, opens a device for control, invokes a command, or turns a
//! model/vendor string into a mutation decision.  A host constructor is
//! provided for the real `/sys`, `/proc`, `/sys/fs/cgroup`, and `/run` roots;
//! tests use the same engine with in-memory fixtures.

use std::collections::BTreeMap;

use sysboost_core::capability::ids as core_capability_ids;
use sysboost_core::{
    BackendId, CapabilityDescriptor, CapabilityEvidence, CapabilityId, CapabilityInventory,
    CapabilityState, EqualityKind, EvidenceSource, FeatureClass, PrivilegeRequirement, RiskClass,
    TargetId, TargetKind,
};
use sysboost_core::{ErrorCode, SysboostError, Timestamp};
use sysboost_platform::{Clock, DirectoryEntry, EntryKind, ReadOnlyFileSystem, RelativePath};

use crate::cgroup::CgroupVersion;
use crate::fs::RootedFilesystem;

/// Stable report-only capability names used by the Linux discovery matrix.
pub mod ids {
    /// Kernel and runtime environment evidence.
    pub const KERNEL_ENVIRONMENT: &str = "environment.kernel";
    /// CPU topology evidence.
    pub const CPU_TOPOLOGY: &str = "cpu.topology";
    /// Heterogeneous CPU capacity evidence.
    pub const CPU_CAPACITY: &str = "cpu.capacity";
    /// NUMA topology evidence.
    pub const NUMA_TOPOLOGY: &str = "memory.numa";
    /// Cgroup v2 mount and controller evidence.
    pub const CGROUP_V2: &str = "cgroup.v2";
    /// Cgroup utilization-clamp evidence.
    pub const CGROUP_UCLAMP: &str = "cgroup.uclamp";
    /// CPU boost/turbo interface evidence.
    pub const CPU_BOOST: &str = "cpu.policy.boost";
    /// Platform profile evidence.
    pub const PLATFORM_PROFILE: &str = "platform.profile";
    /// GPU device and driver evidence.
    pub const GPU_DEVICE: &str = "gpu.device";
    /// IRQ affinity metadata evidence.
    pub const IRQ_METADATA: &str = "irq.metadata";
    /// Transparent huge page evidence.
    pub const THP: &str = "memory.thp";
    /// Swap evidence.
    pub const SWAP: &str = "memory.swap";
    /// zram evidence.
    pub const ZRAM: &str = "memory.zram";
    /// zswap evidence.
    pub const ZSWAP: &str = "memory.zswap";
    /// Scheduler facility evidence.
    pub const SCHEDULER: &str = "scheduler.facilities";
    /// systemd presence evidence.
    pub const SYSTEMD: &str = "service.systemd";
}

const DISCOVERY_BACKEND: &str = "linux.discovery";
const MAX_DISCOVERY_READ_BYTES: usize = 1024 * 1024;

/// High-level interpretation of one read-only discovery result.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DiscoveryStatus {
    /// The interface was present, parsed, and understood by this detector.
    Supported,
    /// The interface was not exposed by this host or fixture.
    Unavailable,
    /// The interface was present but the read was denied.
    PermissionDenied,
    /// The interface was present but sysboost has no reviewed operation for it.
    PresentButUnsupported,
    /// The observation is intentionally informational and never mutation-ready.
    ReportOnly,
    /// The interface was present but its evidence was malformed or incomplete.
    Indeterminate,
}

/// One capability-matrix finding, including optional target identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityFinding {
    /// Stable semantic capability identity.
    pub id: CapabilityId,
    /// Optional opaque target identity for per-policy/device findings.
    pub target: Option<TargetId>,
    /// Read-only discovery status.
    pub status: DiscoveryStatus,
    /// Product safety classification.
    pub classification: FeatureClass,
    /// Evidence supporting the status.
    pub evidence: Vec<CapabilityEvidence>,
    /// Bounded, normalized attributes useful to doctor output.
    pub attributes: BTreeMap<String, String>,
}

/// Read-only sources used by [`CapabilityDiscovery`].
#[derive(Clone, Copy)]
pub struct DiscoverySources<'a> {
    /// Approved `/sys` root or virtual equivalent.
    pub sysfs: &'a dyn ReadOnlyFileSystem,
    /// Approved `/proc` root or virtual equivalent.
    pub procfs: &'a dyn ReadOnlyFileSystem,
    /// Optional cgroup filesystem root.
    pub cgroup: Option<&'a dyn ReadOnlyFileSystem>,
    /// Optional `/run` root used for service-presence evidence.
    pub run: Option<&'a dyn ReadOnlyFileSystem>,
}

impl<'a> DiscoverySources<'a> {
    /// Construct sources with only the required sysfs and procfs roots.
    pub fn new(sysfs: &'a dyn ReadOnlyFileSystem, procfs: &'a dyn ReadOnlyFileSystem) -> Self {
        Self {
            sysfs,
            procfs,
            cgroup: None,
            run: None,
        }
    }

    /// Add an approved cgroup root.
    pub fn with_cgroup(mut self, cgroup: &'a dyn ReadOnlyFileSystem) -> Self {
        self.cgroup = Some(cgroup);
        self
    }

    /// Add an approved runtime root.
    pub fn with_run(mut self, run: &'a dyn ReadOnlyFileSystem) -> Self {
        self.run = Some(run);
        self
    }
}

/// Real Linux roots opened in read-only adapter mode.
pub struct HostRoots {
    /// Canonical `/sys` adapter.
    pub sysfs: RootedFilesystem,
    /// Canonical `/proc` adapter.
    pub procfs: RootedFilesystem,
    /// Optional canonical `/sys/fs/cgroup` adapter.
    pub cgroup: Option<RootedFilesystem>,
    /// Optional canonical `/run` adapter.
    pub run: Option<RootedFilesystem>,
}

impl HostRoots {
    /// Open the standard Linux roots without performing any mutation.
    pub fn open() -> Result<Self, SysboostError> {
        let sysfs = RootedFilesystem::new("/sys")?;
        let procfs = RootedFilesystem::new("/proc")?;
        let cgroup = RootedFilesystem::new("/sys/fs/cgroup").ok();
        let run = RootedFilesystem::new("/run").ok();
        Ok(Self {
            sysfs,
            procfs,
            cgroup,
            run,
        })
    }

    /// Borrow these roots as the discovery port set.
    pub fn sources(&self) -> DiscoverySources<'_> {
        let mut sources = DiscoverySources::new(&self.sysfs, &self.procfs);
        if let Some(cgroup) = self.cgroup.as_ref() {
            sources = sources.with_cgroup(cgroup);
        }
        if let Some(run) = self.run.as_ref() {
            sources = sources.with_run(run);
        }
        sources
    }
}

/// Kernel and runtime facts that are useful for diagnosis but never select a
/// tuning operation by themselves.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EnvironmentFacts {
    /// Kernel release from procfs.
    pub kernel_release: Option<String>,
    /// Kernel version/build text from procfs.
    pub kernel_version: Option<String>,
    /// Architecture reported by procfs when available.
    pub architecture: Option<String>,
    /// First vendor string observed in `/proc/cpuinfo`, for context only.
    pub cpu_vendor: Option<String>,
    /// First model string observed in `/proc/cpuinfo`, for context only.
    pub cpu_model: Option<String>,
    /// Number of processor records parsed from procfs.
    pub cpu_count: usize,
    /// Init process name, if readable.
    pub init_name: Option<String>,
    /// Conservative container/namespace hint from procfs evidence.
    pub container_hint: bool,
    /// Evidence strings supporting the container hint.
    pub container_evidence: Vec<String>,
}

/// One detected CPUFreq policy and its read-only values.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CpuFreqPolicyFacts {
    /// Numeric policy identity.
    pub id: u32,
    /// Related CPU list as exposed by sysfs.
    pub related_cpus: Option<String>,
    /// Scaling driver name.
    pub driver: Option<String>,
    /// Available governor names.
    pub available_governors: Vec<String>,
    /// Current governor.
    pub current_governor: Option<String>,
    /// Current energy-performance preference.
    pub energy_performance_preference: Option<String>,
    /// Available energy-performance preferences.
    pub energy_performance_choices: Vec<String>,
    /// Read-only minimum frequency in kHz.
    pub min_khz: Option<u64>,
    /// Read-only maximum frequency in kHz.
    pub max_khz: Option<u64>,
    /// Read-only current frequency in kHz.
    pub current_khz: Option<u64>,
    /// Names of policy files that could not be read or parsed.
    pub read_failures: Vec<String>,
}

/// CPUFreq-wide and platform-profile observations.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CpuFreqFacts {
    /// Enumerated policies in deterministic numeric order.
    pub policies: Vec<CpuFreqPolicyFacts>,
    /// Global boost/turbo value when exposed.
    pub boost: Option<String>,
    /// Current platform profile.
    pub platform_profile: Option<String>,
    /// Available platform profiles.
    pub platform_profile_choices: Vec<String>,
}

/// One CPU topology record.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CpuTopologyEntry {
    /// Logical CPU number.
    pub cpu: u32,
    /// Package ID when exposed.
    pub package_id: Option<u32>,
    /// Core ID when exposed.
    pub core_id: Option<u32>,
    /// Thread sibling list when exposed.
    pub thread_siblings: Option<String>,
    /// CPU capacity hint when exposed.
    pub capacity: Option<u64>,
    /// Whether the CPU is listed online.
    pub online: bool,
}

/// CPU topology and heterogeneous-capacity summary.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CpuTopologyFacts {
    /// Possible CPU range/list.
    pub possible: Option<String>,
    /// Online CPU range/list.
    pub online: Option<String>,
    /// Per-CPU topology observations.
    pub entries: Vec<CpuTopologyEntry>,
    /// Whether capacity hints contain more than one value.
    pub heterogeneous: bool,
}

/// One NUMA node observation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NumaNodeFacts {
    /// Numeric NUMA node identity.
    pub id: u32,
    /// CPUs assigned to the node.
    pub cpus: Option<String>,
    /// Parsed total memory in kB.
    pub memory_total_kb: Option<u64>,
}

/// NUMA topology summary.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NumaFacts {
    /// Enumerated nodes.
    pub nodes: Vec<NumaNodeFacts>,
}

/// Cgroup v1/v2 controller evidence.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CgroupFacts {
    /// Detected hierarchy version.
    pub version: Option<CgroupVersion>,
    /// Available v2 controllers.
    pub controllers: Vec<String>,
    /// Controllers enabled in the inspected subtree.
    pub enabled_controllers: Vec<String>,
    /// Current CPU weight text.
    pub cpu_weight: Option<String>,
    /// Current CPU max text.
    pub cpu_max: Option<String>,
    /// Current effective CPU set text.
    pub cpuset_cpus: Option<String>,
    /// Current utilization clamp minimum.
    pub uclamp_min: Option<String>,
    /// Current utilization clamp maximum.
    pub uclamp_max: Option<String>,
    /// Current process cgroup membership text.
    pub membership: Option<String>,
}

/// One DRM/GPU device observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GpuDeviceFacts {
    /// Stable enumerated DRM entry name.
    pub name: String,
    /// PCI/device vendor value when readable.
    pub vendor: Option<String>,
    /// PCI/device ID when readable.
    pub device: Option<String>,
    /// PCI class value when readable.
    pub class: Option<String>,
    /// Driver name from the device uevent when readable.
    pub driver: Option<String>,
    /// Entry kind observed during enumeration.
    pub entry_kind: EntryKind,
}

/// GPU discovery summary.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GpuFacts {
    /// Enumerated DRM card entries.
    pub devices: Vec<GpuDeviceFacts>,
}

/// One IRQ affinity metadata observation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IrqEntryFacts {
    /// IRQ number.
    pub irq: u32,
    /// Configured affinity list.
    pub affinity: Option<String>,
    /// Effective affinity list when exposed.
    pub effective_affinity: Option<String>,
}

/// IRQ metadata summary; no affinity write is exposed.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IrqFacts {
    /// Default affinity value.
    pub default_affinity: Option<String>,
    /// Enumerated IRQ entries.
    pub entries: Vec<IrqEntryFacts>,
}

/// Memory and compression-interface observations.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MemoryFacts {
    /// Transparent huge-page enabled mode text.
    pub thp_enabled: Option<String>,
    /// Transparent huge-page defragmentation mode text.
    pub thp_defrag: Option<String>,
    /// Total swap in kB.
    pub swap_total_kb: Option<u64>,
    /// Free swap in kB.
    pub swap_free_kb: Option<u64>,
    /// Number of active swap entries.
    pub active_swap_entries: usize,
    /// Enumerated zram device names.
    pub zram_devices: Vec<String>,
    /// zswap enabled value.
    pub zswap_enabled: Option<String>,
    /// zswap compressor value.
    pub zswap_compressor: Option<String>,
    /// zswap pool value.
    pub zswap_zpool: Option<String>,
}

/// Scheduler and pressure-interface observations.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SchedulerFacts {
    /// Readable scheduler interface names.
    pub facilities: Vec<String>,
    /// Whether CPU pressure information is readable.
    pub cpu_pressure: bool,
    /// Scheduler utilization clamp minimum.
    pub uclamp_min: Option<String>,
    /// Scheduler utilization clamp maximum.
    pub uclamp_max: Option<String>,
    /// NUMA balancing value.
    pub numa_balancing: Option<String>,
    /// Energy-aware scheduling value.
    pub energy_aware: Option<String>,
}

/// systemd/service-presence facts, kept separate from tuning admission.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SystemdFacts {
    /// Whether systemd evidence was found.
    pub present: bool,
    /// Evidence source used for the result.
    pub evidence: Vec<String>,
}

/// Complete read-only discovery output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryReport {
    /// Timestamp supplied by the injected clock.
    pub observed_at: Timestamp,
    /// Kernel/runtime environment facts.
    pub environment: EnvironmentFacts,
    /// CPUFreq and platform-profile facts.
    pub cpufreq: CpuFreqFacts,
    /// CPU topology/capacity facts.
    pub topology: CpuTopologyFacts,
    /// NUMA facts.
    pub numa: NumaFacts,
    /// Cgroup facts.
    pub cgroup: CgroupFacts,
    /// GPU/DRM facts.
    pub gpu: GpuFacts,
    /// IRQ metadata facts.
    pub irq: IrqFacts,
    /// Memory/THP/swap/compression facts.
    pub memory: MemoryFacts,
    /// Scheduler facts.
    pub scheduler: SchedulerFacts,
    /// systemd facts.
    pub systemd: SystemdFacts,
    /// Capability matrix used by planning and diagnostic callers.
    pub findings: Vec<CapabilityFinding>,
    /// Existing core inventory projection for planner consumers.
    pub inventory: CapabilityInventory,
}

/// Read-only capability discovery engine.
pub struct CapabilityDiscovery<'a> {
    sources: DiscoverySources<'a>,
}

impl<'a> CapabilityDiscovery<'a> {
    /// Construct a discovery engine from injected read-only roots.
    pub fn new(sources: DiscoverySources<'a>) -> Self {
        Self { sources }
    }

    /// Detect all supported facts without performing any host mutation.
    pub fn discover(&self, clock: &dyn Clock) -> Result<DiscoveryReport, SysboostError> {
        let observed_at = clock.now()?;
        let mut findings = Vec::new();
        let mut descriptors = Vec::new();

        let (environment, environment_status, environment_evidence) =
            detect_environment(self.sources.procfs);
        add_finding(
            &mut findings,
            ids::KERNEL_ENVIRONMENT,
            None,
            environment_status,
            FeatureClass::BootOnlyReportOnly,
            environment_evidence,
            BTreeMap::new(),
        );

        let (cpufreq, cpufreq_findings) = detect_cpufreq(self.sources.sysfs);
        for finding in cpufreq_findings {
            add_descriptor_for_finding(&mut descriptors, &finding, TargetKind::CpuPolicy);
            findings.push(finding);
        }

        let (topology, topology_findings) = detect_topology(self.sources.sysfs);
        for finding in topology_findings {
            findings.push(finding);
        }

        let (numa, numa_findings) = detect_numa(self.sources.sysfs);
        findings.extend(numa_findings);

        let (cgroup, cgroup_findings) = detect_cgroup(self.sources.cgroup, self.sources.procfs);
        for finding in cgroup_findings {
            if finding.id.as_str() == core_capability_ids::CGROUP_CPU_WEIGHT
                || finding.id.as_str() == core_capability_ids::CGROUP_CPU_MAX
                || finding.id.as_str() == core_capability_ids::CGROUP_CPUSET_CPUS
            {
                add_descriptor_for_finding(&mut descriptors, &finding, TargetKind::Cgroup);
            }
            findings.push(finding);
        }

        let (gpu, gpu_findings) = detect_gpus(self.sources.sysfs);
        for finding in gpu_findings {
            if finding.id.as_str() == core_capability_ids::GPU_PERFORMANCE_PROFILE
                || finding.id.as_str() == core_capability_ids::GPU_POWER_LIMIT
            {
                add_descriptor_for_finding(&mut descriptors, &finding, TargetKind::Gpu);
            }
            findings.push(finding);
        }

        let (irq, irq_findings) = detect_irqs(self.sources.procfs);
        for finding in irq_findings {
            if finding.id.as_str() == core_capability_ids::IRQ_AFFINITY {
                add_descriptor_for_finding(&mut descriptors, &finding, TargetKind::Irq);
            }
            findings.push(finding);
        }

        let (memory, memory_findings) = detect_memory(self.sources.sysfs, self.sources.procfs);
        findings.extend(memory_findings);

        let (scheduler, scheduler_findings) = detect_scheduler(self.sources.procfs);
        findings.extend(scheduler_findings);

        let (systemd, systemd_findings) = detect_systemd(self.sources.procfs, self.sources.run);
        findings.extend(systemd_findings);

        findings.sort_by(|left, right| {
            left.id.as_str().cmp(right.id.as_str()).then_with(|| {
                left.target
                    .as_ref()
                    .map(TargetId::as_str)
                    .cmp(&right.target.as_ref().map(TargetId::as_str))
            })
        });
        descriptors.sort_by(|left, right| {
            left.id
                .as_str()
                .cmp(right.id.as_str())
                .then_with(|| left.backend.as_str().cmp(right.backend.as_str()))
        });

        Ok(DiscoveryReport {
            observed_at,
            environment,
            cpufreq,
            topology,
            numa,
            cgroup,
            gpu,
            irq,
            memory,
            scheduler,
            systemd,
            findings,
            inventory: CapabilityInventory {
                observed_at,
                capabilities: descriptors,
            },
        })
    }
}

impl sysboost_platform::CapabilityDetector for CapabilityDiscovery<'_> {
    fn detect(&self, clock: &dyn Clock) -> Result<CapabilityInventory, SysboostError> {
        self.discover(clock).map(|report| report.inventory)
    }
}

#[derive(Clone, Debug)]
enum Probe<T> {
    Present(T),
    Missing,
    Denied,
    Malformed,
}

fn path(value: &str) -> RelativePath {
    RelativePath::new(value.to_owned()).expect("discovery paths are fixed and validated")
}

fn read_bytes(filesystem: &dyn ReadOnlyFileSystem, value: &str) -> Probe<Vec<u8>> {
    match filesystem.read(&path(value)) {
        Ok(bytes) if bytes.len() <= MAX_DISCOVERY_READ_BYTES => Probe::Present(bytes),
        Ok(_) => Probe::Malformed,
        Err(error) => match error.code {
            ErrorCode::AuthorizationError | ErrorCode::CapabilityError => Probe::Denied,
            ErrorCode::TargetError | ErrorCode::Unsupported => Probe::Missing,
            _ => Probe::Malformed,
        },
    }
}

fn read_text(filesystem: &dyn ReadOnlyFileSystem, value: &str) -> Probe<String> {
    match read_bytes(filesystem, value) {
        Probe::Present(bytes) => match String::from_utf8(bytes) {
            Ok(text) => Probe::Present(text.trim().to_owned()),
            Err(_) => Probe::Malformed,
        },
        Probe::Missing => Probe::Missing,
        Probe::Denied => Probe::Denied,
        Probe::Malformed => Probe::Malformed,
    }
}

fn list(filesystem: &dyn ReadOnlyFileSystem, value: Option<&str>) -> Probe<Vec<DirectoryEntry>> {
    let relative = value.map(path);
    match filesystem.list(relative.as_ref()) {
        Ok(entries) => Probe::Present(entries),
        Err(error) => match error.code {
            ErrorCode::AuthorizationError | ErrorCode::CapabilityError => Probe::Denied,
            ErrorCode::TargetError | ErrorCode::Unsupported => Probe::Missing,
            _ => Probe::Malformed,
        },
    }
}

fn status<T>(probe: &Probe<T>, present: DiscoveryStatus) -> DiscoveryStatus {
    match probe {
        Probe::Present(_) => present,
        Probe::Missing => DiscoveryStatus::Unavailable,
        Probe::Denied => DiscoveryStatus::PermissionDenied,
        Probe::Malformed => DiscoveryStatus::Indeterminate,
    }
}

fn status_for_probes<T>(probes: &[(&Probe<T>, DiscoveryStatus)]) -> DiscoveryStatus {
    if probes
        .iter()
        .any(|(probe, _)| matches!(probe, Probe::Denied))
    {
        return DiscoveryStatus::PermissionDenied;
    }
    if probes
        .iter()
        .any(|(probe, _)| matches!(probe, Probe::Malformed))
    {
        return DiscoveryStatus::Indeterminate;
    }
    probes
        .iter()
        .find_map(|(probe, present)| matches!(probe, Probe::Present(_)).then_some(*present))
        .unwrap_or(DiscoveryStatus::Unavailable)
}

fn combine_statuses(statuses: &[DiscoveryStatus]) -> DiscoveryStatus {
    if statuses
        .iter()
        .any(|status| *status == DiscoveryStatus::PermissionDenied)
    {
        return DiscoveryStatus::PermissionDenied;
    }
    if statuses
        .iter()
        .any(|status| *status == DiscoveryStatus::Indeterminate)
    {
        return DiscoveryStatus::Indeterminate;
    }
    if statuses
        .iter()
        .any(|status| *status == DiscoveryStatus::Supported)
    {
        return DiscoveryStatus::Supported;
    }
    if statuses
        .iter()
        .any(|status| *status == DiscoveryStatus::PresentButUnsupported)
    {
        return DiscoveryStatus::PresentButUnsupported;
    }
    if statuses
        .iter()
        .any(|status| *status == DiscoveryStatus::ReportOnly)
    {
        return DiscoveryStatus::ReportOnly;
    }
    DiscoveryStatus::Unavailable
}

fn evidence(source: EvidenceSource, detail: impl Into<String>) -> CapabilityEvidence {
    CapabilityEvidence {
        source,
        detail: detail.into(),
    }
}

fn probe_evidence<T>(probe: &Probe<T>, source: EvidenceSource, name: &str) -> CapabilityEvidence {
    let detail = match probe {
        Probe::Present(_) => format!("{name} is readable and parsed"),
        Probe::Missing => format!("{name} is not exposed"),
        Probe::Denied => format!("{name} is present but read access was denied"),
        Probe::Malformed => format!("{name} was present but malformed or oversized"),
    };
    evidence(source, detail)
}

fn add_finding(
    findings: &mut Vec<CapabilityFinding>,
    id: &str,
    target: Option<&str>,
    status: DiscoveryStatus,
    classification: FeatureClass,
    evidence: Vec<CapabilityEvidence>,
    attributes: BTreeMap<String, String>,
) {
    let id = CapabilityId::new(id.to_owned()).expect("discovery capability ID is valid");
    let target = target.and_then(|value| TargetId::new(value.to_owned()).ok());
    findings.push(CapabilityFinding {
        id,
        target,
        status,
        classification,
        evidence,
        attributes,
    });
}

fn add_descriptor_for_finding(
    descriptors: &mut Vec<CapabilityDescriptor>,
    finding: &CapabilityFinding,
    target_kind: TargetKind,
) {
    let backend = BackendId::new(DISCOVERY_BACKEND).expect("static backend ID is valid");
    let state = match finding.status {
        DiscoveryStatus::Supported
        | DiscoveryStatus::PresentButUnsupported
        | DiscoveryStatus::ReportOnly => CapabilityState::ReadOnly,
        DiscoveryStatus::Unavailable => CapabilityState::Unsupported,
        DiscoveryStatus::PermissionDenied => CapabilityState::Denied,
        DiscoveryStatus::Indeterminate => CapabilityState::Indeterminate,
    };
    descriptors.push(CapabilityDescriptor {
        id: finding.id.clone(),
        backend,
        target_kind,
        state,
        operations: Vec::new(),
        privilege: PrivilegeRequirement::ReadOnly,
        equality: EqualityKind::ByteExact,
        risk: match finding.classification {
            FeatureClass::RuntimeMutable => RiskClass::Medium,
            FeatureClass::Conditional => RiskClass::Medium,
            FeatureClass::Experimental => RiskClass::Critical,
            FeatureClass::BootOnlyReportOnly => RiskClass::Low,
        },
        classification: finding.classification,
        evidence: finding.evidence.clone(),
    });
}

fn parse_tokens(value: &str) -> Vec<String> {
    let mut values = value
        .split_whitespace()
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

fn parse_u64(probe: Probe<String>) -> Probe<u64> {
    match probe {
        Probe::Present(value) => value
            .parse::<u64>()
            .map(Probe::Present)
            .unwrap_or(Probe::Malformed),
        Probe::Missing => Probe::Missing,
        Probe::Denied => Probe::Denied,
        Probe::Malformed => Probe::Malformed,
    }
}

fn parse_u32(probe: Probe<String>) -> Probe<u32> {
    match probe {
        Probe::Present(value) => value
            .parse::<u32>()
            .map(Probe::Present)
            .unwrap_or(Probe::Malformed),
        Probe::Missing => Probe::Missing,
        Probe::Denied => Probe::Denied,
        Probe::Malformed => Probe::Malformed,
    }
}

fn key_values(value: &str) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    for line in value.lines() {
        let Some((key, value)) = line.split_once([':', '=']) else {
            continue;
        };
        values.insert(key.trim().to_owned(), value.trim().to_owned());
    }
    values
}

fn first_key(value: &str, key: &str) -> Option<String> {
    key_values(value).get(key).cloned()
}

fn sort_numeric_names(entries: &[DirectoryEntry], prefix: &str) -> Vec<u32> {
    let mut values = entries
        .iter()
        .filter_map(|entry| {
            (entry.kind == EntryKind::Directory && entry.name.starts_with(prefix))
                .then(|| entry.name[prefix.len()..].parse::<u32>().ok())
                .flatten()
        })
        .collect::<Vec<_>>();
    values.sort_unstable();
    values.dedup();
    values
}

fn detect_environment(
    procfs: &dyn ReadOnlyFileSystem,
) -> (EnvironmentFacts, DiscoveryStatus, Vec<CapabilityEvidence>) {
    let release = read_text(procfs, "sys/kernel/osrelease");
    let version = read_text(procfs, "sys/kernel/version");
    let cpuinfo = read_text(procfs, "cpuinfo");
    let init = read_text(procfs, "1/comm");
    let membership = read_text(procfs, "1/cgroup");

    let cpuinfo_text = match &cpuinfo {
        Probe::Present(value) => value.as_str(),
        _ => "",
    };
    let cpu_vendor =
        first_key(cpuinfo_text, "vendor_id").or_else(|| first_key(cpuinfo_text, "CPU implementer"));
    let cpu_model =
        first_key(cpuinfo_text, "model name").or_else(|| first_key(cpuinfo_text, "Model"));
    let architecture = first_key(cpuinfo_text, "Architecture");
    let cpu_count = cpuinfo_text
        .lines()
        .filter(|line| line.trim_start().starts_with("processor"))
        .count();

    let membership_text = match &membership {
        Probe::Present(value) => value.as_str(),
        _ => "",
    };
    let mut container_evidence = Vec::new();
    for marker in [
        "docker",
        "kubepods",
        "containerd",
        "libpod",
        "lxc",
        "podman",
    ] {
        if membership_text.to_ascii_lowercase().contains(marker) {
            container_evidence.push(format!("procfs cgroup contains {marker}"));
        }
    }
    if let Probe::Present(value) = &init {
        if value == "systemd" {
            container_evidence.push("init process is systemd".to_owned());
        }
    }
    container_evidence.sort();
    container_evidence.dedup();

    let environment = EnvironmentFacts {
        kernel_release: probe_value(release.clone()),
        kernel_version: probe_value(version.clone()),
        architecture,
        cpu_vendor,
        cpu_model,
        cpu_count,
        init_name: probe_value(init.clone()),
        container_hint: !container_evidence.is_empty()
            && !container_evidence
                .iter()
                .any(|value| value == "init process is systemd"),
        container_evidence,
    };
    let status = status_for_probes(&[(&release, DiscoveryStatus::ReportOnly)]);
    let evidence = vec![
        probe_evidence(&release, EvidenceSource::Procfs, "procfs kernel release"),
        probe_evidence(&version, EvidenceSource::Procfs, "procfs kernel version"),
        probe_evidence(&cpuinfo, EvidenceSource::Procfs, "procfs CPU information"),
        probe_evidence(&init, EvidenceSource::Procfs, "procfs init process"),
        probe_evidence(
            &membership,
            EvidenceSource::Procfs,
            "procfs cgroup membership",
        ),
    ];
    (environment, status, evidence)
}

fn probe_value<T: Clone>(probe: Probe<T>) -> Option<T> {
    match probe {
        Probe::Present(value) => Some(value),
        Probe::Missing | Probe::Denied | Probe::Malformed => None,
    }
}

fn detect_cpufreq(sysfs: &dyn ReadOnlyFileSystem) -> (CpuFreqFacts, Vec<CapabilityFinding>) {
    let policy_dir = list(sysfs, Some("devices/system/cpu/cpufreq"));
    let policy_ids = match &policy_dir {
        Probe::Present(entries) => sort_numeric_names(entries, "policy"),
        _ => Vec::new(),
    };
    let mut facts = CpuFreqFacts::default();
    let mut findings = Vec::new();

    let boost = read_text(sysfs, "devices/system/cpu/cpufreq/boost");
    let no_turbo = read_text(sysfs, "devices/system/cpu/cpufreq/no_turbo");
    let boost_probe = if matches!(boost, Probe::Present(_)) {
        &boost
    } else {
        &no_turbo
    };
    facts.boost = probe_value(boost.clone()).or_else(|| probe_value(no_turbo.clone()));
    add_finding(
        &mut findings,
        ids::CPU_BOOST,
        None,
        status_for_probes(&[
            (&boost, DiscoveryStatus::Supported),
            (&no_turbo, DiscoveryStatus::Supported),
        ]),
        FeatureClass::RuntimeMutable,
        vec![
            probe_evidence(boost_probe, EvidenceSource::Sysfs, "CPU boost interface"),
            probe_evidence(&no_turbo, EvidenceSource::Sysfs, "CPU no_turbo interface"),
        ],
        BTreeMap::new(),
    );

    let platform_profile = read_text(sysfs, "firmware/acpi/platform_profile");
    let platform_choices = read_text(sysfs, "firmware/acpi/platform_profile_choices");
    facts.platform_profile = probe_value(platform_profile.clone());
    facts.platform_profile_choices = match platform_choices.clone() {
        Probe::Present(value) => parse_tokens(&value),
        Probe::Missing | Probe::Denied | Probe::Malformed => Vec::new(),
    };
    add_finding(
        &mut findings,
        ids::PLATFORM_PROFILE,
        None,
        status_for_probes(&[
            (&platform_profile, DiscoveryStatus::Supported),
            (&platform_choices, DiscoveryStatus::Supported),
        ]),
        FeatureClass::Conditional,
        vec![
            probe_evidence(&platform_profile, EvidenceSource::Sysfs, "platform profile"),
            probe_evidence(
                &platform_choices,
                EvidenceSource::Sysfs,
                "platform profile choices",
            ),
        ],
        BTreeMap::new(),
    );

    let fallback_status = status(&policy_dir, DiscoveryStatus::Supported);
    if policy_ids.is_empty() {
        for id in [
            core_capability_ids::CPU_POLICY_FREQUENCY_MIN,
            core_capability_ids::CPU_POLICY_FREQUENCY_MAX,
            core_capability_ids::CPU_POLICY_GOVERNOR,
            core_capability_ids::CPU_POLICY_ENERGY_PREFERENCE,
        ] {
            add_finding(
                &mut findings,
                id,
                None,
                fallback_status,
                FeatureClass::RuntimeMutable,
                vec![probe_evidence(
                    &policy_dir,
                    EvidenceSource::Sysfs,
                    "CPUFreq policy directory",
                )],
                BTreeMap::new(),
            );
        }
        return (facts, findings);
    }

    for policy_id in policy_ids {
        let prefix = format!("devices/system/cpu/cpufreq/policy{policy_id}");
        let related = read_text(sysfs, &format!("{prefix}/related_cpus"));
        let driver = read_text(sysfs, &format!("{prefix}/scaling_driver"));
        let available_governors =
            read_text(sysfs, &format!("{prefix}/scaling_available_governors"));
        let current_governor = read_text(sysfs, &format!("{prefix}/scaling_governor"));
        let epp = read_text(sysfs, &format!("{prefix}/energy_performance_preference"));
        let epp_choices = read_text(
            sysfs,
            &format!("{prefix}/energy_performance_available_preferences"),
        );
        let min = parse_u64(read_text(sysfs, &format!("{prefix}/scaling_min_freq")));
        let max = parse_u64(read_text(sysfs, &format!("{prefix}/scaling_max_freq")));
        let current = parse_u64(read_text(sysfs, &format!("{prefix}/scaling_cur_freq")));

        let mut policy = CpuFreqPolicyFacts {
            id: policy_id,
            related_cpus: probe_value(related.clone()),
            driver: probe_value(driver.clone()),
            available_governors: probe_value(available_governors.clone())
                .map(|value| parse_tokens(&value))
                .unwrap_or_default(),
            current_governor: probe_value(current_governor.clone()),
            energy_performance_preference: probe_value(epp.clone()),
            energy_performance_choices: probe_value(epp_choices.clone())
                .map(|value| parse_tokens(&value))
                .unwrap_or_default(),
            min_khz: probe_value(min.clone()),
            max_khz: probe_value(max.clone()),
            current_khz: probe_value(current.clone()),
            read_failures: Vec::new(),
        };
        for (name, probe) in [
            ("related_cpus", &related),
            ("scaling_driver", &driver),
            ("scaling_available_governors", &available_governors),
            ("scaling_governor", &current_governor),
            ("energy_performance_preference", &epp),
            ("energy_performance_available_preferences", &epp_choices),
        ] {
            if !matches!(probe, Probe::Present(_)) {
                policy.read_failures.push(name.to_owned());
            }
        }
        for (name, probe) in [("scaling_min_freq", &min), ("scaling_max_freq", &max)] {
            if !matches!(probe, Probe::Present(_)) {
                policy.read_failures.push(name.to_owned());
            }
        }
        facts.policies.push(policy);

        let target = format!("cpu.policy.{policy_id}");
        let mut attributes = BTreeMap::new();
        if let Some(value) = facts.policies.last().and_then(|value| value.driver.clone()) {
            attributes.insert("driver".to_owned(), value);
        }
        if let Some(value) = facts
            .policies
            .last()
            .and_then(|value| value.related_cpus.clone())
        {
            attributes.insert("related_cpus".to_owned(), value);
        }
        let governor_status = status_for_probes(&[
            (&available_governors, DiscoveryStatus::Supported),
            (&current_governor, DiscoveryStatus::Supported),
        ]);
        add_finding(
            &mut findings,
            core_capability_ids::CPU_POLICY_GOVERNOR,
            Some(&target),
            governor_status,
            FeatureClass::RuntimeMutable,
            vec![
                probe_evidence(
                    &available_governors,
                    EvidenceSource::Sysfs,
                    "CPUFreq available governors",
                ),
                probe_evidence(
                    &current_governor,
                    EvidenceSource::Sysfs,
                    "CPUFreq current governor",
                ),
            ],
            attributes.clone(),
        );
        add_finding(
            &mut findings,
            core_capability_ids::CPU_POLICY_FREQUENCY_MIN,
            Some(&target),
            status(&min, DiscoveryStatus::Supported),
            FeatureClass::RuntimeMutable,
            vec![probe_evidence(
                &min,
                EvidenceSource::Sysfs,
                "CPUFreq minimum frequency",
            )],
            attributes.clone(),
        );
        add_finding(
            &mut findings,
            core_capability_ids::CPU_POLICY_FREQUENCY_MAX,
            Some(&target),
            status(&max, DiscoveryStatus::Supported),
            FeatureClass::RuntimeMutable,
            vec![probe_evidence(
                &max,
                EvidenceSource::Sysfs,
                "CPUFreq maximum frequency",
            )],
            attributes.clone(),
        );
        add_finding(
            &mut findings,
            core_capability_ids::CPU_POLICY_ENERGY_PREFERENCE,
            Some(&target),
            status(&epp, DiscoveryStatus::Supported),
            FeatureClass::RuntimeMutable,
            vec![
                probe_evidence(
                    &epp,
                    EvidenceSource::Sysfs,
                    "CPUFreq energy-performance preference",
                ),
                probe_evidence(
                    &epp_choices,
                    EvidenceSource::Sysfs,
                    "CPUFreq energy-performance choices",
                ),
            ],
            attributes,
        );
    }
    (facts, findings)
}

fn detect_topology(sysfs: &dyn ReadOnlyFileSystem) -> (CpuTopologyFacts, Vec<CapabilityFinding>) {
    let cpu_root = list(sysfs, Some("devices/system/cpu"));
    let cpu_ids = match &cpu_root {
        Probe::Present(entries) => sort_numeric_names(entries, "cpu"),
        _ => Vec::new(),
    };
    let possible = read_text(sysfs, "devices/system/cpu/possible");
    let online = read_text(sysfs, "devices/system/cpu/online");
    let online_text = probe_value(online.clone()).unwrap_or_default();
    let mut facts = CpuTopologyFacts {
        possible: probe_value(possible.clone()),
        online: probe_value(online.clone()),
        entries: Vec::new(),
        heterogeneous: false,
    };
    let mut capacities = Vec::new();
    for cpu in cpu_ids {
        let prefix = format!("devices/system/cpu/cpu{cpu}");
        let package = parse_u32(read_text(
            sysfs,
            &format!("{prefix}/topology/physical_package_id"),
        ));
        let core = parse_u32(read_text(sysfs, &format!("{prefix}/topology/core_id")));
        let siblings = read_text(sysfs, &format!("{prefix}/topology/thread_siblings_list"));
        let capacity = parse_u64(read_text(sysfs, &format!("{prefix}/cpu_capacity")));
        if let Probe::Present(value) = &capacity {
            capacities.push(*value);
        }
        facts.entries.push(CpuTopologyEntry {
            cpu,
            package_id: probe_value(package),
            core_id: probe_value(core),
            thread_siblings: probe_value(siblings),
            capacity: probe_value(capacity),
            online: range_contains(&online_text, cpu),
        });
    }
    capacities.sort_unstable();
    capacities.dedup();
    facts.heterogeneous = capacities.len() > 1;

    let topology_status = combine_statuses(&[
        status(&cpu_root, DiscoveryStatus::Supported),
        status(&possible, DiscoveryStatus::Supported),
        status(&online, DiscoveryStatus::Supported),
    ]);
    let mut topology_attributes = BTreeMap::new();
    topology_attributes.insert("cpu_count".to_owned(), facts.entries.len().to_string());
    topology_attributes.insert("heterogeneous".to_owned(), facts.heterogeneous.to_string());
    let topology_evidence = vec![
        probe_evidence(&cpu_root, EvidenceSource::Sysfs, "CPU topology directory"),
        probe_evidence(&possible, EvidenceSource::Sysfs, "possible CPU list"),
        probe_evidence(&online, EvidenceSource::Sysfs, "online CPU list"),
    ];
    let capacity_status = if capacities.is_empty() {
        combine_statuses(&[
            status(&cpu_root, DiscoveryStatus::PresentButUnsupported),
            status(&possible, DiscoveryStatus::PresentButUnsupported),
        ])
    } else {
        DiscoveryStatus::Supported
    };
    let capacity_evidence = if capacities.is_empty() {
        vec![evidence(
            EvidenceSource::Sysfs,
            "no per-CPU capacity hint was exposed",
        )]
    } else {
        vec![evidence(
            EvidenceSource::Sysfs,
            format!(
                "{} distinct CPU capacity values were observed",
                capacities.len()
            ),
        )]
    };
    (
        facts,
        vec![
            CapabilityFinding {
                id: CapabilityId::new(ids::CPU_TOPOLOGY).expect("static capability ID"),
                target: None,
                status: topology_status,
                classification: FeatureClass::BootOnlyReportOnly,
                evidence: topology_evidence,
                attributes: topology_attributes.clone(),
            },
            CapabilityFinding {
                id: CapabilityId::new(ids::CPU_CAPACITY).expect("static capability ID"),
                target: None,
                status: capacity_status,
                classification: FeatureClass::Conditional,
                evidence: capacity_evidence,
                attributes: topology_attributes,
            },
        ],
    )
}

fn range_contains(value: &str, needle: u32) -> bool {
    for part in value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        let Some((start, end)) = part.split_once('-') else {
            if part.parse::<u32>().ok() == Some(needle) {
                return true;
            }
            continue;
        };
        let (Some(start), Some(end)) = (start.parse::<u32>().ok(), end.parse::<u32>().ok()) else {
            continue;
        };
        if (start..=end).contains(&needle) {
            return true;
        }
    }
    false
}

fn detect_numa(sysfs: &dyn ReadOnlyFileSystem) -> (NumaFacts, Vec<CapabilityFinding>) {
    let node_root = list(sysfs, Some("devices/system/node"));
    let node_ids = match &node_root {
        Probe::Present(entries) => sort_numeric_names(entries, "node"),
        _ => Vec::new(),
    };
    let mut facts = NumaFacts::default();
    for node in node_ids {
        let prefix = format!("devices/system/node/node{node}");
        let cpulist = read_text(sysfs, &format!("{prefix}/cpulist"));
        let meminfo = read_text(sysfs, &format!("{prefix}/meminfo"));
        let memory_total_kb = probe_value(meminfo.clone())
            .and_then(|value| first_key(&value, "MemTotal"))
            .and_then(|value| value.split_whitespace().next().and_then(|v| v.parse().ok()));
        facts.nodes.push(NumaNodeFacts {
            id: node,
            cpus: probe_value(cpulist),
            memory_total_kb,
        });
    }
    facts.nodes.sort_by_key(|node| node.id);
    let status = status(&node_root, DiscoveryStatus::Supported);
    let mut attributes = BTreeMap::new();
    attributes.insert("node_count".to_owned(), facts.nodes.len().to_string());
    (
        facts,
        vec![CapabilityFinding {
            id: CapabilityId::new(ids::NUMA_TOPOLOGY).expect("static capability ID"),
            target: None,
            status,
            classification: FeatureClass::BootOnlyReportOnly,
            evidence: vec![probe_evidence(
                &node_root,
                EvidenceSource::Sysfs,
                "NUMA node directory",
            )],
            attributes,
        }],
    )
}

fn detect_cgroup(
    cgroup: Option<&dyn ReadOnlyFileSystem>,
    procfs: &dyn ReadOnlyFileSystem,
) -> (CgroupFacts, Vec<CapabilityFinding>) {
    let membership = read_text(procfs, "self/cgroup");
    let mut facts = CgroupFacts {
        membership: probe_value(membership.clone()),
        ..CgroupFacts::default()
    };
    let Some(cgroup) = cgroup else {
        return (
            facts,
            cgroup_unavailable_findings(membership, "cgroup root was not configured"),
        );
    };

    let controllers = read_text(cgroup, "cgroup.controllers");
    let subtree = read_text(cgroup, "cgroup.subtree_control");
    let cgroup_type = read_text(cgroup, "cgroup.type");
    let v1_weight = read_text(cgroup, "cpu.shares");
    let v1_quota = read_text(cgroup, "cpu.cfs_quota_us");
    let v2_weight = read_text(cgroup, "cpu.weight");
    let v2_max = read_text(cgroup, "cpu.max");
    let v2_cpuset = read_text(cgroup, "cpuset.cpus");
    let v1_cpuset = read_text(cgroup, "cpuset.cpus");
    let uclamp_min = read_text(cgroup, "cpu.uclamp.min");
    let uclamp_max = read_text(cgroup, "cpu.uclamp.max");

    let is_v2 =
        matches!(controllers, Probe::Present(_)) || matches!(cgroup_type, Probe::Present(_));
    let is_v1 =
        !is_v2 && (matches!(v1_weight, Probe::Present(_)) || matches!(v1_quota, Probe::Present(_)));
    facts.version = if is_v2 {
        Some(CgroupVersion::V2)
    } else if is_v1 {
        Some(CgroupVersion::V1)
    } else {
        None
    };
    facts.controllers = probe_value(controllers.clone())
        .map(|value| parse_tokens(&value))
        .unwrap_or_default();
    facts.enabled_controllers = probe_value(subtree.clone())
        .map(|value| parse_tokens(&value))
        .unwrap_or_default();
    facts.cpu_weight = if is_v2 {
        probe_value(v2_weight.clone())
    } else {
        probe_value(v1_weight.clone())
    };
    facts.cpu_max = if is_v2 {
        probe_value(v2_max.clone())
    } else {
        probe_value(v1_quota.clone())
    };
    facts.cpuset_cpus = if is_v2 {
        probe_value(v2_cpuset.clone())
    } else {
        probe_value(v1_cpuset.clone())
    };
    facts.uclamp_min = probe_value(uclamp_min.clone());
    facts.uclamp_max = probe_value(uclamp_max.clone());

    let hierarchy_status = if is_v2 {
        DiscoveryStatus::Supported
    } else if is_v1 {
        DiscoveryStatus::PresentButUnsupported
    } else {
        status(&controllers, DiscoveryStatus::Supported)
    };
    let mut findings = vec![CapabilityFinding {
        id: CapabilityId::new(ids::CGROUP_V2).expect("static capability ID"),
        target: None,
        status: hierarchy_status,
        classification: FeatureClass::Conditional,
        evidence: vec![
            probe_evidence(
                &controllers,
                EvidenceSource::CgroupV2,
                "cgroup v2 controller list",
            ),
            probe_evidence(
                &cgroup_type,
                EvidenceSource::CgroupV2,
                "cgroup hierarchy type",
            ),
            probe_evidence(&v1_weight, EvidenceSource::CgroupV1, "cgroup v1 CPU shares"),
        ],
        attributes: BTreeMap::new(),
    }];

    let cpu_controller = facts.controllers.iter().any(|value| value == "cpu") || is_v1;
    let weight_probe = if is_v2 { &v2_weight } else { &v1_weight };
    let max_probe = if is_v2 { &v2_max } else { &v1_quota };
    let cpuset_probe = if is_v2 { &v2_cpuset } else { &v1_cpuset };
    let controller_status = |probe: &Probe<String>| {
        if !cpu_controller {
            if is_v2 {
                DiscoveryStatus::PresentButUnsupported
            } else {
                status(probe, DiscoveryStatus::Supported)
            }
        } else {
            status(probe, DiscoveryStatus::Supported)
        }
    };
    let cgroup_evidence = |probe: &Probe<String>, name: &str| {
        vec![probe_evidence(
            probe,
            if is_v2 {
                EvidenceSource::CgroupV2
            } else {
                EvidenceSource::CgroupV1
            },
            name,
        )]
    };
    findings.push(CapabilityFinding {
        id: CapabilityId::new(core_capability_ids::CGROUP_CPU_WEIGHT)
            .expect("static capability ID"),
        target: None,
        status: controller_status(weight_probe),
        classification: FeatureClass::RuntimeMutable,
        evidence: cgroup_evidence(weight_probe, "cgroup CPU weight"),
        attributes: BTreeMap::new(),
    });
    findings.push(CapabilityFinding {
        id: CapabilityId::new(core_capability_ids::CGROUP_CPU_MAX).expect("static capability ID"),
        target: None,
        status: controller_status(max_probe),
        classification: FeatureClass::RuntimeMutable,
        evidence: cgroup_evidence(max_probe, "cgroup CPU max"),
        attributes: BTreeMap::new(),
    });
    findings.push(CapabilityFinding {
        id: CapabilityId::new(core_capability_ids::CGROUP_CPUSET_CPUS)
            .expect("static capability ID"),
        target: None,
        status: if !cpu_controller && is_v2 {
            DiscoveryStatus::PresentButUnsupported
        } else {
            status(cpuset_probe, DiscoveryStatus::Supported)
        },
        classification: FeatureClass::Conditional,
        evidence: cgroup_evidence(cpuset_probe, "cgroup effective CPU set"),
        attributes: BTreeMap::new(),
    });
    findings.push(CapabilityFinding {
        id: CapabilityId::new(ids::CGROUP_UCLAMP).expect("static capability ID"),
        target: None,
        status: if !cpu_controller && is_v2 {
            DiscoveryStatus::PresentButUnsupported
        } else {
            status_for_probes(&[
                (&uclamp_min, DiscoveryStatus::Supported),
                (&uclamp_max, DiscoveryStatus::Supported),
            ])
        },
        classification: FeatureClass::Conditional,
        evidence: vec![
            probe_evidence(
                &uclamp_min,
                EvidenceSource::CgroupV2,
                "cgroup uclamp minimum",
            ),
            probe_evidence(
                &uclamp_max,
                EvidenceSource::CgroupV2,
                "cgroup uclamp maximum",
            ),
        ],
        attributes: BTreeMap::new(),
    });
    (facts, findings)
}

fn cgroup_unavailable_findings(membership: Probe<String>, detail: &str) -> Vec<CapabilityFinding> {
    let evidence = vec![
        evidence(EvidenceSource::CgroupV2, detail),
        probe_evidence(
            &membership,
            EvidenceSource::Procfs,
            "procfs cgroup membership",
        ),
    ];
    [
        ids::CGROUP_V2,
        ids::CGROUP_UCLAMP,
        core_capability_ids::CGROUP_CPU_WEIGHT,
        core_capability_ids::CGROUP_CPU_MAX,
        core_capability_ids::CGROUP_CPUSET_CPUS,
    ]
    .into_iter()
    .map(|id| CapabilityFinding {
        id: CapabilityId::new(id).expect("static capability ID"),
        target: None,
        status: DiscoveryStatus::Unavailable,
        classification: if id == core_capability_ids::CGROUP_CPUSET_CPUS
            || id == ids::CGROUP_V2
            || id == ids::CGROUP_UCLAMP
        {
            FeatureClass::Conditional
        } else {
            FeatureClass::RuntimeMutable
        },
        evidence: evidence.clone(),
        attributes: BTreeMap::new(),
    })
    .collect()
}

fn detect_gpus(sysfs: &dyn ReadOnlyFileSystem) -> (GpuFacts, Vec<CapabilityFinding>) {
    let drm = list(sysfs, Some("class/drm"));
    let mut entries = match &drm {
        Probe::Present(entries) => entries
            .iter()
            .filter(|entry| entry.name.starts_with("card"))
            .cloned()
            .collect::<Vec<_>>(),
        _ => Vec::new(),
    };
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    let mut facts = GpuFacts::default();
    let mut findings = Vec::new();
    for entry in entries {
        let prefix = format!("class/drm/{}", entry.name);
        let uevent = read_text(sysfs, &format!("{prefix}/uevent"));
        let vendor = read_text(sysfs, &format!("{prefix}/device/vendor"));
        let device = read_text(sysfs, &format!("{prefix}/device/device"));
        let class = read_text(sysfs, &format!("{prefix}/device/class"));
        let driver = probe_value(uevent.clone()).and_then(|value| first_key(&value, "DRIVER"));
        facts.devices.push(GpuDeviceFacts {
            name: entry.name.clone(),
            vendor: probe_value(vendor.clone()),
            device: probe_value(device.clone()),
            class: probe_value(class.clone()),
            driver,
            entry_kind: entry.kind,
        });
        let target = format!("gpu.{}", entry.name);
        let device_status = if entry.kind == EntryKind::Symlink {
            DiscoveryStatus::PresentButUnsupported
        } else {
            status_for_probes(&[
                (&uevent, DiscoveryStatus::PresentButUnsupported),
                (&vendor, DiscoveryStatus::PresentButUnsupported),
            ])
        };
        let evidence = vec![
            evidence(
                EvidenceSource::Device,
                format!("DRM entry {} was enumerated", entry.name),
            ),
            probe_evidence(&uevent, EvidenceSource::Device, "DRM uevent"),
            probe_evidence(&vendor, EvidenceSource::Device, "GPU vendor identifier"),
        ];
        for id in [
            core_capability_ids::GPU_PERFORMANCE_PROFILE,
            core_capability_ids::GPU_POWER_LIMIT,
        ] {
            add_finding(
                &mut findings,
                id,
                Some(&target),
                device_status,
                FeatureClass::Experimental,
                evidence.clone(),
                BTreeMap::new(),
            );
        }
        add_finding(
            &mut findings,
            ids::GPU_DEVICE,
            Some(&target),
            device_status,
            FeatureClass::Experimental,
            evidence,
            BTreeMap::new(),
        );
    }
    if facts.devices.is_empty() {
        add_finding(
            &mut findings,
            ids::GPU_DEVICE,
            None,
            status(&drm, DiscoveryStatus::ReportOnly),
            FeatureClass::Experimental,
            vec![probe_evidence(
                &drm,
                EvidenceSource::Device,
                "DRM class directory",
            )],
            BTreeMap::new(),
        );
    }
    (facts, findings)
}

fn detect_irqs(procfs: &dyn ReadOnlyFileSystem) -> (IrqFacts, Vec<CapabilityFinding>) {
    let irq_root = list(procfs, Some("irq"));
    let irq_ids = match &irq_root {
        Probe::Present(entries) => sort_numeric_names(entries, ""),
        _ => Vec::new(),
    };
    let default_affinity = read_text(procfs, "irq/default_smp_affinity");
    let mut facts = IrqFacts {
        default_affinity: probe_value(default_affinity.clone()),
        entries: Vec::new(),
    };
    let mut findings = Vec::new();
    for irq in irq_ids {
        let affinity = read_text(procfs, &format!("irq/{irq}/smp_affinity_list"));
        let effective = read_text(procfs, &format!("irq/{irq}/effective_affinity_list"));
        facts.entries.push(IrqEntryFacts {
            irq,
            affinity: probe_value(affinity.clone()),
            effective_affinity: probe_value(effective.clone()),
        });
        let target = format!("irq.{irq}");
        add_finding(
            &mut findings,
            core_capability_ids::IRQ_AFFINITY,
            Some(&target),
            status_for_probes(&[
                (&affinity, DiscoveryStatus::PresentButUnsupported),
                (&effective, DiscoveryStatus::PresentButUnsupported),
            ]),
            FeatureClass::Experimental,
            vec![
                probe_evidence(&affinity, EvidenceSource::Procfs, "IRQ affinity list"),
                probe_evidence(
                    &effective,
                    EvidenceSource::Procfs,
                    "IRQ effective affinity list",
                ),
            ],
            BTreeMap::new(),
        );
    }
    if facts.entries.is_empty() {
        add_finding(
            &mut findings,
            ids::IRQ_METADATA,
            None,
            combine_statuses(&[
                status(&irq_root, DiscoveryStatus::ReportOnly),
                status(&default_affinity, DiscoveryStatus::ReportOnly),
            ]),
            FeatureClass::Experimental,
            vec![
                probe_evidence(&irq_root, EvidenceSource::Procfs, "IRQ directory"),
                probe_evidence(
                    &default_affinity,
                    EvidenceSource::Procfs,
                    "default IRQ affinity",
                ),
            ],
            BTreeMap::new(),
        );
    } else {
        add_finding(
            &mut findings,
            ids::IRQ_METADATA,
            None,
            DiscoveryStatus::ReportOnly,
            FeatureClass::Experimental,
            vec![evidence(
                EvidenceSource::Procfs,
                format!("{} IRQ entries were enumerated", facts.entries.len()),
            )],
            BTreeMap::new(),
        );
    }
    (facts, findings)
}

fn detect_memory(
    sysfs: &dyn ReadOnlyFileSystem,
    procfs: &dyn ReadOnlyFileSystem,
) -> (MemoryFacts, Vec<CapabilityFinding>) {
    let thp_enabled = read_text(sysfs, "kernel/mm/transparent_hugepage/enabled");
    let thp_defrag = read_text(sysfs, "kernel/mm/transparent_hugepage/defrag");
    let meminfo = read_text(procfs, "meminfo");
    let swaps = read_text(procfs, "swaps");
    let zram_root = list(sysfs, Some("class/block"));
    let zram_devices = match &zram_root {
        Probe::Present(entries) => entries
            .iter()
            .filter(|entry| entry.kind == EntryKind::Directory && entry.name.starts_with("zram"))
            .map(|entry| entry.name.clone())
            .collect::<Vec<_>>(),
        _ => Vec::new(),
    };
    let zswap_enabled = read_text(sysfs, "module/zswap/parameters/enabled");
    let zswap_compressor = read_text(sysfs, "module/zswap/parameters/compressor");
    let zswap_zpool = read_text(sysfs, "module/zswap/parameters/zpool");
    let meminfo_text = probe_value(meminfo.clone()).unwrap_or_default();
    let swap_total_kb = meminfo_value(&meminfo_text, "SwapTotal");
    let swap_free_kb = meminfo_value(&meminfo_text, "SwapFree");
    let swaps_text = probe_value(swaps.clone()).unwrap_or_default();
    let active_swap_entries = swaps_text
        .lines()
        .skip(1)
        .filter(|line| !line.trim().is_empty())
        .count();
    let facts = MemoryFacts {
        thp_enabled: probe_value(thp_enabled.clone()),
        thp_defrag: probe_value(thp_defrag.clone()),
        swap_total_kb,
        swap_free_kb,
        active_swap_entries,
        zram_devices,
        zswap_enabled: probe_value(zswap_enabled.clone()),
        zswap_compressor: probe_value(zswap_compressor.clone()),
        zswap_zpool: probe_value(zswap_zpool.clone()),
    };
    let mut findings = Vec::new();
    add_finding(
        &mut findings,
        ids::THP,
        None,
        status_for_probes(&[
            (&thp_enabled, DiscoveryStatus::ReportOnly),
            (&thp_defrag, DiscoveryStatus::ReportOnly),
        ]),
        FeatureClass::Conditional,
        vec![
            probe_evidence(&thp_enabled, EvidenceSource::Sysfs, "THP enabled mode"),
            probe_evidence(&thp_defrag, EvidenceSource::Sysfs, "THP defrag mode"),
        ],
        BTreeMap::new(),
    );
    add_finding(
        &mut findings,
        ids::SWAP,
        None,
        status(&meminfo, DiscoveryStatus::ReportOnly),
        FeatureClass::BootOnlyReportOnly,
        vec![
            probe_evidence(
                &meminfo,
                EvidenceSource::Procfs,
                "procfs memory information",
            ),
            probe_evidence(&swaps, EvidenceSource::Procfs, "procfs swap table"),
        ],
        BTreeMap::new(),
    );
    add_finding(
        &mut findings,
        ids::ZRAM,
        None,
        if facts.zram_devices.is_empty() {
            status(&zram_root, DiscoveryStatus::ReportOnly)
        } else {
            DiscoveryStatus::ReportOnly
        },
        FeatureClass::Conditional,
        vec![probe_evidence(
            &zram_root,
            EvidenceSource::Sysfs,
            "zram block devices",
        )],
        BTreeMap::new(),
    );
    add_finding(
        &mut findings,
        ids::ZSWAP,
        None,
        status_for_probes(&[
            (&zswap_enabled, DiscoveryStatus::ReportOnly),
            (&zswap_compressor, DiscoveryStatus::ReportOnly),
            (&zswap_zpool, DiscoveryStatus::ReportOnly),
        ]),
        FeatureClass::Conditional,
        vec![
            probe_evidence(&zswap_enabled, EvidenceSource::Sysfs, "zswap enabled"),
            probe_evidence(&zswap_compressor, EvidenceSource::Sysfs, "zswap compressor"),
            probe_evidence(&zswap_zpool, EvidenceSource::Sysfs, "zswap pool"),
        ],
        BTreeMap::new(),
    );
    (facts, findings)
}

fn meminfo_value(value: &str, key: &str) -> Option<u64> {
    first_key(value, key).and_then(|value| {
        value
            .split_whitespace()
            .next()
            .and_then(|number| number.parse::<u64>().ok())
    })
}

fn detect_scheduler(procfs: &dyn ReadOnlyFileSystem) -> (SchedulerFacts, Vec<CapabilityFinding>) {
    let probes = [
        (
            "sched_util_clamp_min",
            read_text(procfs, "sys/kernel/sched_util_clamp_min"),
        ),
        (
            "sched_util_clamp_max",
            read_text(procfs, "sys/kernel/sched_util_clamp_max"),
        ),
        (
            "numa_balancing",
            read_text(procfs, "sys/kernel/numa_balancing"),
        ),
        (
            "sched_energy_aware",
            read_text(procfs, "sys/kernel/sched_energy_aware"),
        ),
        ("cpu_pressure", read_text(procfs, "pressure/cpu")),
    ];
    let facilities = probes
        .iter()
        .filter(|(_, probe)| matches!(probe, Probe::Present(_)))
        .map(|(name, _)| (*name).to_owned())
        .collect::<Vec<_>>();
    let facts = SchedulerFacts {
        facilities,
        cpu_pressure: matches!(probes[4].1, Probe::Present(_)),
        uclamp_min: probe_value(probes[0].1.clone()),
        uclamp_max: probe_value(probes[1].1.clone()),
        numa_balancing: probe_value(probes[2].1.clone()),
        energy_aware: probe_value(probes[3].1.clone()),
    };
    let statuses = probes
        .iter()
        .map(|(_, probe)| (probe, DiscoveryStatus::ReportOnly))
        .collect::<Vec<_>>();
    let status = status_for_probes(&statuses);
    let evidence = probes
        .iter()
        .map(|(name, probe)| probe_evidence(probe, EvidenceSource::Procfs, name))
        .collect();
    (
        facts,
        vec![CapabilityFinding {
            id: CapabilityId::new(ids::SCHEDULER).expect("static capability ID"),
            target: None,
            status,
            classification: FeatureClass::Experimental,
            evidence,
            attributes: BTreeMap::new(),
        }],
    )
}

fn detect_systemd(
    procfs: &dyn ReadOnlyFileSystem,
    run: Option<&dyn ReadOnlyFileSystem>,
) -> (SystemdFacts, Vec<CapabilityFinding>) {
    let init = read_text(procfs, "1/comm");
    let systemd_dir = run
        .map(|filesystem| list(filesystem, Some("systemd/system")))
        .unwrap_or(Probe::Missing);
    let init_systemd = matches!(&init, Probe::Present(value) if value == "systemd");
    let dir_systemd = matches!(systemd_dir, Probe::Present(_));
    let mut evidence = Vec::new();
    if init_systemd {
        evidence.push("PID 1 is named systemd".to_owned());
    }
    if dir_systemd {
        evidence.push("/run/systemd/system is present".to_owned());
    }
    let facts = SystemdFacts {
        present: init_systemd || dir_systemd,
        evidence,
    };
    let status = if facts.present {
        DiscoveryStatus::ReportOnly
    } else if matches!(init, Probe::Denied) || matches!(systemd_dir, Probe::Denied) {
        DiscoveryStatus::PermissionDenied
    } else if matches!(init, Probe::Malformed) || matches!(systemd_dir, Probe::Malformed) {
        DiscoveryStatus::Indeterminate
    } else {
        DiscoveryStatus::Unavailable
    };
    (
        facts,
        vec![CapabilityFinding {
            id: CapabilityId::new(ids::SYSTEMD).expect("static capability ID"),
            target: None,
            status,
            classification: FeatureClass::BootOnlyReportOnly,
            evidence: vec![
                probe_evidence(&init, EvidenceSource::Procfs, "PID 1 command name"),
                probe_evidence(
                    &systemd_dir,
                    EvidenceSource::Synthetic,
                    "systemd runtime directory",
                ),
            ],
            attributes: BTreeMap::new(),
        }],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeSet;

    use crate::fs::FixtureFilesystem;
    use sysboost_core::{CapabilityState, ErrorCode};
    use sysboost_platform::{FileMetadata, FixedClock};

    struct FixtureSet {
        sysfs: FixtureFilesystem,
        procfs: FixtureFilesystem,
        cgroup: Option<FixtureFilesystem>,
        run: Option<FixtureFilesystem>,
    }

    impl FixtureSet {
        fn sources(&self) -> DiscoverySources<'_> {
            let mut sources = DiscoverySources::new(&self.sysfs, &self.procfs);
            if let Some(cgroup) = self.cgroup.as_ref() {
                sources = sources.with_cgroup(cgroup);
            }
            if let Some(run) = self.run.as_ref() {
                sources = sources.with_run(run);
            }
            sources
        }
    }

    fn seed(filesystem: &mut FixtureFilesystem, path: &str, value: &str) {
        filesystem.set_fixture_value(
            RelativePath::new(path.to_owned()).expect("fixture path is valid"),
            value.as_bytes().to_vec(),
            true,
        );
    }

    fn base_fixture(vendor: &str, model: &str, capacities: &[u64]) -> FixtureSet {
        let mut sysfs = FixtureFilesystem::new();
        let mut procfs = FixtureFilesystem::new();
        let mut cgroup = FixtureFilesystem::new();

        seed(
            &mut sysfs,
            "devices/system/cpu/cpufreq/policy0/scaling_driver",
            "schedutil\n",
        );
        seed(
            &mut sysfs,
            "devices/system/cpu/cpufreq/policy0/scaling_available_governors",
            "performance powersave schedutil\n",
        );
        seed(
            &mut sysfs,
            "devices/system/cpu/cpufreq/policy0/scaling_governor",
            "schedutil\n",
        );
        seed(
            &mut sysfs,
            "devices/system/cpu/cpufreq/policy0/energy_performance_preference",
            "balance_performance\n",
        );
        seed(
            &mut sysfs,
            "devices/system/cpu/cpufreq/policy0/energy_performance_available_preferences",
            "performance balance_performance balance_power power\n",
        );
        seed(
            &mut sysfs,
            "devices/system/cpu/cpufreq/policy0/scaling_min_freq",
            "800000\n",
        );
        seed(
            &mut sysfs,
            "devices/system/cpu/cpufreq/policy0/scaling_max_freq",
            "3600000\n",
        );
        seed(
            &mut sysfs,
            "devices/system/cpu/cpufreq/policy0/scaling_cur_freq",
            "1800000\n",
        );
        seed(
            &mut sysfs,
            "devices/system/cpu/cpufreq/policy0/related_cpus",
            "0-3\n",
        );
        seed(&mut sysfs, "devices/system/cpu/cpufreq/boost", "1\n");
        seed(&mut sysfs, "firmware/acpi/platform_profile", "balanced\n");
        seed(
            &mut sysfs,
            "firmware/acpi/platform_profile_choices",
            "performance balanced quiet\n",
        );
        seed(&mut sysfs, "devices/system/cpu/possible", "0-3\n");
        seed(&mut sysfs, "devices/system/cpu/online", "0-3\n");
        seed(&mut sysfs, "devices/system/node/node0/cpulist", "0-3\n");
        seed(
            &mut sysfs,
            "devices/system/node/node0/meminfo",
            "Node 0 MemTotal:       16384 kB\n",
        );
        seed(
            &mut sysfs,
            "kernel/mm/transparent_hugepage/enabled",
            "always [madvise] never\n",
        );
        seed(
            &mut sysfs,
            "kernel/mm/transparent_hugepage/defrag",
            "always defer [defer+madvise] never\n",
        );
        seed(&mut sysfs, "class/block/zram0/disksize", "1073741824\n");
        seed(&mut sysfs, "module/zswap/parameters/enabled", "Y\n");
        seed(&mut sysfs, "module/zswap/parameters/compressor", "zstd\n");
        seed(&mut sysfs, "module/zswap/parameters/zpool", "z3fold\n");

        for (cpu, capacity) in capacities.iter().enumerate() {
            let prefix = format!("devices/system/cpu/cpu{cpu}");
            seed(
                &mut sysfs,
                &format!("{prefix}/topology/physical_package_id"),
                "0\n",
            );
            seed(
                &mut sysfs,
                &format!("{prefix}/topology/core_id"),
                &(cpu / 2).to_string(),
            );
            seed(
                &mut sysfs,
                &format!("{prefix}/topology/thread_siblings_list"),
                &format!("{}\n", if cpu % 2 == 0 { cpu } else { cpu - 1 }),
            );
            seed(
                &mut sysfs,
                &format!("{prefix}/cpu_capacity"),
                &format!("{capacity}\n"),
            );
        }

        seed(
            &mut procfs,
            "sys/kernel/osrelease",
            "6.8.0-sysboost-fixture\n",
        );
        seed(
            &mut procfs,
            "sys/kernel/version",
            "#1 SMP PREEMPT_DYNAMIC\n",
        );
        let mut cpuinfo = String::new();
        for cpu in 0..capacities.len() {
            cpuinfo.push_str(&format!(
                "processor\t: {cpu}\nvendor_id\t: {vendor}\nmodel name\t: {model}\n\n"
            ));
        }
        seed(&mut procfs, "cpuinfo", &cpuinfo);
        seed(&mut procfs, "1/comm", "systemd\n");
        seed(&mut procfs, "1/cgroup", "0::/machine.slice\n");
        seed(&mut procfs, "self/cgroup", "0::/user.slice\n");
        seed(
            &mut procfs,
            "meminfo",
            "MemTotal:       16384 kB\nSwapTotal:       4096 kB\nSwapFree:        2048 kB\n",
        );
        seed(
            &mut procfs,
            "swaps",
            "Filename\t\t\tType\t\tSize\tUsed\tPriority\n/dev/zram0\tpartition\t4096\t0\t100\n",
        );
        seed(
            &mut procfs,
            "pressure/cpu",
            "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
        );
        for (name, value) in [
            ("sys/kernel/sched_util_clamp_min", "0\n"),
            ("sys/kernel/sched_util_clamp_max", "1024\n"),
            ("sys/kernel/numa_balancing", "1\n"),
            ("sys/kernel/sched_energy_aware", "1\n"),
            ("irq/default_smp_affinity", "ff\n"),
            ("irq/32/smp_affinity_list", "0-3\n"),
            ("irq/32/effective_affinity_list", "0-3\n"),
        ] {
            seed(&mut procfs, name, value);
        }

        for (name, value) in [
            ("cgroup.controllers", "cpuset cpu io memory\n"),
            ("cgroup.subtree_control", "cpu cpuset\n"),
            ("cgroup.type", "domain\n"),
            ("cpu.weight", "100\n"),
            ("cpu.max", "max 100000\n"),
            ("cpuset.cpus", "0-3\n"),
            ("cpu.uclamp.min", "0\n"),
            ("cpu.uclamp.max", "1024\n"),
        ] {
            seed(&mut cgroup, name, value);
        }

        FixtureSet {
            sysfs,
            procfs,
            cgroup: Some(cgroup),
            run: None,
        }
    }

    fn minimal_fixture() -> FixtureSet {
        let mut procfs = FixtureFilesystem::new();
        seed(&mut procfs, "sys/kernel/osrelease", "6.1.0-minimal\n");
        seed(&mut procfs, "1/cgroup", "0::/docker/fixture\n");
        seed(
            &mut procfs,
            "cpuinfo",
            "processor\t: 0\nmodel name\t: virtual cpu\n\n",
        );
        FixtureSet {
            sysfs: FixtureFilesystem::new(),
            procfs,
            cgroup: None,
            run: None,
        }
    }

    fn finding<'a>(report: &'a DiscoveryReport, id: &str) -> Vec<&'a CapabilityFinding> {
        report
            .findings
            .iter()
            .filter(|finding| finding.id.as_str() == id)
            .collect()
    }

    #[derive(Clone, Debug)]
    struct DeniedFixture {
        inner: FixtureFilesystem,
        denied: BTreeSet<RelativePath>,
    }

    impl ReadOnlyFileSystem for DeniedFixture {
        fn read(&self, path: &RelativePath) -> Result<Vec<u8>, SysboostError> {
            if self.denied.contains(path) {
                return Err(SysboostError::new(
                    ErrorCode::CapabilityError,
                    "fixture read denied",
                ));
            }
            self.inner.read(path)
        }

        fn metadata(&self, path: &RelativePath) -> Result<FileMetadata, SysboostError> {
            self.inner.metadata(path)
        }

        fn list(&self, path: Option<&RelativePath>) -> Result<Vec<DirectoryEntry>, SysboostError> {
            self.inner.list(path)
        }
    }

    #[test]
    fn intel_and_amd_like_hosts_use_interface_evidence() {
        for (vendor, model) in [
            ("GenuineIntel", "fixture Intel-like CPU"),
            ("AuthenticAMD", "fixture AMD-like CPU"),
        ] {
            let fixture = base_fixture(vendor, model, &[1024, 1024, 1024, 1024]);
            let report = CapabilityDiscovery::new(fixture.sources())
                .discover(&FixedClock::new(Timestamp::from_unix_millis(10)))
                .expect("fixture discovery succeeds");
            assert_eq!(report.environment.cpu_vendor.as_deref(), Some(vendor));
            assert!(report.environment.cpu_model.is_some());
            assert_eq!(report.cpufreq.policies.len(), 1);
            assert_eq!(
                report.cpufreq.policies[0].driver.as_deref(),
                Some("schedutil")
            );
            assert!(finding(&report, core_capability_ids::CPU_POLICY_GOVERNOR)
                .iter()
                .any(|finding| finding.status == DiscoveryStatus::Supported));
        }
    }

    #[test]
    fn hybrid_cpu_capacity_is_reported_without_model_heuristics() {
        let fixture = base_fixture("unknown", "hybrid fixture", &[1024, 512, 1024, 512]);
        let report = CapabilityDiscovery::new(fixture.sources())
            .discover(&FixedClock::new(Timestamp::from_unix_millis(11)))
            .expect("fixture discovery succeeds");
        assert!(report.topology.heterogeneous);
        assert!(finding(&report, ids::CPU_CAPACITY)
            .iter()
            .any(|finding| finding.status == DiscoveryStatus::Supported));
    }

    #[test]
    fn minimal_vm_or_container_is_nonfatal_and_explicitly_sparse() {
        let fixture = minimal_fixture();
        let report = CapabilityDiscovery::new(fixture.sources())
            .discover(&FixedClock::new(Timestamp::from_unix_millis(12)))
            .expect("minimal fixture discovery succeeds");
        assert_eq!(
            report.environment.kernel_release.as_deref(),
            Some("6.1.0-minimal")
        );
        assert!(report.environment.container_hint);
        assert!(finding(&report, core_capability_ids::CPU_POLICY_GOVERNOR)
            .iter()
            .any(|finding| finding.status == DiscoveryStatus::Unavailable));
        assert!(finding(&report, ids::CGROUP_V2)
            .iter()
            .any(|finding| finding.status == DiscoveryStatus::Unavailable));
    }

    #[test]
    fn missing_cpufreq_and_missing_cgroup_v2_are_distinct_unavailable_results() {
        let mut fixture = minimal_fixture();
        fixture.cgroup = Some(FixtureFilesystem::new());
        let report = CapabilityDiscovery::new(fixture.sources())
            .discover(&FixedClock::new(Timestamp::from_unix_millis(13)))
            .expect("partial fixture discovery succeeds");
        assert!(
            finding(&report, core_capability_ids::CPU_POLICY_FREQUENCY_MIN)
                .iter()
                .all(|finding| finding.status == DiscoveryStatus::Unavailable)
        );
        assert!(finding(&report, ids::CGROUP_V2)
            .iter()
            .all(|finding| finding.status == DiscoveryStatus::Unavailable));
        assert_eq!(report.cgroup.version, None);
    }

    #[test]
    fn multiple_gpus_are_enumerated_without_vendor_specific_selection() {
        let mut fixture = minimal_fixture();
        seed(
            &mut fixture.sysfs,
            "class/drm/card0/uevent",
            "DRIVER=amdgpu\nPCI_CLASS=030000\n",
        );
        seed(
            &mut fixture.sysfs,
            "class/drm/card0/device/vendor",
            "0x1002\n",
        );
        seed(
            &mut fixture.sysfs,
            "class/drm/card1/uevent",
            "DRIVER=i915\nPCI_CLASS=030000\n",
        );
        seed(
            &mut fixture.sysfs,
            "class/drm/card1/device/vendor",
            "0x8086\n",
        );
        let report = CapabilityDiscovery::new(fixture.sources())
            .discover(&FixedClock::new(Timestamp::from_unix_millis(14)))
            .expect("GPU fixture discovery succeeds");
        assert_eq!(report.gpu.devices.len(), 2);
        assert!(finding(&report, core_capability_ids::GPU_POWER_LIMIT)
            .iter()
            .all(|finding| finding.status == DiscoveryStatus::PresentButUnsupported));
    }

    #[test]
    fn partial_and_unreadable_interfaces_are_classified_without_aborting() {
        let fixture = base_fixture(
            "fixture",
            "denied interface host",
            &[1024, 1024, 1024, 1024],
        );
        let denied_paths = [
            "devices/system/cpu/cpufreq/policy0/scaling_available_governors",
            "devices/system/cpu/cpufreq/policy0/scaling_governor",
        ]
        .into_iter()
        .map(|value| RelativePath::new(value.to_owned()).expect("valid denied path"))
        .collect();
        let denied_sysfs = DeniedFixture {
            inner: fixture.sysfs,
            denied: denied_paths,
        };
        let sources = DiscoverySources::new(&denied_sysfs, &fixture.procfs)
            .with_cgroup(fixture.cgroup.as_ref().expect("base cgroup"));
        let report = CapabilityDiscovery::new(sources)
            .discover(&FixedClock::new(Timestamp::from_unix_millis(15)))
            .expect("unreadable optional interface is nonfatal");
        assert!(finding(&report, core_capability_ids::CPU_POLICY_GOVERNOR)
            .iter()
            .any(|finding| finding.status == DiscoveryStatus::PermissionDenied));
        assert!(report
            .findings
            .iter()
            .all(|finding| !finding.evidence.is_empty()));
        assert!(report
            .inventory
            .capabilities
            .iter()
            .all(|descriptor| descriptor.state != CapabilityState::Available));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn host_roots_produce_report_only_discovery_without_writes() {
        let roots = HostRoots::open().expect("Linux pseudo-filesystem roots are available");
        let report = CapabilityDiscovery::new(roots.sources())
            .discover(&FixedClock::new(Timestamp::from_unix_millis(16)))
            .expect("host discovery is read-only and optional-interface tolerant");
        assert_eq!(report.observed_at, Timestamp::from_unix_millis(16));
        assert!(report.environment.kernel_release.is_some());
        assert!(!report.findings.is_empty());
        assert!(report
            .inventory
            .capabilities
            .iter()
            .all(|descriptor| descriptor.state != CapabilityState::Available));
    }
}
