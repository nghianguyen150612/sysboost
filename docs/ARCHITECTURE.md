# sysboost architecture

Status: **frozen contract; safe Rust foundation, read-only discovery, transaction engine, transport-neutral privilege boundary, reviewed typed CPU/workload backends, and conservative topology-aware soft-isolation planning implemented; unsupported runtime families remain deferred**
Decision version: `0.1`
Audit baseline: repository commit `070ffef` (`Initial commit`)
Scope: runtime-only Linux performance changes with exact pre-boost restoration

This document is the contract for implementation work that follows. It is
deliberately more specific than a component overview: later implementation
work must preserve the identifiers, state transitions, trust boundaries, and
invariants below. A change to a frozen contract requires an ADR and an update
to the safety document.

## 1. Repository audit and current state

The initial repository contains only:

| Path | State | Architectural implication |
| --- | --- | --- |
| `README.md` | Title only before this freeze | No public behavior or compatibility contract existed. It now points to this design. |
| `LICENSE` | MIT, copyright 2026 Nguyen Nghia | Governs future source and documentation. |
| Rust workspace/source | Absent | No crate, API, runtime tuning, privileged helper, or migration exists. |
| Tests/CI/configuration | Absent | No existing checks or configuration format can be silently replaced. |

The target workspace below is therefore a greenfield architecture, not a
refactor of an existing implementation. The architecture-freeze change added
design documentation only; Prompt 2 subsequently created the safe Cargo
foundation. Neither change executes a privileged helper or touches host kernel
interfaces.

## 2. Goals and non-goals

### Goals

`sysboost` will:

1. Detect capabilities from the running kernel and exposed interfaces, not from
   distribution, vendor, or CPU/GPU model heuristics.
2. Produce a deterministic, inspectable plan from capability evidence and
   policy.
3. Snapshot every mutation's original state before the first write.
4. Persist durable intent before applying any mutation.
5. Verify every apply and every restore by reading the target back.
6. Restore the exact pre-boost state, or report a conflict/degraded state
   rather than claiming success.
7. Keep privileged mutation behind a narrow, typed boundary.
8. Run the same domain and backend contract tests against fake sysfs, procfs,
   and cgroup environments.

### Non-goals for this architecture freeze

There is no GPU, IRQ, sysctl, bootloader, or firmware implementation in the
current foundation. Prompt 7 adds the reviewed typed CPU power-policy backend
and Prompt 8 adds the reviewed typed scheduler/cgroup-v2 workload backend.
Boot-time configuration is outside the runtime transaction. No shell-command-
based privilege mechanism is permitted.

## 3. Target workspace and dependency direction

The implementation target is a Cargo workspace with these crates:

```text
crates/
  sysboost-core        pure domain model, planner, transaction contracts
  sysboost-platform    I/O, journal, clock, privilege, and backend ports
  sysboost-config      typed configuration and safe hierarchy merging
  sysboost-linux       Linux adapters: sysfs, procfs, cgroups, and backends
  sysboost-protocol    typed controller <-> privileged-service protocol
  sysboost-testkit     fake ports, virtual filesystems, and fault injection
  sysboost-controller  unprivileged CLI/controller binary
  sysboost-privd       narrow root-owned mutation service binary
```

The intended dependency graph is:

```text
                 +------------------+
                 | sysboost-config  |
                 +---------+--------+
                           |
                           v
+----------------+   +-----+----------+   +------------------+
| sysboost-linux +-->| sysboost-core  |<--+ sysboost-platform |
+--------+-------+   +-----+----------+   +------------------+
         |                   ^                    ^
         |                   |                    |
         v                   |                    |
+--------+-------+           |            +-------+--------+
| sysboost-protocol|----------+            | sysboost-testkit|
+--------+-------+                        +----------------+
         ^
         |
  +------+------+       +-----------+
  | controller  |       |   privd   |
  +-------------+       +-----------+
```

More precisely:

- `sysboost-core` depends only on the Rust standard library and, once the
  implementation begins, narrowly reviewed serialization/error crates if
  needed. It may not import Linux names, paths, `std::process::Command`, or
  filesystem APIs for host access.
- `sysboost-platform` defines ports consumed by the core engine and adapters.
  It contains no Linux path knowledge.
- `sysboost-config` parses configuration and produces a core policy. It cannot
  grant capabilities or privileges.
- `sysboost-linux` is the only production crate that knows sysfs/procfs/cgroup
  layout. It implements typed core/platform ports.
- `sysboost-protocol` contains versioned, length-bounded, typed wire messages.
  It does not expose a raw path/write/value escape hatch.
- `sysboost-controller` and `sysboost-privd` are composition roots. Linux
  dependencies are wired there, not leaked into domain logic.
- `sysboost-testkit` is never linked into production binaries. It implements
  the same ports with virtual roots and deterministic failures.

There is no dynamic plugin loading in the initial production design. Backend
registration is compiled in and reviewed. A future plugin mechanism would
require a separate security ADR, signature/allowlist design, and protocol
versioning work.

## 4. Process architecture and trust boundary

The production deployment has two processes:

```text
user / operator
      |
      v
sysboost-controller (normally unprivileged)
  detect -> plan -> request session -> observe status
      |
      | authenticated typed local-IPC adapter (composition-root responsibility)
      v
sysboost-privd (small root-owned service)
  re-detect -> validate -> snapshot -> durable intent
  apply -> verify -> restore -> recovery
      |
      v
kernel interfaces: sysfs, procfs, cgroup filesystem, selected device nodes
```

The controller is untrusted input from the helper's perspective. It may ask
for a policy and a typed plan, but it cannot select an arbitrary path, write an
arbitrary string, or supply a false preimage. The helper:

- authenticates the peer with Unix peer credentials and an allowlisted group;
- validates protocol version, message size, session ownership, plan digest,
  capability IDs, target identities, value bounds, and policy restrictions;
- re-detects capabilities and re-reads target state immediately before
  snapshot/application, closing the controller-to-helper TOCTOU window;
- creates the snapshot and durable intent itself;
- invokes only compiled-in backend operations;
- owns the session journal and crash recovery; and
- never invokes a shell, shell script, external tuning command, or arbitrary
  executable for a privileged action.

Running the controller as root does not create a direct arbitrary-write mode.
The same typed service boundary is used. A report-only mode may run without
`sysboost-privd`; mutation is unavailable in that mode.

Prompt 6 implementation note: `sysboost-platform::PrivilegeService` is the
transport-neutral helper admission and lifecycle core. It accepts a typed
request frame only together with peer identity supplied by its composition
root; it does not derive identity from request bytes, open a socket, or expose
an arbitrary filesystem-write primitive. A production Unix-domain adapter
remains responsible for validating the endpoint's ownership and mode and for
obtaining authenticated kernel peer credentials (for example, `SO_PEERCRED`)
before constructing the strong PID/start/boot identity passed to the service.
The reviewed CPU and workload backends supply the mutation implementations, but
`sysboost-privd` remains report-only until a production Unix-domain adapter and
composition-root registration bind the backends to `PrivilegeService`. The
backends are exercised through that service and the transaction engine in the
contract tests; no controller-side CPU, scheduler, or cgroup write path exists.

## 5. Capability model

Capability detection is evidence-based. A model name, distribution name, or
vendor string may be logged as context but can never be the reason an
operation is selected.

### 5.1 Stable capability identity

`CapabilityId` is a stable semantic identifier, not a path. The initial
namespace is:

```text
cpu.policy.frequency.min
cpu.policy.frequency.max
cpu.policy.governor
cpu.policy.energy_preference
cgroup.cpu.weight
cgroup.cpu.max
cgroup.cpuset.cpus
cgroup.io.weight
cgroup.uclamp
cgroup.workload
cgroup.background
scheduler.process.placement
scheduler.nice
scheduler.ioprio
gpu.performance.profile
gpu.power.limit
irq.affinity
kernel.sysctl.runtime
```

Only capabilities with an implemented backend, exact restoration semantics,
and explicit policy admission can mutate. The list is a vocabulary, not a
promise that every capability is implemented or available on every host.

### 5.2 Capability descriptor

The frozen logical shape is:

```text
CapabilityDescriptor {
    id: CapabilityId,
    backend: BackendId,
    target_kind: TargetKind,
    state: CapabilityState,
    operations: [OperationDescriptor],
    privilege: PrivilegeRequirement,
    equality: EqualityKind,
    risk: RiskClass,
    classification: FeatureClass,
    evidence: [CapabilityEvidence],
}
```

`CapabilityState` is one of `Available`, `ReadOnly`, `Unsupported`,
`Indeterminate`, or `Denied`. `Denied` is distinct from `Unsupported`; a
permission problem must not be silently treated as a missing kernel feature.

Evidence includes the interface family, kernel-exposed feature evidence,
target identity, readable/writable status, parser result, and backend version.
It must not contain an assumption such as “this CPU model supports X”. A
capability may be `Available` only when the backend can read the current value,
encode the requested typed value, capture a restorable preimage, and verify a
readback.

`FeatureClass` is a closed policy vocabulary: `RuntimeMutable`, `Conditional`,
`Experimental`, or `BootOnlyReportOnly`. Availability is still evaluated per
host; the class does not override capability evidence or policy.

The controller's inventory is advisory. `sysboost-privd` creates a fresh,
trusted inventory and binds it to the session's plan digest before mutation.

Prompt 3 adds `sysboost-linux::CapabilityDiscovery` as a read-only projection
over these contracts. It produces a deterministic `DiscoveryReport` containing
kernel/runtime facts, typed CPUFreq policy observations, topology/capacity,
NUMA, cgroup, GPU, IRQ, memory, scheduler, and service-presence facts. Its
capability matrix distinguishes supported observations, unavailable
interfaces, permission-denied reads, present-but-unsupported interfaces,
report-only facts, and indeterminate evidence. The discovery operation itself
remains strictly read-only. CPU and workload capability descriptors may project
as `Available` only for the reviewed `linux.cpu` or `linux.workload` backends,
and only when the detected interface has a typed current value and a proven
target identity. Other detected interfaces remain `ReadOnly` or unsupported
until a reviewed backend supplies preimage, apply, readback, and restore
admission.

### 5.3 Feature classification freeze

Classification describes product maturity and allowed intent, not merely
whether a Linux file happens to be writable.

| Feature family | Classification | Admission rule |
| --- | --- | --- |
| CPUFreq policy governor | Runtime mutable | First-class only for a detected, readable/writable policy with reversible readback. |
| CPUFreq policy min/max frequency | Runtime mutable | One policy target; validate min/max ordering and snapshot both if the backend treats them as a compound unit. |
| CPU energy-performance preference | Runtime mutable | Only with a backend-declared exact equality rule and bounded enum/value. |
| CPU boost/turbo (`boost` or `no_turbo`) | Runtime mutable | One detected host-wide interface, normalized to a typed enabled/disabled state and pinned to its target identity. |
| ACPI platform profile | Conditional | Only for a kernel-advertised profile choice with exact typed restore and stable node identity. |
| Cgroup CPU weight/quota | Runtime mutable | Runtime mutable only when the cgroup controller is detected, writable, and exactly restorable. |
| Cgroup cpuset | Conditional | Requires a valid effective CPU set, parent constraints, and an exact set snapshot. No implicit cgroup creation. |
| Cgroup IO weight | Conditional | Requires the v2 `io` controller, explicit opt-in, and exact typed readback/restore. |
| Cgroup uclamp min/max | Conditional | Requires the v2 `cpu` controller and separate typed min/max operations with exact readback/restore. |
| Workload/conservative-background cgroups | Conditional | Only explicit, bounded names under an approved parent may be created and cleaned up; no arbitrary hierarchy management. |
| Explicit process placement | Conditional | Requires a validated PID plus start-time identity and an explicitly selected destination cgroup. |
| Process nice | Runtime mutable | Bounded `-20..19` nice values for explicitly identified processes; every change is transactional and restorable. |
| Conservative process I/O priority | Experimental | Only typed `none`, `best-effort`, and `idle` classes with bounded levels; real-time I/O priority is excluded. |
| Runtime kernel sysctl family | Conditional | Explicit allowlist only; each key is its own reviewed capability. No generic `/proc/sys` writer. |
| CPU online/offline | Experimental | High blast radius; disabled by default, separate explicit policy, and never part of a normal boost plan. |
| GPU performance profile/power limit | Experimental | Backend/device-specific; no fallback to vendor tools or shell commands. Disabled unless a reviewed backend and exact restore contract exist. |
| IRQ affinity | Experimental | Requires complete IRQ/cpu-set snapshot and ownership/conflict handling; disabled by default. |
| Scheduler policy/priority changes | Experimental | Prompt 8 implements only the explicit nice/ioprio/placement forms above; it never requests `SCHED_FIFO` or `SCHED_RR` and never classifies processes by name. |
| Kernel command line, bootloader, initramfs, module parameters requiring reboot | Boot-only/report-only | The runtime utility reports these as possible configuration opportunities; it never edits them. |
| Firmware, BIOS/UEFI, microcode selection, kernel build options | Boot-only/report-only | Report only. They are outside the runtime transaction and restoration scope. |

Unimplemented or experimental features must not be enabled merely because a
matching file exists. Every feature starts as report-only until its backend,
tests, and safety review are complete. The reviewed CPU backend owns only the
closed operations `cpu.frequency`, `cpu.governor`, `cpu.energy_preference`,
`cpu.boost`, and `platform.profile`; the reviewed workload backend owns only
the closed cgroup-v2 and explicit-process operations listed above. Neither
backend exposes a generic sysfs, procfs, or cgroupfs writer.

## 6. Typed mutation model

### 6.1 What constitutes a mutation

A `MutationUnit` is the smallest backend-defined operation that:

1. has one stable `MutationId`, capability, and target identity;
2. has one typed desired value and bounded encoding;
3. has a complete preimage sufficient for the backend's declared equality;
4. has a declared postcondition and readback verifier; and
5. has a restore operation that consumes the captured preimage.

One pseudo-file write is a mutation only if the backend models its complete
semantic effect. A multi-node change is a compound mutation only when the
backend captures every affected node and provides deterministic apply,
verify, and restore behavior. Hidden side effects are not acceptable. A plan
is a list of mutation units, not a privileged list of paths.

### 6.2 Frozen typed operations

The initial operation vocabulary is an enum-like closed set. It may grow only
by adding a reviewed variant:

```text
MutationKind::CpuFrequency {
    policy: CpuPolicyId,
    min_khz: Option<FrequencyKHz>,
    max_khz: Option<FrequencyKHz>,
}
MutationKind::CpuGovernor { policy: CpuPolicyId, governor: GovernorId }
MutationKind::CpuEnergyPreference { policy: CpuPolicyId, value: EnergyPreference }
MutationKind::CgroupCpuWeight { cgroup: CgroupId, weight: CpuWeight }
MutationKind::CgroupCpuMax { cgroup: CgroupId, quota: CpuQuota, period: CpuPeriod }
MutationKind::CgroupCpuset { cgroup: CgroupId, cpus: CpuSet }
MutationKind::CgroupIoWeight { cgroup: CgroupId, weight: IoWeight }
MutationKind::CgroupUclampMin { cgroup: CgroupId, value: UclampValue }
MutationKind::CgroupUclampMax { cgroup: CgroupId, value: UclampValue }
MutationKind::CgroupWorkload { parent: CgroupId, name: CgroupName }
MutationKind::CgroupBackground { parent: CgroupId, name: CgroupName }
MutationKind::ProcessPlacement { process: ProcessId, cgroup: CgroupId }
MutationKind::ProcessNice { process: ProcessId, nice: NiceValue }
MutationKind::ProcessIoPriority { process: ProcessId, priority: IoPriority }
MutationKind::GpuPerformanceProfile { device: GpuId, profile: GpuProfile }
MutationKind::GpuPowerLimit { device: GpuId, milliwatts: PowerMilliwatts }
MutationKind::IrqAffinity { irq: IrqId, cpus: CpuSet }
MutationKind::RuntimeSysctl { key: ApprovedSysctlKey, value: ApprovedSysctlValue }
```

The last three families are experimental even though their type names are
reserved here. An implementation must not add a generic `WritePath { path,
value }`, `Command { argv }`, or equivalent variant.

The frozen logical plan record is:

```text
PlannedMutation {
    mutation_id: MutationId,
    capability: CapabilityId,
    target: TargetId,
    kind: MutationKind,
    desired: TypedValue,
    precondition: StateFingerprint,
    equality: EqualityKind,
    dependencies: [MutationId],
    rollback: RollbackContract,
}
```

The actual serialized representation may use Rust enums and newtypes, but the
wire and journal must preserve these meanings. `TargetId` is opaque outside
the backend and does not contain an operator-selected host path. The helper
resolves it to an allowlisted internal node only after revalidation.

### 6.3 Snapshot and receipts

Every mutation has a `Snapshot` before apply:

```text
Snapshot {
    mutation_id: MutationId,
    target: TargetId,
    original_raw: BoundedBytes,
    original_typed: TypedValue,
    original_fingerprint: StateFingerprint,
    equality: EqualityKind,
    target_identity: TargetIdentity,
    captured_at: Timestamp,
}
```

The raw representation is retained when the interface supports byte-exact
restoration. The typed value is retained for semantic verification and for
interfaces that canonicalize their output. A backend must declare whether
restoration is `ByteExact`, `ScalarExact`, `SetExact`, or another reviewed
equality. It may not claim exact restoration when the interface cannot
represent the preimage.

An apply returns an `ApplyReceipt` containing the observed precondition,
write result, post-write fingerprint, and backend-owned ownership marker.
Verification is a separate readback operation; a successful write syscall is
never a successful mutation by itself.

## 7. Detection and planning

The pure pipeline is:

```text
detect -> plan -> snapshot -> durable intent -> apply -> verify -> restore
```

The first two stages are advisory and can run in the controller. The trusted
service repeats detection and validates the plan immediately before the
snapshot stage. No mutation may occur during detection or planning.

### 7.1 Detection

Detection enumerates only interfaces and targets exposed by the host. It
records positive evidence and explicit negative/unknown states. It must not
probe by writing. A probe may read metadata, parse a value, and test access
using normal permission checks, but a write test is not allowed because it
would itself be a mutation.

### 7.2 Planning

Planning is deterministic and side-effect free:

- input is effective policy plus capability inventory;
- unsupported, denied, ambiguous, or non-reversible requests fail closed or
  become a reported skip according to the policy's `required` flag;
- desired values are validated against backend-declared bounds;
- operations are deduplicated by target and operation identity;
- dependencies are topologically sorted and cycles are rejected;
- the plan contains no raw paths, shell commands, or privilege escalation
  requests; and
- the plan records a digest of policy, capability evidence, operation list,
  and backend versions.

If a requested operation is `required = true` and cannot meet the exact
snapshot/verify/restore contract, the entire plan is rejected. Optional
operations may be skipped with a structured reason. “Best effort” never means
applying an operation without a restorable preimage.

## 8. Session, transaction, and durable state

### 8.1 Session ownership

A session has a random, non-reused `SessionId`, one authenticated controller
owner, one plan digest, one effective policy digest, and a set of leased
targets. By default, overlapping sessions are rejected. Stacking snapshots on
the same target is intentionally not supported in the first implementation;
it makes the definition of the original state ambiguous.

The helper owns the authoritative session state. The controller receives a
handle and status, not authority to edit the journal or supply restore data.

Runtime state is held below the configured runtime root only after ownership,
exact mode, regular-file type, link count, and no-symlink checks pass. The
production root is `/run/sysboost`, owned by the expected privileged UID/GID
with mode `0700`; state and lock files are expected to be regular, single-link
files with mode `0600`. Lock ownership is bound to PID, process start
identity, and boot identity, so a reused PID cannot authorize stale ownership.

### 8.2 State machine

The legal states are:

```text
New
  -> Detected
  -> Planned
  -> Snapshotted
  -> IntentDurable
  -> Applying
  -> Active                  (all apply operations verified)
  -> Restoring
  -> Restored                (all original states verified)

Any state after IntentDurable may enter:
  RollingBack -> Restored
  RollingBack -> Degraded

Degraded -> RecoveryPending -> Restoring/Degraded
```

`Active` means the boost is currently held, not that the process may exit
without restoration. `Restored` is a positive verification result. `Degraded`
means at least one target could not be proven restored; it is never mapped to a
successful exit status.

### 8.3 Durable intent

The helper persists a root-owned, mode-`0700` session directory, for example
under `/var/lib/sysboost/sessions/<session-id>/`. The exact on-disk format is
an implementation detail, but its logical records are frozen:

1. session header and policy/plan/backend digests;
2. target leases and capability evidence;
3. one complete preimage for every mutation;
4. an intent record listing the exact ordered mutations; and
5. checksummed state-transition records.

The journal is flushed and made durable before the first apply. A temporary
record must be written, flushed, atomically renamed, and followed by a
directory flush where the filesystem permits. An implementation must not
report `IntentDurable` until this succeeds. If any preimage cannot be
persisted, no mutation is applied.

After each mutation apply/verify and each restore/verify, the helper appends a
transition record and flushes it. Records are bounded, authenticated by a
checksum for corruption detection, and include monotonic sequence numbers to
make replay unambiguous. The journal is not a general configuration store and
does not accept controller edits.

### 8.4 Crash recovery and lease loss

The helper scans unfinished journals at startup. It reconciles each target by
reading it through the same backend, then restores using the rules below. A
controller heartbeat is a liveness signal only; loss of the heartbeat starts a
bounded grace period, after which the helper rolls back. A helper crash can
leave a temporary boost in place until the service restarts; recovery must
then run before accepting a new mutation session. This limitation is reported
and is why the journal is durable.

## 9. Apply, verification, and rollback semantics

### 9.1 Apply admission gates

For every mutation, the helper must confirm all of the following in order:

1. the session owns the target lease;
2. the operation and target are in the compiled backend registry;
3. the fresh capability state is available and writable;
4. the policy permits the risk/classification;
5. the typed value is valid and within bounds;
6. the current state matches the planned precondition;
7. the complete snapshot is durable; and
8. the journal is in `IntentDurable`.

Any failed gate stops before the write. A changed precondition triggers a
re-plan or a fail-closed abort; it does not overwrite a newly changed state.

### 9.2 Apply order and failure

The plan's dependency order is the apply order. After each apply, the backend
must read back and verify the declared postcondition. On the first apply or
verification failure, no later operation is attempted and already-touched
mutations are restored in reverse successful-apply order.

### 9.3 Normal restore

Restore is idempotent and runs in reverse dependency order. Normal automatic
restore is compare-and-restore:

- if the current state equals the last state proven to be written by this
  session, the helper writes the snapshot's original value;
- it then reads back and verifies the original using the capability's exact
  equality rule;
- if the current state differs from the session-owned state, the helper does
  not silently clobber an external writer's change; it records a
  `RestoreConflict`, continues independent restores, and ends `Degraded`; and
- a missing target, revoked permission, or failed readback is also `Degraded`.

Therefore a session is reported `Restored` only when every preimage is proven
restored. The product makes no false “best effort complete” claim. An
explicit, separately authorized recovery command may request
`ForceOriginal` for a named session and target; that is a repair action,
requires an audit record, and is never automatic or exposed as an arbitrary
write API.

This rule protects concurrent kernel managers and operators. It also makes
the precise limitation explicit: exact restoration is guaranteed when the
target is stable and no external writer changes it; otherwise sysboost
preserves the external change and reports that the pre-boost state could not
be proven restored.

### 9.4 Rollback status

The only successful terminal state is `Restored`. If one mutation restores and
another conflicts, the helper records both results but returns a failure/degraded
status. Recovery can be retried after the external conflict is resolved. A
new boost is blocked while an unfinished session owns the affected target.

## 10. Filesystem, sysfs, procfs, and cgroup abstractions

Linux-specific path handling belongs exclusively in `sysboost-linux`.

### 10.1 Read and write ports

The platform boundary exposes semantic operations such as:

```text
CapabilityProbe::read(node: ApprovedNode) -> RawObservation
TypedBackend::snapshot(operation: PlannedMutation) -> Snapshot
TypedBackend::apply(operation: PlannedMutation, snapshot: Snapshot)
TypedBackend::verify(operation, expected: ExpectedState)
TypedBackend::restore(operation, snapshot: Snapshot)
```

`ApprovedNode` is an internal enum owned by a backend, not a caller-provided
path. There is no public `write(path, bytes)`, `write_sysfs(path, value)`,
`write_procfs(path, value)`, or `run(command)` port. The Linux adapter maps an
approved node to a fixed, root-bound path only after target enumeration and
identity checks.

The internal adapter may use directory-file-descriptor-relative access,
`O_NOFOLLOW`, and Linux path resolution constraints such as “beneath this
approved mount”. It must reject symlink escapes, unexpected file types,
oversized values, and path components supplied by the controller. Sysfs and
procfs writes are followed by a readback; rename-based atomic replacement is
not assumed because these are virtual kernel files.

The fake implementation uses the same approved-node enum and a temporary
fixture root. A test can therefore exercise path resolution and parsing
without touching the host's `/sys` or `/proc`.

Read-only discovery additionally uses a typed directory-enumeration operation
that returns bounded entry names and non-followed entry kinds. It is not a
generic path writer, does not follow symlinks, and is implemented by both the
real rooted adapter and in-memory fixtures. Missing or disappearing entries
are converted into capability evidence rather than treated as fatal for
optional interfaces.

### 10.2 Cgroup abstraction

The cgroup port is semantic and typed:

```text
CgroupProvider::discover() -> CgroupInventory
CgroupProvider::read_cpu_weight(CgroupId)
CgroupProvider::apply_cpu_weight(CgroupId, CpuWeight)
CgroupProvider::read_cpu_max(CgroupId)
CgroupProvider::apply_cpu_max(CgroupId, CpuQuota, CpuPeriod)
CgroupProvider::read_cpuset(CgroupId)
CgroupProvider::apply_cpuset(CgroupId, CpuSet)
CgroupProvider::read_io_weight(CgroupId)
CgroupProvider::apply_io_weight(CgroupId, IoWeight)
CgroupProvider::read_uclamp(CgroupId, UclampBound)
CgroupProvider::apply_uclamp(CgroupId, UclampBound, UclampValue)
CgroupProvider::create_managed_group(CgroupId, CgroupName, CgroupGroupKind)
CgroupProvider::remove_managed_group(CgroupId, CgroupName, CgroupGroupKind)
ProcessProvider::read_placement(ProcessId)
ProcessProvider::apply_placement(ProcessId, CgroupId)
ProcessProvider::read_nice(ProcessId)
ProcessProvider::apply_nice(ProcessId, NiceValue)
ProcessProvider::read_ioprio(ProcessId)
ProcessProvider::apply_ioprio(ProcessId, IoPriority)
```

The workload backend operates on discovered v2 cgroups and may create or
remove only an explicitly named managed workload/background child under an
approved parent. It may move only an explicitly identified process, using the
PID plus start-time identity; it never scans or classifies arbitrary processes.
A `CgroupId` binds the mount identity, validated relative identity, and
inode/identity evidence where available. The helper revalidates the cgroup,
process identity, controller availability, and current value at snapshot,
apply, verify, and restore time. Lifecycle cleanup requires an empty managed
group with no nested groups. v1 and v2 are separate backend variants; no
path-shaped compatibility shim is allowed to blur their semantics.

### 10.3 CPU topology and runtime soft isolation

Prompt 9 adds a pure CPU placement planner over the read-only topology facts
already collected by discovery. The planner:

- parses the kernel's possible/online CPU lists and rejects a plan when the
  online set is unavailable;
- groups SMT siblings into one physical-core planning unit when package/core
  or sibling metadata is available;
- classifies performance and efficiency groups only when every online CPU has
  positive, distinct kernel capacity values such as `cpu_capacity`;
- treats homogeneous or incomplete capacity evidence as homogeneous/unknown
  and uses deterministic CPU order instead of guessing P-core/E-core identity;
- reserves at least half of the physical-core groups for shared housekeeping
  work, including kernel, compositor/display, audio, networking, GPU helpers,
  and system services;
- emits canonical workload and housekeeping `CpuSet` values plus generated
  affinity-mask bytes for planning and dry-run inspection; and
- captures a topology revision and online set that must match at the final
  pre-apply gate. A changed topology or target identity fails closed rather
  than recomputing placement.

`--prefer-performance-cores` is a planning preference only. It orders
kernel-proven performance groups first; it is a no-op with an explicit
homogeneous/unknown fallback when capacity evidence cannot prove a
heterogeneous topology. The selected workload set can be submitted only as
the existing typed `MutationKind::CgroupCpuset` operation through the approved
planner -> privilege -> transaction -> workload-backend path. Affinity masks
are generated data, not a direct `sched_setaffinity` mutation API. Boot-time
isolation features (`isolcpus=`, `nohz_full=`, and `rcu_nocbs=`) remain outside
the runtime utility.

### 10.4 Virtualization contract

Every backend must run against a `sysboost-testkit` fixture that can model:

- readable, writable, read-only, missing, malformed, and permission-denied
  nodes;
- canonicalizing writes and delayed readback;
- target disappearance and identity replacement;
- external writes between apply and restore;
- cgroup v1/v2 controller availability and hierarchy constraints;
- journal write/flush/rename failures; and
- helper/controller disconnects at every transaction stage.

No test may need root or a real host performance change to validate these
contracts.

## 11. Backend interfaces and registration

The platform/core ports are logically:

```text
CapabilityDetector
  detect(context) -> CapabilityInventory

Planner
  build(policy, inventory) -> Plan

MutationBackend
  descriptor() -> BackendDescriptor
  detect(context) -> BackendInventory
  snapshot(execution_token, mutation) -> Snapshot
  apply(execution_token, mutation, snapshot) -> ApplyReceipt
  verify(execution_token, mutation, expected) -> Verification
  restore(execution_token, mutation, snapshot) -> RestoreReceipt

JournalStore
  create_intent(session, plan, snapshots)
  append_transition(session, transition)
  load_unfinished()

PrivilegeBroker
  prepare(plan) -> SessionHandle
  apply(session)
  restore(session)
  status(session)
```

The Rust traits may split these methods for borrow-checking and stage safety,
but the semantics must remain. `MutationBackend` snapshot/apply/verify/restore
calls require an unforgeable `BackendExecutionToken` held only by
`TransactionEngine`, so a backend cannot be driven directly around durable
intent and complete-snapshot admission. The Linux CPU and workload backends
keep their writable adapters private and expose only read-only inspection
views; their typed mutation implementations are reached through that
token-gated port.

`BackendDescriptor` declares backend ID/version, capability IDs, target kinds,
supported equality, maximum encoded sizes, risk, and feature classification.
The registry rejects duplicate capability/operation ownership and registers
only compiled-in backends. A backend is admitted only if it has unit,
contract, fault-injection, and recovery tests.

## 12. Error taxonomy

Errors are structured and stage-specific. At minimum the public error taxonomy
is:

| Error class | Meaning | Default behavior |
| --- | --- | --- |
| `ConfigError` | Invalid syntax, type, hierarchy, or unsafe policy | Reject before detection. |
| `CapabilityError` | Missing, malformed, ambiguous, or stale evidence | Skip optional; reject required. |
| `Unsupported` | Interface/backend does not implement the operation | Report, never fall back to a different mutation. |
| `AuthorizationError` | Peer, policy, or privilege not permitted | Fail closed and audit. |
| `TargetError` | Target missing, identity changed, or outside scope | Abort before write. |
| `PlanningError` | Invalid value, dependency cycle, duplicate, or unsafe plan | Reject whole plan. |
| `SnapshotError` | Complete original state could not be read or encoded | No mutation. |
| `DurabilityError` | Intent/journal could not be durably persisted | No mutation. |
| `TransportError` | Protocol, peer, framing, timeout, or disconnect failure | Helper recovers session; controller reports uncertain status. |
| `ApplyError` | Typed operation failed or partial backend action occurred | Roll back touched mutations. |
| `VerificationError` | Readback did not satisfy the declared postcondition | Roll back. |
| `RestoreConflict` | External change prevents safe compare-and-restore | Preserve external value; end `Degraded`. |
| `RestoreError` | Original write/readback failed | Retry/recover; end `Degraded` if unproven. |
| `JournalCorrupt` | Checksums/sequence/state are invalid | Do not mutate; require recovery inspection. |
| `InvariantViolation` | Internal bug or impossible state | Stop, preserve state, alert loudly. |

Errors carry session/mutation/backend/target identifiers, stage, stable code,
retryability, and a safe remediation. They do not echo arbitrary values,
credentials, or untrusted paths into logs or protocol errors.

## 13. Verification semantics

Verification is a first-class operation with a result containing:

```text
Verification {
    subject: MutationId or SessionId,
    expected: ExpectedState,
    observed: ObservedState,
    equality: EqualityKind,
    result: Verified | Mismatch | Unreadable | Missing,
    observed_at: Timestamp,
}
```

The equality contract is selected by the capability descriptor:

- `ByteExact`: original bytes must be restored exactly.
- `ScalarExact`: typed scalar value must equal the preimage.
- `SetExact`: normalized set equality must equal the preimage, with a stable
  canonical representation recorded.
- Any weaker comparison requires an explicit ADR and is not eligible for a
  default runtime mutation.

Verification must account for interfaces that apply asynchronously: the
backend may poll with a bounded deadline, but it may not sleep indefinitely or
declare success based only on a write return code. A failed verification is a
transaction failure, not a warning.

## 14. Configuration hierarchy

Configuration expresses desired policy; it never describes privileged paths.
The effective policy is formed in this order:

```text
compiled safe defaults
  -> system policy: /etc/sysboost/config.toml
  -> user policy: ${XDG_CONFIG_HOME:-~/.config}/sysboost/config.toml
  -> invocation options
  -> detected capability constraints
```

The merge rules are safety-oriented:

- compiled defaults are report-only/opt-in for risky families;
- system policy defines administrator allowlists, protected targets, maximum
  risk, and value bounds;
- user policy may select and narrow what the system permits, but cannot widen
  an administrator restriction;
- CLI options may select a subset and narrow values, but cannot bypass the
  system ceiling; and
- detection can remove an unavailable capability but can never grant one.

Deny/protect rules at a higher-trust layer always win. The helper loads its
  own root-owned policy and treats controller/user policy as an untrusted
  request constrained by that policy. The controller never passes a config
  path to the helper. Invalid or world-writable system configuration is a
  hard error, not an invitation to continue with guessed settings.

The initial schema should include explicit `mode` (`report`, `boost`),
`required`, target selectors, capability selections, numeric bounds, risk
allowances, session timeout, and logging settings. It must not include raw
filesystem paths or command strings. Environment variables are not a hidden
precedence layer; only documented path selection such as `XDG_CONFIG_HOME`
may affect discovery.

## 15. Logging and audit model

Operational logging is structured JSON or journald fields with a stable event
schema:

```text
timestamp, level, component, session_id, plan_digest, mutation_id,
backend_id, capability_id, target_id, stage, event, outcome, error_code,
duration_ms
```

The default log contains logical identifiers and outcomes, not raw preimage
bytes. Values are redacted or summarized unless an explicit secure diagnostic
mode is enabled. Untrusted strings are escaped to prevent log injection.

The root-owned session journal is the authoritative audit trail for mutation,
verification, restore, conflict, recovery, and force-repair events. It is
append-only from the service's perspective. Logs must make it possible to
answer: what policy and capability evidence led to the plan, what was
changed, what was verified, what was restored, and what remains uncertain.

## 16. Test architecture

The test suite is layered:

1. **Core unit/property tests**: typed value bounds, plan determinism,
   dependency sorting, duplicate rejection, state-machine legality, digest
   stability, and the invariant that apply is impossible before durable
   intent.
2. **Port contract tests**: every backend runs the same snapshot/apply/
   verify/restore cases through fake ports.
3. **Virtual Linux integration tests**: fake sysfs, procfs, cgroup v1/v2, and
   target identities; no host paths and no root.
4. **Fault-injection tests**: fail reads, parsing, permissions, writes,
   readback, journal flush/rename, transport, heartbeat, and process restart
   at each state transition.
5. **Recovery tests**: replay unfinished journals, verify reverse rollback,
   conflict behavior, idempotent restore, and degraded-state blocking.
6. **Protocol tests**: version negotiation, framing limits, invalid enum/value
   rejection, peer authorization, replay/duplicate requests, and fuzzing of
   untrusted messages.
7. **Security tests**: prove no controller input reaches a raw path or command,
   no symlink escape is accepted, and unregistered operations are rejected.

An optional privileged lab test may be added later, but it must be opt-in,
isolated, and never part of normal CI. The design is considered valid without
mutating the developer's real `/sys`, `/proc`, cgroups, GPU, or IRQ state.

## 17. Implementation and migration rule

Because the audit found no existing crate or runtime behavior, there was no
legacy architecture to preserve and no migration shim to invent. Prompt 2
created the workspace in the order `core` -> `platform` and `testkit` ->
`config` -> `linux`/`protocol` -> binaries. Runtime backend work must follow
the feature classification and safety gates in this document.

The first implementation prompt must not silently introduce a direct root
writer, generic path API, implicit shell fallback, or unjournaled mutation.
If an implementation needs a new capability, equality rule, session state,
privilege, or backend registration mechanism, it must stop and update this
freeze through an ADR before coding.

## 18. Frozen contracts checklist

The following are frozen for subsequent work:

- capability IDs are semantic and evidence-driven;
- controller and privileged service are separate trust domains;
- the helper re-detects and snapshots; the controller cannot supply a
  preimage;
- mutation units are typed, bounded, target-scoped, and individually
  restorable;
- no arbitrary path/value/command privileged API exists;
- the mandatory order is `detect -> plan -> snapshot -> durable intent ->
  apply -> verify -> restore`;
- no write occurs before complete preimages and durable intent;
- apply and restore are readback-verified;
- restore is reverse-order, idempotent, and compare-and-restore by default;
- external conflicts produce `Degraded`, never false success;
- only `Restored` is a successful terminal state;
- overlapping target sessions are rejected by default;
- sysfs/procfs/cgroup paths are Linux-adapter internals and are virtualizable;
- backend registration is compiled-in and capability-owned;
- boot-only/report-only features are never runtime writes; and
- tests must run without real host mutation.
