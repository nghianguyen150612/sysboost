# ADR 0001: Capability-driven transactional architecture

- Status: Accepted
- Date: 2026-08-21
- Scope: Initial production architecture
- Supersedes: None

## Context

The repository is a greenfield initial commit. There is no Rust workspace,
runtime code, privileged helper, configuration schema, or test architecture.
`sysboost` is nevertheless safety-critical in one specific way: it must not
leave runtime kernel state changed after a boost session, and it must not
silently destroy a concurrent writer's change while trying to restore state.

Linux exposes performance controls through optional, version-sensitive
interfaces such as sysfs, procfs, cgroupfs, device nodes, and IRQ metadata.
Their presence varies by kernel configuration, permissions, topology, and
runtime state. Distro/vendor/model heuristics are therefore not an acceptable
capability source. A privileged design based on shell commands or arbitrary
path writes would also make exact rollback and security review impossible.

## Decision

Adopt a capability-driven, typed, journaled transaction architecture:

1. Keep domain types, planning, state transitions, and safety rules in a
   Linux-independent `sysboost-core` crate.
2. Put I/O and service boundaries behind platform ports; keep sysfs/procfs/
   cgroup path knowledge in `sysboost-linux`.
3. Use an unprivileged controller and a small root-owned `sysboost-privd`.
   The helper accepts only versioned typed operations and revalidates all
   controller claims.
4. Require the sequence `detect -> plan -> snapshot -> durable intent ->
   apply -> verify -> restore`.
5. Give each mutation a typed desired value, stable target, complete preimage,
   equality rule, and restore contract.
6. Register reviewed backends at compile time; do not load arbitrary plugins.
7. Use fake sysfs/procfs/cgroup ports and fault injection for ordinary tests.
8. Treat external restore interference as a conflict and report `Degraded`,
   rather than silently overwriting the external writer.
9. Keep boot-time and experimental families report-only or explicitly gated.

The detailed contracts are frozen in
[ARCHITECTURE.md](../ARCHITECTURE.md), with the non-negotiable safety rules in
[SAFETY.md](../SAFETY.md).

## Alternatives considered

### Direct root process with generic filesystem writes

Rejected. It makes every caller a privileged caller, allows arbitrary target
selection, spreads Linux path logic into policy code, and cannot prove that a
write is paired with a complete preimage.

### Shell commands or vendor tuning utilities

Rejected. Command availability and syntax are not capability evidence; command
side effects are difficult to enumerate and restore; quoting and executable
resolution expand the privilege boundary.

### Distro/vendor/model decision tables

Rejected. They become stale and fail on custom kernels, containers, firmware,
permissions, and topology. Live interface evidence is the authoritative input.

### Best-effort writes with process-exit cleanup

Rejected. Process exit is not a durable transaction, and cleanup cannot know
what happened after a crash or concurrent external write. Durable preimages,
journal replay, verification, and explicit degraded status are required.

### Dynamic backend plugins in the first release

Deferred. Dynamic loading increases the privileged code and supply-chain
surface. Compiled-in registration is easier to review and test. A plugin
system would require its own security and compatibility decision.

## Consequences

Positive:

- exact restoration is a first-class API property rather than an afterthought;
- policy and planning remain portable and testable;
- all privileged writes are closed over reviewed operation types;
- fake Linux interfaces make failure and recovery testing practical; and
- unavailable or unsafe features degrade to an explicit report instead of a
  guessed mutation.

Costs and limitations:

- two-process coordination and a durable journal add implementation work;
- a helper crash can leave a temporary boost until service recovery runs;
- external changes can make a session `Degraded` rather than automatically
  restoring the old value;
- some Linux interfaces will remain report-only because they cannot preserve a
  complete preimage; and
- every new capability needs a backend contract, tests, and safety review.

## Migration and implementation note

There is no existing architecture to migrate. The next implementation work
should create the workspace in dependency order and must not introduce a
generic privileged writer, shell fallback, or unjournaled mutation under the
guise of bootstrapping. Any departure from the frozen contracts requires a
new ADR before implementation.

