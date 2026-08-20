# sysboost safety contract

Status: **frozen safety contract; foundation and read-only discovery implemented; runtime mutation deferred**
This document states the safety properties that every future implementation
and backend must satisfy. It is intentionally operational: if a proposed
feature cannot meet these rules, it is report-only until the contract changes
through an ADR.

## 1. Safety objective

`sysboost` is a runtime-only optimizer. The highest-priority invariant is:

> A session may be reported successful only when every mutation has been
> verified and every original pre-boost state has been verified after restore.

The utility must never trade restoration certainty for a larger performance
gain. A capability that cannot provide a complete preimage, a typed bounded
write, and a readback equality rule is not runtime mutable.

The design is fail-closed. Unsupported, denied, ambiguous, stale, malformed,
or non-reversible interfaces are skipped only when policy marks them optional;
a required request rejects the plan. No “best effort” mode is allowed to make
an untracked write.

## 2. Non-negotiable invariants

1. No real host mutation occurs during detection or planning.
2. Every mutation has exactly one typed operation, target identity, desired
   value, precondition, complete snapshot, and restore contract.
3. The complete snapshot and durable intent exist before the first write.
4. The controller cannot choose a raw privileged path, raw write bytes, or
   command to execute.
5. The helper revalidates capabilities, policy, target identity, and current
   state immediately before snapshot/apply.
6. Every apply and restore is verified by readback using the capability's
   declared exact equality.
7. Rollback runs in reverse dependency order and is safe to retry.
8. An external change is a conflict, not permission to silently overwrite.
9. `Degraded` and uncertain recovery are failures that block new sessions on
   affected targets.
10. Boot-only/report-only features never enter the runtime mutation path.

## 3. Mutation admission checklist

Before a backend can apply one mutation, the helper must have positive answers
to all questions below:

| Gate | Required evidence | If false |
| --- | --- | --- |
| Capability | Fresh, positive capability evidence | Skip/reject; never guess. |
| Backend | Compiled-in, registered, tested backend owns the operation | Reject as unregistered. |
| Policy | Effective system policy permits the capability and risk | Reject. |
| Target | Stable, in-scope target identity | Abort before write. |
| Value | Typed value parses, is bounded, and satisfies kernel/backend constraints | Reject plan. |
| Precondition | Current state equals the planned observation | Re-plan or abort. |
| Preimage | Full original state and equality metadata are captured | No write. |
| Durability | Journal intent is flushed and durable | No write. |
| Lease | No overlapping session or unknown owner controls the target | Reject. |
| Verification | Backend declares a bounded readback verifier | No runtime admission. |

These gates are defense in depth. Passing a controller-side check never
substitutes for the helper's check.

## 4. Exact restoration and conflicts

### 4.1 Definition of exact

Exactness is defined per capability:

- `ByteExact`: restore the exact bytes read before the session.
- `ScalarExact`: restore the exact typed scalar, including a documented unit
  and normalization rule.
- `SetExact`: restore the same set, with a deterministic canonical encoding.

The preimage contains raw bytes plus the typed interpretation whenever the
interface permits. A backend that loses information while parsing or writing
must not advertise an exact equality rule.

### 4.2 Compare-and-restore

Normal rollback is ownership-aware:

```text
current == last_session_verified_value
    -> write original preimage
    -> read and verify original

current != last_session_verified_value
    -> record RestoreConflict
    -> do not overwrite external state
    -> continue independent restores
    -> terminal state is Degraded, not Restored
```

This protects a user, kernel manager, or second service that changed the same
resource while the session was active. It also makes the guarantee honest:
sysboost can prove exact restoration only when the target remains stable. An
operator may later use an explicitly authorized, audited force-repair action
for a named session and target. That action is recovery, not normal rollback,
and still uses the typed backend/preimage contract.

### 4.3 No false success

The following are not success:

- write returned without an error but readback was not performed;
- readback is unavailable;
- the target disappeared;
- permission changed;
- the journal was not durable;
- an external writer changed the target;
- only some mutations restored; or
- the helper cannot establish which state was last written.

The service must surface the session ID, mutation ID, stable error code, and
recovery state so an operator can remediate it.

## 5. Failure and recovery matrix

| Failure point | Required action | Allowed terminal state |
| --- | --- | --- |
| Detection/planning | Make no writes; report or reject | No session / rejected |
| Snapshot read/parse | Abort before apply; retain no active lease if safe | Rejected |
| Journal create/flush/rename | Abort before apply | Rejected |
| First apply | Verify failure or partial effect enters rollback | Restored or Degraded |
| Later apply | Stop new applies; restore successful mutations in reverse order | Restored or Degraded |
| Apply readback | Roll back; do not continue plan | Restored or Degraded |
| Controller disconnect | Helper owns journal; grace period then rollback | Restored or Degraded |
| Helper restart | Replay unfinished journal before accepting new session | Restored or RecoveryPending/Degraded |
| Restore write/readback | Retry under bounded policy; preserve conflict state | Restored or Degraded |
| External target change | Compare-and-restore refuses to clobber | Degraded |
| Journal corruption | Freeze mutation/recovery, alert, require inspection | RecoveryPending |
| Internal invariant violation | Stop and preserve observable state; emit audit event | Degraded/RecoveryPending |

If recovery is uncertain, the safe operational choice is to block further
changes to the affected target until a named operator resolves the session.

## 6. Privilege and attack surface

### 6.1 Controller boundary

The controller handles user policy, CLI input, display, and an advisory
inventory. It is not trusted with root credentials, the journal, or arbitrary
host paths. The helper treats every incoming field as hostile, including
capability IDs, target IDs, lengths, enum discriminants, and policy digests.

### 6.2 Privileged service boundary

The helper is a small root-owned service with:

- a root-owned executable and journal directory;
- a Unix socket with restrictive ownership/mode and peer-credential checks;
- protocol version, maximum frame length, timeout, and request-rate limits;
- session nonce/ownership checks to prevent replay or cross-session use;
- compiled-in operation and target validation;
- no shell, `Command`, external tuning executable, or user-supplied script;
- no dynamic backend loading in the initial design; and
- a narrow filesystem allowlist implemented by each backend.

The implementation should additionally apply ordinary Linux hardening that is
compatible with the supported kernel (minimal supplementary groups/capability
set, private runtime files, restrictive umask, and an appropriate syscall
filter). Hardening must not be treated as a substitute for typed API
validation.

### 6.3 Kernel pseudo-filesystems

sysfs, procfs, and cgroupfs are treated as changing external state, not as
ordinary trusted files. The adapter must:

- resolve only backend-owned nodes beneath an approved mount/root;
- reject symlink traversal and unexpected file types;
- bound reads and writes;
- parse with strict typed parsers and reject trailing garbage where relevant;
- re-read after writes; and
- handle disappearance, remounts, permission changes, and identity changes as
  errors or conflicts.

No controller-supplied path is ever passed to a filesystem call in the helper.

## 7. Configuration safety

The effective configuration is the intersection of safe defaults, administrator
policy, user selection, CLI narrowing, and detected capability constraints.
Higher-trust deny/protect rules cannot be overridden by lower-trust settings.

The system configuration must be root-owned and not group/world-writable. A
bad system configuration is a hard error. User configuration can request only
what the helper's system policy allows. Configuration has no generic path,
command, or “write arbitrary key” field.

Risk defaults are:

- report-only for boot/firmware/kernel-build features;
- opt-in for experimental GPU, IRQ, CPU online/offline, and scheduler
  families;
- optional and capability-gated for conditional cgroup/sysctl families; and
- no mutation when exact snapshot or readback is unavailable.

## 8. Feature safety classes

The authoritative classification is in
[ARCHITECTURE.md](ARCHITECTURE.md). In summary:

- **Runtime mutable**: reviewed CPUFreq and selected cgroup operations with
  exact snapshot/restore.
- **Conditional**: operations whose availability, controller topology, or
  kernel semantics must be detected on each host.
- **Experimental**: GPU, IRQ affinity, CPU online/offline, and scheduler
  families; disabled by default and separately gated.
- **Boot-only/report-only**: bootloader, kernel command line, initramfs,
  firmware/BIOS, microcode selection, and kernel build configuration.

The classification is not permission to implement a feature. It is the safety
policy that implementation must satisfy.

## 9. Test obligations

Safety tests must prove behavior without changing the developer host:

- fake sysfs/procfs/cgroup fixtures for every backend;
- no-write-before-intent tests;
- failure injection at every journal and transaction boundary;
- crash/restart and journal replay tests;
- external-change conflict tests;
- idempotent reverse rollback tests;
- protocol fuzzing and authorization tests; and
- path traversal and command-injection negative tests.

Any future opt-in real-host lab test must be isolated, clearly marked, and
never required for ordinary builds or CI.

## 10. Operator-visible safety statuses

The implementation must distinguish at least:

- `ReportOnly`: no mutation was attempted;
- `Prepared`: complete snapshot and durable intent exist, no apply yet;
- `Active`: all intended applies are verified and the session is held;
- `Restored`: every original state is verified;
- `Degraded`: one or more originals are unproven or conflicted; and
- `RecoveryPending`: journal/recovery requires attention before new changes.

Only `Restored` is a successful mutation-session completion. Report-only can
be successful as a report command because it performed no mutation, but it is
not a boost success.

## 11. Safety review gate for a new backend

A backend may move from report-only to runtime mutable only after reviewers can
answer “yes” to every item:

1. Is the capability selected from live evidence rather than hardware/vendor
   assumptions?
2. Is the operation closed, typed, bounded, and target-scoped?
3. Can every affected state element be snapshotted before any write?
4. Is the declared equality strong enough to support the exact-restoration
   invariant?
5. Is apply followed by bounded readback verification?
6. Is restore reverse-order, idempotent, and conflict-aware?
7. Does the backend work against fake Linux fixtures and injected failures?
8. Does the privileged service need no generic path or command API?
9. Are policy/risk defaults safe and the feature class documented?
10. Are journal recovery and degraded-state behavior tested?

One “no” leaves the backend report-only or experimental.
