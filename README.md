# sysboost

`sysboost` is intended to be a runtime-only Linux performance optimization
utility. Its primary safety invariant is exact restoration of the state that
existed before a boost session.

The architecture is frozen, the Rust foundation, read-only Linux capability
discovery, transaction/privilege boundaries, reviewed typed CPU/workload
backends, and conservative topology-aware runtime soft-isolation planning are
implemented. The production boundaries, mutation contracts, transaction
model, safety rules, and test virtualization requirements are documented in:

- [Architecture](docs/ARCHITECTURE.md)
- [Safety](docs/SAFETY.md)
- [ADR 0001: Architecture freeze](docs/adr/0001-architecture-freeze.md)
