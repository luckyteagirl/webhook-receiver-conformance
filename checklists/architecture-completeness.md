# Architecture Completeness Checklist

- [ ] Every component exists to satisfy mapped P0 requirements.
- [ ] Dependency direction is acyclic and inward.
- [ ] Every external/internal interface has input, output, errors, timeout, idempotency, versioning, and security semantics.
- [ ] State transitions include trigger, guard, transaction boundary, side effect, and recovery.
- [ ] Data schema has keys, constraints, migration, retention, and corruption behavior.
- [ ] Context, modules, components, deployment, trust, data, state, and dynamic views agree.
- [ ] External nondeterminism is not represented as deterministic.
- [ ] Overengineering review removes unsupported services and abstractions.
