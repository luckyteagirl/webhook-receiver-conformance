# Implementation Tasks

`machine/task-index.yaml` is the machine authority for 75 tasks. Each Markdown work packet is a complete agent handoff.

## Rules

- Start only dependency-ready tasks.
- Respect exclusive ownership and forbidden files.
- Parallel work requires matching `parallel_group` and disjoint ownership.
- Public schema, migration, error-enum, and CLI registry changes require integration-owner coordination.
- Complete every command and return objective evidence.
- Stop at packet scope.

## Phases

| Phase | Tasks |
| --- | --- |
| phase-00-foundation | TASK-0001, TASK-0002, TASK-0003, TASK-0004 |
| phase-01-domain-and-schemas | TASK-0101, TASK-0102, TASK-0103, TASK-0104, TASK-0105, TASK-0106, TASK-0107, TASK-0108, TASK-0109, TASK-0110 |
| phase-02-journal-and-state | TASK-0201, TASK-0202, TASK-0203, TASK-0204, TASK-0205, TASK-0206, TASK-0207 |
| phase-03-scheduler-and-executor | TASK-0301, TASK-0302, TASK-0303, TASK-0304, TASK-0305, TASK-0306, TASK-0307, TASK-0308, TASK-0309, TASK-0310, TASK-0311 |
| phase-04-signers-and-mutations | TASK-0401, TASK-0402, TASK-0403, TASK-0404, TASK-0405, TASK-0406, TASK-0407 |
| phase-05-observers-and-assertions | TASK-0501, TASK-0502, TASK-0503, TASK-0504, TASK-0505, TASK-0506, TASK-0507, TASK-0508, TASK-0509 |
| phase-06-reporting | TASK-0601, TASK-0602, TASK-0603, TASK-0604, TASK-0605, TASK-0606 |
| phase-07-reference-receivers | TASK-0701, TASK-0702, TASK-0703, TASK-0704, TASK-0705, TASK-0706, TASK-0707, TASK-0708, TASK-0709, TASK-0710, TASK-0711 |
| phase-08-packaging-security-and-ci | TASK-0801, TASK-0802, TASK-0803, TASK-0804, TASK-0805, TASK-0806, TASK-0807, TASK-0808, TASK-0809, TASK-0810 |
