# Schema Validation

**Executed:** 2026-07-26  
**Validator:** Python `jsonschema` Draft 2020-12, PyYAML safe loader, Python XML parser.

| Gate | Result | Detail |
| --- | --- | --- |
| JSON parsing | PASS | 20 JSON files parsed. |
| YAML parsing | PASS | 6 YAML files parsed without custom tags. |
| JSON Schema meta-validation | PASS | 11 Draft 2020-12 schemas accepted by jsonschema. |
| Example examples/project-config.minimal.yaml | PASS | Validated against project-config.schema.json. |
| Example examples/project-config.complete.yaml | PASS | Validated against project-config.schema.json. |
| Example examples/fixture-manifest.example.json | PASS | Validated against fixture-manifest.schema.json. |
| Example examples/run-manifest.example.json | PASS | Validated against run-manifest.schema.json. |
| Example examples/result-summary.example.json | PASS | Validated against result-summary.schema.json. |
| Example examples/observer-request.example.json | PASS | Validated against observer-request.schema.json. |
| Example examples/observer-response.example.json | PASS | Validated against observer-response.schema.json. |
| Example examples/plugin-metadata.example.json | PASS | Validated against plugin-metadata.schema.json. |
| JSON Lines examples/deliveries.example.jsonl | PASS | 1 record(s) validated against delivery-record.schema.json. |
| JSON Lines examples/observations.example.jsonl | PASS | 1 record(s) validated against observation-record.schema.json. |
| JSON Lines examples/assertions.example.jsonl | PASS | 1 record(s) validated against assertion-record.schema.json. |
| JUnit XML | PASS | Example is well formed. |
| Task index schema | PASS | 75 task records validated. |
| Requirement quality | PASS | 355 singular requirements have complete metadata, one normative keyword, and resolved mappings. |
| Agentic task graph | PASS | 75 tasks form an acyclic DAG; 10 work packets passed the fresh-agent structural simulation. |
| Traceability | PASS | 100% requirements, tasks, tests, ADR requirement links, scenarios, and interface test references resolve. |
| Diagram structural validation | PASS | 26 Mermaid sources passed header and delimiter checks. |
| Mermaid renderer validation | LIMITED | mmdc is not installed; syntax received structural validation only. |
| Research coverage | PASS | 120 sources; 11 incident/issue/report records; 11 tool/repository/product/package records. |
| Placeholder scan | PASS | No TBD/TODO/FIXME/PLACEHOLDER token in authoritative, task, or machine artifacts. |
| Adversarial finding gate | PASS | No critical or high-severity finding remains open. |

## Result

- Passes: 23
- Failures: 0
- Limited checks: 1

No success is claimed for a check that was not executed. Mermaid renderer validation is limited when `mmdc` is unavailable.
