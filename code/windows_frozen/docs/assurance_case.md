# Prototype assurance case

This document turns the word *trustworthy* into bounded, testable claims. It is
not a certification or a proof of live-network safety. Each claim identifies
the mechanism, executable evidence, and remaining limitation.

| ID | Bounded claim | Mechanism | Executable or review evidence | Residual limitation |
|---|---|---|---|---|
| AC-01 | Malformed or unknown actions do not bypass evaluation. | Closed contract, bounded JSON content, strict enum handling, deny on parse failure. | `tests/test_contract.py`; adversarial cases in `tests/test_policy_and_adversarial.py`. | Resource exhaustion outside configured file/object bounds remains a deployment concern. |
| AC-02 | A proposal cannot authenticate itself or select a stronger role. | Out-of-band authenticated-principal input, exact payload/principal binding, frozen principal-to-role map, RBAC. | Forged, missing, and role-mismatch tests in `tests/test_engine_edge_cases.py`. | The prototype models authenticated transport; it does not implement mTLS or an identity provider. |
| AC-03 | An action cannot change semantic meaning using a wrong interface, target type, extra parameter, or control alias. | Exact interface/action, action/target, and action/parameter policy maps. | Semantic negative tests in `tests/test_engine_edge_cases.py`; strict policy tests. | Operator mappings are illustrative and need deployment-specific review. |
| AC-04 | Protected targets, excessive parameters, understated risk, stale requests, and expired TTLs fail closed. | Protected-slice list, numeric bounds, minimum-risk floor, clock-skew/age and TTL checks. | Conformance categories plus edge-case tests. | Correct thresholds depend on operator risk appetite and synchronized trusted clocks. |
| AC-05 | High-risk approvals cannot be satisfied by an in-band assertion alone. | Default-deny verifier and external fixture bound to the exact proposal digest, agent, role, status, and expiry. | Approval forgery, mutation, expiry, and success tests. | Production requires a signed, revocable approval service and protected keys. |
| AC-06 | Direct same-target/same-control conflicts do not execute automatically. | Validated active-state snapshot and deterministic conflict escalation. | Conflict conformance cases and malformed-state test. | Indirect, cross-KPI, and learned-policy conflicts are not detected. |
| AC-07 | Disruptive proposals declare rollback and bounded lifetime. | Rollback presence and maximum TTL rules. | Missing-rollback and TTL tests. | The prototype does not prove that a written rollback procedure will work. |
| AC-08 | An `ALLOW` result cannot be reused for a modified proposal in the dry run. | Executor verifies origin, decision, action ID, proposal digest, audit checksum, and in-process replay set. | Decision/use substitution, checksum-tampering, non-allow, and replay tests. | Production needs signed decisions and durable atomic idempotency across replicas. |
| AC-09 | Every Trust-Boundary outcome is attributable and integrity-checkable. | Audit for allow/deny/escalate/malformed input with authenticated principal, policy/proposal hashes, reasons, and checksum. | Complete-audit conformance test and checksum tests. | A checksum is not a signature or immutable log anchor. |
| AC-10 | Security configuration is unambiguous and frozen. | Strict shape validation, deep copy, canonical hash, duplicate-key/non-finite/size rejection. | Policy mutation/shape tests and `tests/test_jsonio.py`. | A party that can replace trusted files and code can still change behaviour. |
| AC-11 | Dataset context is real, version-bound, and privacy-minimized. | Official DOI, archive/member hashes, SQLite integrity/schema checks, exhaustive strata aggregation, no raw identifier export. | `tests/test_netslab_adapter.py`, extraction receipt, `DATASET.md`, generated context manifest. | Dataset labels are ground truth for replay context, not proof of detector or mitigation performance. |
| AC-12 | Comparative results are reproducible and not overstated. | Frozen suite/policy/registry, raw decisions, source/output hashes, warmups, randomized blocks, exact counts, descriptive intervals. | Generator/run manifests, benchmark tests, blind-review tooling. | Constructed cases are correlated and do not estimate operational prevalence. |
| AC-13 | The original gateway and dataset-context experiments cannot actuate a network. | Dry-run executor only; no O-RAN client, endpoint or credentials. | Source review, `SECURITY.md`, and executor tests. | The separately opt-in Linux laboratory now has scoped packet/traffic-control capability; it has a separate threat model and is not production or O-RAN actuation. |
| AC-14 | Public release minimizes software supply-chain risk. | Zero runtime dependencies, pinned CI actions, supported-Python matrix, Apache-2.0 code licence, CC BY 4.0 data attribution. | `pyproject.toml`, CI workflow, `LICENSE`, and `DATASET.md`. | Hosted CI and future toolchain releases remain external dependencies. |

## Required independent evidence before paper claims

1. Two co-authors independently label the blinded cases; report agreement and
   retain adjudication notes.
2. Domain authors verify each standards locator and clearly distinguish
   standards-derived statements from illustrative operator policy.
3. Run at least three pre-declared repetitions on an idle documented host and
   retain all runs, not only the fastest one.
4. Reproduce from a clean clone on a second environment.
5. Freeze a release tag and archive the exact code/results with a persistent
   identifier.

Until these items are complete, benchmark numbers are engineering pilot results.

## Separate closed-loop laboratory

The new controller/backend has unit-tested software guards, but no Linux
packet-level execution evidence yet. The protocol and draft manuscript snippet
are explicitly NOT RUN. A passing mock, command-construction test, or packet
accounting test cannot establish kernel containment, achieved rate, mitigation
benefit, or successful restoration on a real Linux host. See
`docs/CLOSED_LOOP_STATUS.md` for the required next validation steps.
