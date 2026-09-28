# Reviewer and public-code readiness checklist

This checklist distinguishes safeguards already implemented from work that must
be completed before the paper's final experiment.

| Critical question | Required treatment | Current evidence/status |
|---|---|---|
| Is this merely an extension of the CSCN planner? | Accept actions from any source; evaluate a separate pre-execution trust question. | Planner-independent action contract and three fixed comparison systems implemented. |
| Is the dataset invented? | Use NetsLab-5GORAN-IDD for incident context; call generated cases a conformance suite. | Archive and database hashes frozen; 45,244 rows and all 19 subcategories profiled; privacy-preserving adapter implemented. |
| May the derived context be published? | Record the official licence and attribution, and describe modifications. | Kaggle lists CC BY 4.0; `DATASET.md` records attribution, checksums, and aggregation changes. |
| Was the dataset silently changed from the supporting paper? | Report the downloaded release schema/counts and never substitute a missing class. | Exact label mapping and explicit TCP/port-scan mismatch notes are generated. |
| Are labels circular? | Blind at least two authors to generated expectations, report agreement and adjudicate. | Blinded export, comparison, confusion matrix, and Cohen's kappa implemented; reviews pending. |
| Are standards and operator assumptions confused? | Mark each rule as standards-informed, threat-derived, governance, or illustrative operator policy. | Traceability table implemented; exact source locators require final author verification. |
| Does the proposal authenticate itself? | Supply identity out of band and resolve its role from a trusted registry. | Authenticated context/payload binding implemented; missing, unknown, forged, or mismatched principals are denied. |
| Can ignored parameters or a wrong target smuggle intent? | Enforce exact per-action parameter and target contracts. | Semantic contracts and negative tests implemented. |
| Can an action forge human approval? | Verify approval out of band and bind it to action, agent, role, and expiry. | Default-deny approval verifier and offline registry adapter implemented. |
| Can malformed state hide conflicts? | Fail safely when the active-action snapshot is invalid. | Invalid active state escalates with a reason code. |
| Can an agent understate risk? | Enforce an operator-defined minimum risk per action. | Risk-floor policy implemented. |
| Are requests fresh and non-replayed? | Check timestamps and reject duplicate execution identifiers. | Clock-skew/age checks and dry-run replay guard implemented. |
| Are malformed inputs safe? | Bound fields, nesting, collection size and encoded size; reject unknown and non-finite values. | Fail-closed typed parser and adversarial tests implemented. |
| Can reviewed JSON mean something different at runtime? | Reject duplicate keys, non-finite constants, and oversized security files. | Strict policy, approval-registry, and suite loaders implemented. |
| Is policy configuration itself validated? | Reject incomplete, unknown, contradictory, duplicate, or non-finite policy values. | Strict policy loader implemented with canonical policy hash. |
| Is auditability complete? | Audit allow, deny, escalate, and malformed requests with policy and input digests. | Complete decision records and record checksums implemented. Checksum is not overclaimed as a signature. |
| Can the code actuate a network? | Provide no credentials or live connector; use a dry-run executor only. | Mock executor has no network imports or endpoint configuration. |
| Can an allowed decision be reused for a changed action? | Bind execution to the audit proposal digest and action ID. | Decision/use binding and replay tests implemented. |
| Is archive handling safe? | Do not auto-extract; bound header reads; flag traversal names and suspicious compression. | Read-only inventory with hashing and archive checks implemented. |
| Are results reproducible? | Freeze suite, policies, seed and environment; publish raw decisions and checksums. | Generator manifest and run manifest implemented. |
| Are performance comparisons fair? | Warm up, use a monotonic high-resolution clock, randomize evaluation blocks, retain raw timing samples. | Implemented; final runs should also document host load and power mode. |
| Is uncertainty reported without pseudo-replication? | Report counts and explicitly limit inference from constructed, correlated cases. | Numerators, denominators, and descriptive Wilson intervals are emitted; the protocol forbids population claims. |
| Are secrets or personal identifiers exposed? | Ignore credentials/raw data; use synthetic IDs; omit usernames/hostnames from manifests. | Git exclusions, synthetic fixtures, privacy-conscious provenance implemented. |
| Is the software supply chain controlled? | Minimize dependencies, run CI across supported Python versions, publish licence and security policy. | Core has zero runtime dependencies; CI and security policy implemented. Full release review pending. |
| Are claims bounded? | State that conformance is not live-network safety or mitigation effectiveness. | README, protocol, and threat model contain explicit limitations. |

## Required before manuscript submission

1. Reconfirm the dataset licence/version metadata on the final release date.
2. Have two co-authors complete blinded label sheets; adjudicate disagreements.
3. Verify every standards locator against the cited public document.
4. Freeze policy and suite hashes before the final run.
5. Run the benchmark on an idle, documented host at least three independent
   times and retain every raw result file.
6. Perform a clean-clone reproduction on a second machine or CI runner.
7. Confirm third-party dataset licence and publish download instructions rather
   than raw data unless redistribution is explicitly permitted.
8. Add all authors and the final DOI/repository URL to `CITATION.cff`.
9. Tag the exact paper release and archive it with a persistent identifier.
