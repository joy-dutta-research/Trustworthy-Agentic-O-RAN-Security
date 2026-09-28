# What the findings enable next

The initial PoC establishes a practical starting point: an explicit policy boundary, evidence-aware intervention and outcome checking can be studied as separate, complementary responsibilities. The results also help prioritize development. This section separates what was observed from what a future study should establish.

| What the completed tests show | What this contributes | Next engineering or research step |
|---|---|---|
| The full boundary enforces the frozen reference policy on the tested constructed cases | A traceable baseline for Safe Action Verification | Broader policy coverage and independently reviewed operator assumptions |
| Policy-compliant false-alarm proposals remain permitted | A clear distinction between authorization and the need to intervene | Richer evidence/uncertainty handling and learned-detector evaluation |
| Local checks have measurable cost and larger active-action sets increase work | Concrete processing and state-scaling requirements | Indexed conflict/state handling, bounded state and carefully tested concurrency |
| The single-worker gate overflows its queue at the higher offered rates | A measured operating envelope for the current implementation | Capacity planning, scheduling/backpressure and overload-safe admission design |
| Flood mitigation gains are similar across the tested intervention methods | Evidence that the bounded action can help in the controlled scenario | More scenarios, operating points and repetitions to compare broader trade-offs |
| Feedback abstains in the tested benign bursts and approximately preserves legitimate suspect traffic | An operational reason to corroborate an alert before applying an allowed action | Diverse benign/attack transients and explicit detection-delay trade-offs |
| Corroboration adds about one second before the recorded apply-decision | An explicit observation-delay cost | Faster or adaptive evidence windows, evaluated without relaxing safety criteria |
| Acknowledged no-op actions trigger no-benefit handling without improving delivery | A testable distinction between actuator acceptance and measured benefit | Genuinely harmful-action recovery, escalation paths and operator interaction |
| Both model reviews agree on the supplied original-case decisions | Consistency evidence for interpreting the declared rules | More complete rule citations, stronger model provenance and independent human review |
| The clean VM repeats the protocol on Workstation 2 | Environment-reconstruction evidence | Independent physical-host packet replications and a larger confirmatory study |

These are development opportunities grounded in observed behavior. The overload, false-alarm admissions and ineffective-action outcomes remain part of the current results; they are not reclassified as unperformed future experiments.

## Broader framework evaluation

The paper's architecture provides a place for capabilities beyond this initial implementation. Future work can evaluate real O-RAN interfaces and radio-stack integration, multi-agent coordination, learned threat detection, LLM/RAG proposal generation, secure operational memory, continuous learning and organizational governance. Each extension needs its own threat model, evaluation protocol and claim boundary.

The larger confirmatory packet study should increase scenario diversity and independent replication, freeze its protocol before measurement, and preserve all outcomes. The initial PoC already supports the separation of permission, corroboration and effectiveness; broader claims should build on that evidence through additional tests.
