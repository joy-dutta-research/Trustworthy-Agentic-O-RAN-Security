# Model-review results

These tables are recomputed from the preserved first responses and the released post-review crosswalks. No model is called by this analysis.

| Measure | Reviewer A | Reviewer B |
| --- | ---: | ---: |
| Complete unique responses | 120 | 120 |
| Reference matches | 120 | 120 |
| Ambiguity flags | 0 | 0 |
| Decisions with explicit rule references | 120 | 80 |
| Decisions without explicit rule references | 0 | 40 |
| ALLOW | 20 | 20 |
| DENY | 60 | 60 |
| ESCALATE | 40 | 40 |
| INSUFFICIENT_INFORMATION | 0 | 0 |

Pairwise decision agreement: **120/120**. Cohen's kappa among jointly decided cases: **1.0**.

The two reviews agree on the stated policy decisions. Explicit rule citations remain an opportunity to improve explanation traceability: Reviewer B left 40 such fields empty (20 ALLOW and 20 conflict-related ESCALATE cases), while supplying a rationale for every case. The supplied schema permits empty rule-reference arrays.

The useful contribution is a separately recorded check that the written policy can be interpreted consistently. The open-ended critiques also identify concrete next steps for target mapping, policy maintenance and cumulative-action controls. See [the interpretation](INTERPRETATION.md) before citing these descriptive results.

These are 120 constructed cases, including related variants, not independent incidents. The review does not measure detector accuracy, model effectiveness in the controller, or operational safety. Displayed model/mode identities and service-enforced blinding were not independently verified. All original critiques remain available.
