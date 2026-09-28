# Stage 1: policy validity

The full Trust Boundary agreed with the reference decision for all 777 constructed cases and admitted none of the 647 proposals that required blocking. All four methods admitted all 130 reference-permitted proposals. This demonstrates the value of the complete policy check over the simpler baselines within the declared test design.

| File | How to read it |
|---|---|
| `method_comparison.csv` / `.json` | One row per method; admitted/total counts retain their denominators. |
| `scoped_properties.csv` / `.json` | 25 checks on selected valid-action witnesses; not universal proofs. |
| `targeted_mutations.csv` / `.json` | All 14 predefined test-only code mutations were detected. |
| `stratified_results.csv` / `.json` | The original group/action strata, without adding them into a second overall total. |
| `coverage.json` | Case groups, 669 distinct semantic configurations and declared interaction coverage. |

**What we learn.** This supports Safe Action Verification at the Trust Boundary. Reference-policy agreement is not detector accuracy or proof that every permitted action is operationally safe. The 130 permitted cases include 12 legacy-limitation probes. We retain the frozen policy's protected-service restriction gap for `rollback_policy` so the comparison remains consistent. A separately versioned correction is a next step, not a change made retrospectively to these results.

| Method | Agreement / 777 | Block-required admitted / 647 | Permitted admitted / 130 |
|---|---|---|---|
| Direct | 130 | 647 | 130 |
| Contract | 172 | 605 | 130 |
| Contract + RBAC | 362 | 415 | 130 |
| Full Trust Boundary | 777 | 0 | 130 |

[Column meanings and units](DATA_DICTIONARY.md)

[Results guide](../README.md) · [Previous stage](../00_overview/README.md) · [Next stage](../02_dataset_robustness/README.md)
