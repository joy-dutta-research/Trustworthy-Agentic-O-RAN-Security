# Stage 3: assumption sensitivity

We use 12 predefined conditions to show how the prototype responds to different operator choices. All sensitivity summaries matched between Workstation 1 and Workstation 2. Tighter NetsLab reduction/TTL limits change some decisions, while the tested 5G-NIDD budget settings change proposal payloads without changing decisions. This makes the role of policy assumptions visible and reproducible.

`assumption_changes.csv` / `.json` compares each condition with the frozen primary setting on its fixed inputs. Changes count case occurrences, not independent incidents. `all_method_results.csv` / `.json` retains every method, group and denominator under all 12 conditions, including zero changes. JSON contains the same values in nested form.

These are illustrative operator thresholds, not requirements attributed to a standard. The next policy study can test additional choices against operational requirements while preserving this version as the baseline.

| Condition | Cases | Decision changes | Reason changes | Proposal changes |
|---|---|---|---|---|
| sensitivity:netslab:original | 20000 | 0 | 0 | 0 |
| sensitivity:netslab:reduction60 | 20000 | 326 | 1216 | 0 |
| sensitivity:netslab:reduction90 | 20000 | 0 | 0 | 0 |
| sensitivity:netslab:ttl300 | 20000 | 4112 | 13852 | 0 |
| sensitivity:netslab:ttl600 | 20000 | 2055 | 8009 | 0 |
| sensitivity:nidd:budget2000 | 120000 | 0 | 0 | 8100 |
| sensitivity:nidd:budget500 | 120000 | 0 | 0 | 29964 |
| sensitivity:nidd:original | 120000 | 0 | 0 | 0 |
| sensitivity:nidd:reduction60 | 120000 | 0 | 0 | 0 |
| sensitivity:nidd:reduction90 | 120000 | 0 | 0 | 0 |
| sensitivity:nidd:ttl300 | 120000 | 0 | 0 | 0 |
| sensitivity:nidd:ttl600 | 120000 | 0 | 0 | 0 |

[Column meanings and units](DATA_DICTIONARY.md)

[Results guide](../README.md) · [Previous stage](../02_dataset_robustness/README.md) · [Next stage](../04_processing_cost/README.md)
