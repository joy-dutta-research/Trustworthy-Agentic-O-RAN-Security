# Independent raw load spot audit

Status: **PASS**.

12-cell spot audit: block 0, both methods, both datasets, three rates; not a full 60-cell raw audit.

Selection was fixed by block number and job metadata, not observed outcomes. The script reads preserved raw files and never runs the gateway or traffic experiment.

| Dataset | Rate/s | Method | Scheduled | Admitted | Overflow | Completed by drain | Unfinished | Late | Result |
|---|---:|---|---:|---:|---:|---:|---:|---:|---|
| 5gnidd | 1000 | direct | 60000 | 60000 | 0 | 60000 | 0 | 0 | PASS |
| 5gnidd | 1000 | trust_boundary | 60000 | 37136 | 22864 | 37136 | 0 | 0 | PASS |
| 5gnidd | 100 | direct | 6000 | 6000 | 0 | 6000 | 0 | 0 | PASS |
| 5gnidd | 100 | trust_boundary | 6000 | 6000 | 0 | 6000 | 0 | 0 | PASS |
| 5gnidd | 5000 | direct | 300000 | 300000 | 0 | 300000 | 0 | 0 | PASS |
| 5gnidd | 5000 | trust_boundary | 300000 | 48365 | 251635 | 48365 | 0 | 0 | PASS |
| netslab | 1000 | direct | 60000 | 60000 | 0 | 60000 | 0 | 0 | PASS |
| netslab | 1000 | trust_boundary | 60000 | 40286 | 19714 | 40286 | 0 | 0 | PASS |
| netslab | 100 | direct | 6000 | 6000 | 0 | 6000 | 0 | 0 | PASS |
| netslab | 100 | trust_boundary | 6000 | 6000 | 0 | 6000 | 0 | 0 | PASS |
| netslab | 5000 | direct | 300000 | 300000 | 0 | 300000 | 0 | 0 | PASS |
| netslab | 5000 | trust_boundary | 300000 | 46012 | 253988 | 46012 | 0 | 0 | PASS |

Also reconciled request identities/timestamps, reference-agreement flags, scheduled-origin deadline counts, trace outstanding-work high-water, and producer-lateness diagnostics. Raw-file SHA-256 values are retained in audit.json.

This supports reporting/accounting consistency for the selected 12 cells. It is not a full raw-data audit, a repeated experiment, a latency-percentile audit, or validation of real-network safety.
