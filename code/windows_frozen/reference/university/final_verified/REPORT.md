# v0.2 evaluation synthesis

Status: **COMPLETE_WITH_REPORTED_FINDINGS**.

This is a compact-summary synthesis, not an independent raw-observation recomputation.

## Policy and dataset evidence

- validity: 777 constructed cases; status COMPLETED; gateway decision disagreements 0, reason disagreements 0, unhandled errors 0.
- netslab: 20000 constructed cases; status COMPLETED; gateway decision disagreements 0, reason disagreements 0, unhandled errors 0.
- census/record_proposals: 733693 case occurrences; 33 normalized meaningful configurations; gateway reference agreement {"denominator":733693,"numerator":733693,"rate":1.0}; required-block admissions 0/0.
- panels/conformance: 95000 case occurrences; 162 normalized meaningful configurations; gateway reference agreement {"denominator":95000,"numerator":95000,"rate":1.0}; required-block admissions 0/75000.
- panels/false_alarm_probes: 5000 case occurrences; 1 normalized meaningful configurations; gateway reference agreement {"denominator":5000,"numerator":5000,"rate":1.0}; required-block admissions 0/0.
  Benign disruptive admission (limitation, not safe-action success): {"denominator":5000,"numerator":5000,"rate":1.0}.

Alternative thresholds are reported separately in analysis.json; all configured conditions are retained.

## Local timing and scaling

Values below are means of block p50/p95 values in microseconds; they are not pooled request percentiles.

| Dataset | Mode | Boundary/path | State | Method | Blocks | Mean block p50 (µs) | Mean block p95 (µs) |
|---|---|---|---:|---|---:|---:|---:|
| 5gnidd | micro | evaluator_component | None | contract | 20 | 11.410 | 15.935 |
| 5gnidd | micro | evaluator_component | None | contract_rbac | 20 | 12.025 | 17.205 |
| 5gnidd | micro | evaluator_component | None | direct | 20 | 0.790 | 1.110 |
| 5gnidd | micro | evaluator_component | None | trust_boundary | 20 | 47.135 | 77.375 |
| 5gnidd | micro | matched_local_processing_with_buffered_event_logging | None | contract | 20 | 22.520 | 33.436 |
| 5gnidd | micro | matched_local_processing_with_buffered_event_logging | None | contract_rbac | 20 | 24.080 | 35.437 |
| 5gnidd | micro | matched_local_processing_with_buffered_event_logging | None | direct | 20 | 8.960 | 13.020 |
| 5gnidd | micro | matched_local_processing_with_buffered_event_logging | None | trust_boundary | 20 | 64.167 | 106.246 |
| netslab | micro | evaluator_component | None | contract | 20 | 12.545 | 19.226 |
| netslab | micro | evaluator_component | None | contract_rbac | 20 | 13.445 | 20.185 |
| netslab | micro | evaluator_component | None | direct | 20 | 0.835 | 1.275 |
| netslab | micro | evaluator_component | None | trust_boundary | 20 | 54.302 | 101.667 |
| netslab | micro | matched_local_processing_with_buffered_event_logging | None | contract | 20 | 24.585 | 39.861 |
| netslab | micro | matched_local_processing_with_buffered_event_logging | None | contract_rbac | 20 | 25.570 | 37.867 |
| netslab | micro | matched_local_processing_with_buffered_event_logging | None | direct | 20 | 9.320 | 14.530 |
| netslab | micro | matched_local_processing_with_buffered_event_logging | None | trust_boundary | 20 | 72.580 | 127.515 |
| 5gnidd | scaling | no_conflict | 0 | trust_boundary | 5 | 46.430 | 95.616 |
| 5gnidd | scaling | no_conflict; large input | 0 | trust_boundary | 5 | 67.310 | 157.015 |
| 5gnidd | scaling | conflict_first | 1 | trust_boundary | 5 | 63.430 | 118.196 |
| 5gnidd | scaling | conflict_last | 1 | trust_boundary | 5 | 63.210 | 122.840 |
| 5gnidd | scaling | malformed_last | 1 | trust_boundary | 5 | 53.380 | 100.556 |
| 5gnidd | scaling | no_conflict | 1 | trust_boundary | 5 | 61.370 | 108.791 |
| 5gnidd | scaling | conflict_first | 10 | trust_boundary | 5 | 63.490 | 118.861 |
| 5gnidd | scaling | conflict_last | 10 | trust_boundary | 5 | 170.110 | 335.650 |
| 5gnidd | scaling | malformed_last | 10 | trust_boundary | 5 | 168.120 | 343.051 |
| 5gnidd | scaling | no_conflict | 10 | trust_boundary | 5 | 170.400 | 325.811 |
| 5gnidd | scaling | conflict_first | 100 | trust_boundary | 5 | 62.770 | 133.114 |
| 5gnidd | scaling | conflict_last | 100 | trust_boundary | 5 | 1217.600 | 1979.875 |
| 5gnidd | scaling | malformed_last | 100 | trust_boundary | 5 | 1249.610 | 2056.594 |
| 5gnidd | scaling | no_conflict | 100 | trust_boundary | 5 | 1232.870 | 2106.708 |
| 5gnidd | scaling | conflict_first | 1000 | trust_boundary | 5 | 61.670 | 102.444 |
| 5gnidd | scaling | conflict_last | 1000 | trust_boundary | 5 | 14894.590 | 21017.230 |
| 5gnidd | scaling | malformed_last | 1000 | trust_boundary | 5 | 14658.500 | 20385.643 |
| 5gnidd | scaling | no_conflict | 1000 | trust_boundary | 5 | 13521.290 | 19006.342 |
| netslab | scaling | no_conflict | 0 | trust_boundary | 5 | 57.040 | 94.814 |
| netslab | scaling | no_conflict; large input | 0 | trust_boundary | 5 | 87.840 | 139.929 |
| netslab | scaling | conflict_first | 1 | trust_boundary | 5 | 73.600 | 112.247 |
| netslab | scaling | conflict_last | 1 | trust_boundary | 5 | 74.960 | 123.741 |
| netslab | scaling | malformed_last | 1 | trust_boundary | 5 | 66.570 | 108.416 |
| netslab | scaling | no_conflict | 1 | trust_boundary | 5 | 71.260 | 110.325 |
| netslab | scaling | conflict_first | 10 | trust_boundary | 5 | 73.980 | 118.880 |
| netslab | scaling | conflict_last | 10 | trust_boundary | 5 | 177.390 | 305.264 |
| netslab | scaling | malformed_last | 10 | trust_boundary | 5 | 170.080 | 288.158 |
| netslab | scaling | no_conflict | 10 | trust_boundary | 5 | 173.780 | 277.489 |
| netslab | scaling | conflict_first | 100 | trust_boundary | 5 | 72.910 | 113.919 |
| netslab | scaling | conflict_last | 100 | trust_boundary | 5 | 1193.340 | 1861.555 |
| netslab | scaling | malformed_last | 100 | trust_boundary | 5 | 1193.870 | 1979.844 |
| netslab | scaling | no_conflict | 100 | trust_boundary | 5 | 1186.920 | 1934.623 |
| netslab | scaling | conflict_first | 1000 | trust_boundary | 5 | 78.610 | 168.985 |
| netslab | scaling | conflict_last | 1000 | trust_boundary | 5 | 18004.820 | 21796.000 |
| netslab | scaling | malformed_last | 1000 | trust_boundary | 5 | 18008.830 | 20935.510 |
| netslab | scaling | no_conflict | 1000 | trust_boundary | 5 | 16698.000 | 19366.519 |

Existing paired process-block bootstrap intervals (B3−B0 and B3−B2), all scaling methods, separate resource runs and per-seed load outcomes are retained in analysis.json.

## Offered load

| Dataset | Method | Rate/s | Seed | Completed/offered | Overflow/offered | Censored/offered | Generator-limited |
|---|---|---:|---:|---:|---:|---:|---|
| netslab | direct | 100 | 4000 | 6000/6000 | 0/6000 | 0/6000 | False |
| netslab | trust_boundary | 100 | 4000 | 6000/6000 | 0/6000 | 0/6000 | False |
| netslab | direct | 100 | 4001 | 6000/6000 | 0/6000 | 0/6000 | False |
| netslab | trust_boundary | 100 | 4001 | 6000/6000 | 0/6000 | 0/6000 | False |
| netslab | direct | 100 | 4002 | 6000/6000 | 0/6000 | 0/6000 | False |
| netslab | trust_boundary | 100 | 4002 | 6000/6000 | 0/6000 | 0/6000 | False |
| netslab | trust_boundary | 100 | 4003 | 6000/6000 | 0/6000 | 0/6000 | False |
| netslab | direct | 100 | 4003 | 6000/6000 | 0/6000 | 0/6000 | False |
| netslab | direct | 100 | 4004 | 6000/6000 | 0/6000 | 0/6000 | False |
| netslab | trust_boundary | 100 | 4004 | 6000/6000 | 0/6000 | 0/6000 | False |
| netslab | direct | 1000 | 4000 | 60000/60000 | 0/60000 | 0/60000 | False |
| netslab | trust_boundary | 1000 | 4000 | 40286/60000 | 19714/60000 | 0/60000 | False |
| netslab | direct | 1000 | 4001 | 60000/60000 | 0/60000 | 0/60000 | False |
| netslab | trust_boundary | 1000 | 4001 | 44915/60000 | 15085/60000 | 0/60000 | False |
| netslab | direct | 1000 | 4002 | 60000/60000 | 0/60000 | 0/60000 | False |
| netslab | trust_boundary | 1000 | 4002 | 31166/60000 | 28834/60000 | 0/60000 | True |
| netslab | trust_boundary | 1000 | 4003 | 45144/60000 | 14856/60000 | 0/60000 | False |
| netslab | direct | 1000 | 4003 | 60000/60000 | 0/60000 | 0/60000 | False |
| netslab | direct | 1000 | 4004 | 60000/60000 | 0/60000 | 0/60000 | False |
| netslab | trust_boundary | 1000 | 4004 | 39468/60000 | 20532/60000 | 0/60000 | False |
| netslab | direct | 5000 | 4000 | 300000/300000 | 0/300000 | 0/300000 | False |
| netslab | trust_boundary | 5000 | 4000 | 46012/300000 | 253988/300000 | 0/300000 | False |
| netslab | direct | 5000 | 4001 | 300000/300000 | 0/300000 | 0/300000 | False |
| netslab | trust_boundary | 5000 | 4001 | 38115/300000 | 261885/300000 | 0/300000 | False |
| netslab | direct | 5000 | 4002 | 300000/300000 | 0/300000 | 0/300000 | True |
| netslab | trust_boundary | 5000 | 4002 | 44250/300000 | 255750/300000 | 0/300000 | False |
| netslab | trust_boundary | 5000 | 4003 | 43454/300000 | 256546/300000 | 0/300000 | False |
| netslab | direct | 5000 | 4003 | 300000/300000 | 0/300000 | 0/300000 | False |
| netslab | direct | 5000 | 4004 | 300000/300000 | 0/300000 | 0/300000 | False |
| netslab | trust_boundary | 5000 | 4004 | 43899/300000 | 256101/300000 | 0/300000 | False |
| 5gnidd | direct | 100 | 4000 | 6000/6000 | 0/6000 | 0/6000 | False |
| 5gnidd | trust_boundary | 100 | 4000 | 6000/6000 | 0/6000 | 0/6000 | False |
| 5gnidd | direct | 100 | 4001 | 6000/6000 | 0/6000 | 0/6000 | False |
| 5gnidd | trust_boundary | 100 | 4001 | 6000/6000 | 0/6000 | 0/6000 | False |
| 5gnidd | direct | 100 | 4002 | 6000/6000 | 0/6000 | 0/6000 | False |
| 5gnidd | trust_boundary | 100 | 4002 | 6000/6000 | 0/6000 | 0/6000 | False |
| 5gnidd | trust_boundary | 100 | 4003 | 6000/6000 | 0/6000 | 0/6000 | False |
| 5gnidd | direct | 100 | 4003 | 6000/6000 | 0/6000 | 0/6000 | False |
| 5gnidd | direct | 100 | 4004 | 6000/6000 | 0/6000 | 0/6000 | False |
| 5gnidd | trust_boundary | 100 | 4004 | 6000/6000 | 0/6000 | 0/6000 | False |
| 5gnidd | direct | 1000 | 4000 | 60000/60000 | 0/60000 | 0/60000 | False |
| 5gnidd | trust_boundary | 1000 | 4000 | 37136/60000 | 22864/60000 | 0/60000 | False |
| 5gnidd | direct | 1000 | 4001 | 60000/60000 | 0/60000 | 0/60000 | False |
| 5gnidd | trust_boundary | 1000 | 4001 | 34136/60000 | 25864/60000 | 0/60000 | False |
| 5gnidd | direct | 1000 | 4002 | 60000/60000 | 0/60000 | 0/60000 | False |
| 5gnidd | trust_boundary | 1000 | 4002 | 44102/60000 | 15898/60000 | 0/60000 | False |
| 5gnidd | trust_boundary | 1000 | 4003 | 44029/60000 | 15971/60000 | 0/60000 | False |
| 5gnidd | direct | 1000 | 4003 | 60000/60000 | 0/60000 | 0/60000 | False |
| 5gnidd | direct | 1000 | 4004 | 60000/60000 | 0/60000 | 0/60000 | False |
| 5gnidd | trust_boundary | 1000 | 4004 | 41890/60000 | 18110/60000 | 0/60000 | False |
| 5gnidd | direct | 5000 | 4000 | 300000/300000 | 0/300000 | 0/300000 | False |
| 5gnidd | trust_boundary | 5000 | 4000 | 48365/300000 | 251635/300000 | 0/300000 | False |
| 5gnidd | direct | 5000 | 4001 | 300000/300000 | 0/300000 | 0/300000 | False |
| 5gnidd | trust_boundary | 5000 | 4001 | 42885/300000 | 257115/300000 | 0/300000 | False |
| 5gnidd | direct | 5000 | 4002 | 300000/300000 | 0/300000 | 0/300000 | False |
| 5gnidd | trust_boundary | 5000 | 4002 | 48155/300000 | 251845/300000 | 0/300000 | False |
| 5gnidd | trust_boundary | 5000 | 4003 | 37818/300000 | 262182/300000 | 0/300000 | False |
| 5gnidd | direct | 5000 | 4003 | 300000/300000 | 0/300000 | 0/300000 | False |
| 5gnidd | direct | 5000 | 4004 | 300000/300000 | 0/300000 | 0/300000 | False |
| 5gnidd | trust_boundary | 5000 | 4004 | 46685/300000 | 253315/300000 | 0/300000 | False |

## Interpretation limits

- Policy conformance under illustrative operator assumptions is not incident truth, mitigation necessity or operational safety.
- Constructed variants, overlapping source panels and repeated calls are not independent safety trials; no safety-probability confidence interval is inferred.
- The census contains only eligible Benign/ICMPFlood/SYNFlood/UDPFlood records; unsupported labels and zero/undefined attack packet rates remain excluded.
- All control identities, slices, authorities and state are simulated. No learned detector, LLM planner, live E2/A1 integration or radio service outcome is validated.
- Natural proposals and controlled violations remain separate. Zero required-block denominators are null, not successful blocking evidence.
- False-alarm admissions remain a limitation group, not safe-action successes. Audit checksums are not signatures or evidence authentication.
- Timing is local host/workload evidence. Buffered event logging is not durable persistence; there is no hard-real-time or production-capacity claim.
- Process-block percentile means are not pooled request percentiles; paired differences of percentiles are not percentiles of per-request overhead.
- Load latency percentiles describe completed requests only. Overflow and right-censored requests remain in all-offered denominators; generator-limited conditions are retained.
- This report hashes and checks compact summaries/receipts only. It does not reread or independently recompute raw CSV/JSONL observations.

## Selection and provenance

Selected revised performance partitions: 18/18. Excluded directories: 35; all remain untouched.

See analysis.json for the exact selected/excluded run index and manifest.json for SHA-256 hashes of every consumed compact summary, receipt, source snapshot and protocol file. Earlier complete performance, pilots, diagnostics and incomplete attempts are not pooled into final estimates.
