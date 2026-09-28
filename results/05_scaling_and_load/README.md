# Stage 5: state scaling and offered load

The experiments identify the prototype's operating envelope and the most useful engineering priorities. Every offered request completed at 100 proposals/s. Increasing state and offered load shows where indexing, scheduling and admission control will be valuable.

The full gate's queue **overflowed at 1,000 and 5,000 proposals/s**. All full-gate cells at those two rates had zero all-offered success within the illustrative 10-ms deadline. These are measured outcomes, retained alongside the successful low-rate case. They are not production-capacity results. Direct execution completed every offered request at all three tested rates.

Load means **action proposals/s, not network packets/s**: one consumer, 100 fixed nonconflicting actions, queue capacity 1,000, 10-s warm-up, 60-s offering and up to 30-s drain. Completion includes drain and is not a steady-state throughput estimate. Completed-only latency excludes dropped requests, so read it beside completion/overflow/deadline fractions. We retain and flag two generator-limited Workstation 1 cells.

`state_and_input_scaling` contains all 576 host-specific conditions, including conflict-first, conflict-last, malformed-last, near-limit input and resource-only runs. Timing is µs in those source columns; the selected no-conflict table below converts p95 to ms. Resource-only cells have no timing statistic rather than a fabricated zero. `load_by_seed` retains all 120 cells and their counts, 1/10/100-ms deadlines, timing components and resource records. `load_summary` averages five seeds per host/dataset/method/rate; min/max are observed ranges, **not confidence intervals**. `scaling_paired_block_comparisons` contains our recorded within-host bootstrap summaries, not new statistical tests. The raw host keys remain `university` for Workstation 1 and `workstation` for Workstation 2.

## Full-gate ordinary-input state scan

| Host | Dataset | Active actions | Mean block-p95 ms |
|---|---|---|---|
| Workstation 1 | 5G-NIDD | 0 | 0.096 |
| Workstation 1 | 5G-NIDD | 1 | 0.109 |
| Workstation 1 | 5G-NIDD | 10 | 0.326 |
| Workstation 1 | 5G-NIDD | 100 | 2.107 |
| Workstation 1 | 5G-NIDD | 1000 | 19.006 |
| Workstation 1 | NetsLab | 0 | 0.095 |
| Workstation 1 | NetsLab | 1 | 0.110 |
| Workstation 1 | NetsLab | 10 | 0.277 |
| Workstation 1 | NetsLab | 100 | 1.935 |
| Workstation 1 | NetsLab | 1000 | 19.367 |
| Workstation 2 | 5G-NIDD | 0 | 0.054 |
| Workstation 2 | 5G-NIDD | 1 | 0.073 |
| Workstation 2 | 5G-NIDD | 10 | 0.204 |
| Workstation 2 | 5G-NIDD | 100 | 1.429 |
| Workstation 2 | 5G-NIDD | 1000 | 13.288 |
| Workstation 2 | NetsLab | 0 | 0.091 |
| Workstation 2 | NetsLab | 1 | 0.109 |
| Workstation 2 | NetsLab | 10 | 0.230 |
| Workstation 2 | NetsLab | 100 | 1.463 |
| Workstation 2 | NetsLab | 1000 | 14.995 |

## Offered-load completion

| Host | Dataset | Method | Proposals/s | Complete % mean | Min % | Max % | Within 10 ms % |
|---|---|---|---|---|---|---|---|
| Workstation 1 | 5G-NIDD | Direct | 100 | 100.000 | 100.000 | 100.000 | 99.933 |
| Workstation 1 | 5G-NIDD | Direct | 1000 | 100.000 | 100.000 | 100.000 | 99.916 |
| Workstation 1 | 5G-NIDD | Direct | 5000 | 100.000 | 100.000 | 100.000 | 99.983 |
| Workstation 1 | 5G-NIDD | Full Trust Boundary | 100 | 100.000 | 100.000 | 100.000 | 99.857 |
| Workstation 1 | 5G-NIDD | Full Trust Boundary | 1000 | 67.098 | 56.893 | 73.503 | 0.000 |
| Workstation 1 | 5G-NIDD | Full Trust Boundary | 5000 | 14.927 | 12.606 | 16.122 | 0.000 |
| Workstation 1 | NetsLab | Direct | 100 | 100.000 | 100.000 | 100.000 | 99.987 |
| Workstation 1 | NetsLab | Direct | 1000 | 100.000 | 100.000 | 100.000 | 99.970 |
| Workstation 1 | NetsLab | Direct | 5000 | 100.000 | 100.000 | 100.000 | 99.982 |
| Workstation 1 | NetsLab | Full Trust Boundary | 100 | 100.000 | 100.000 | 100.000 | 99.957 |
| Workstation 1 | NetsLab | Full Trust Boundary | 1000 | 66.993 | 51.943 | 75.240 | 0.000 |
| Workstation 1 | NetsLab | Full Trust Boundary | 5000 | 14.382 | 12.705 | 15.337 | 0.000 |
| Workstation 2 | 5G-NIDD | Direct | 100 | 100.000 | 100.000 | 100.000 | 100.000 |
| Workstation 2 | 5G-NIDD | Direct | 1000 | 100.000 | 100.000 | 100.000 | 99.989 |
| Workstation 2 | 5G-NIDD | Direct | 5000 | 100.000 | 100.000 | 100.000 | 99.987 |
| Workstation 2 | 5G-NIDD | Full Trust Boundary | 100 | 100.000 | 100.000 | 100.000 | 99.990 |
| Workstation 2 | 5G-NIDD | Full Trust Boundary | 1000 | 68.850 | 65.022 | 71.073 | 0.000 |
| Workstation 2 | 5G-NIDD | Full Trust Boundary | 5000 | 12.902 | 11.230 | 13.688 | 0.000 |
| Workstation 2 | NetsLab | Direct | 100 | 100.000 | 100.000 | 100.000 | 100.000 |
| Workstation 2 | NetsLab | Direct | 1000 | 100.000 | 100.000 | 100.000 | 100.000 |
| Workstation 2 | NetsLab | Direct | 5000 | 100.000 | 100.000 | 100.000 | 99.994 |
| Workstation 2 | NetsLab | Full Trust Boundary | 100 | 100.000 | 100.000 | 100.000 | 100.000 |
| Workstation 2 | NetsLab | Full Trust Boundary | 1000 | 76.118 | 74.437 | 78.152 | 0.000 |
| Workstation 2 | NetsLab | Full Trust Boundary | 5000 | 14.986 | 14.614 | 15.189 | 0.000 |

[Column meanings and units](DATA_DICTIONARY.md)

[Results guide](../README.md) · [Previous stage](../04_processing_cost/README.md) · [Next stage](../06_packet_feedback/README.md)
