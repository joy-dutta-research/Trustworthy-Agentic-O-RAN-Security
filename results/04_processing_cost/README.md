# Stage 4: local processing cost

The low-state measurements quantify the cost of applying the Trust Boundary. They support feasibility for the tested local verification path while showing the extra work required by the safeguards. Read Stage 5 before drawing a capacity conclusion.

Values below are **microseconds (µs), means of 20 process-block percentiles**. They are not percentiles pooled over all requests. Each microbenchmark uses 1,000 warm-up and 10,000 measured requests per method/block. Workstation 1 and Workstation 2 are separate physical computers; hardware, scheduling and power conditions prevent a causal CPU-only comparison. In the unchanged CSV/JSON files, `university` means Workstation 1 and `workstation` means Workstation 2.

The component boundary times the evaluator. The matched boundary includes matched local processing with **buffered** event logging. Neither includes LLM inference, network/actuator latency, radio response, remote audit durability, initialization or final log flush. Workstation 2 is not uniformly faster; compare p50 and p95 separately.

`microbenchmarks.csv` / `.json` retains all 32 host-specific cells, p50/p95/p99, block ranges, request counts and process-resource measurements. CPU includes instrumentation. `micro_paired_block_comparisons` retains our recorded bootstrap summaries: differences of matched process-block percentile statistics, not percentiles of per-request overhead. `absolute_added_ns` is nanoseconds; `slowdown_ratio` is unitless. These existing within-host intervals are not a new cross-host significance test.

| Dataset | Boundary | Method | Workstation 1 p50 µs | Workstation 2 p50 µs | Workstation 1 p95 µs | Workstation 2 p95 µs |
|---|---|---|---|---|---|---|
| 5G-NIDD | Component | Direct | 0.790 | 0.895 | 1.110 | 1.125 |
| 5G-NIDD | Component | Contract | 11.410 | 13.095 | 15.935 | 16.510 |
| 5G-NIDD | Component | Contract + RBAC | 12.025 | 13.995 | 17.205 | 18.025 |
| 5G-NIDD | Component | Full Trust Boundary | 47.135 | 51.585 | 77.375 | 72.791 |
| 5G-NIDD | Matched | Direct | 8.960 | 10.150 | 13.020 | 13.645 |
| 5G-NIDD | Matched | Contract | 22.520 | 25.848 | 33.436 | 33.646 |
| 5G-NIDD | Matched | Contract + RBAC | 24.080 | 27.573 | 35.437 | 35.505 |
| 5G-NIDD | Matched | Full Trust Boundary | 64.167 | 69.975 | 106.246 | 96.196 |
| NetsLab | Component | Direct | 0.835 | 0.895 | 1.275 | 1.235 |
| NetsLab | Component | Contract | 12.545 | 13.790 | 19.226 | 20.130 |
| NetsLab | Component | Contract + RBAC | 13.445 | 15.165 | 20.185 | 22.525 |
| NetsLab | Component | Full Trust Boundary | 54.302 | 57.848 | 101.667 | 101.481 |
| NetsLab | Matched | Direct | 9.320 | 10.195 | 14.530 | 14.795 |
| NetsLab | Matched | Contract | 24.585 | 26.415 | 39.861 | 37.275 |
| NetsLab | Matched | Contract + RBAC | 25.570 | 28.185 | 37.867 | 40.301 |
| NetsLab | Matched | Full Trust Boundary | 72.580 | 76.862 | 127.515 | 125.237 |

[Column meanings and units](DATA_DICTIONARY.md)

[Results guide](../README.md) · [Previous stage](../03_sensitivity/README.md) · [Next stage](../05_scaling_and_load/README.md)
