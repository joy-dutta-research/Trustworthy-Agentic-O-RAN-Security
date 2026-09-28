# Stage 7: reproducibility and what to repeat next

The frozen policy/dataset summaries and all 12 sensitivity summaries agree between Workstation 1 and Workstation 2. All 42 regenerated case files, containing 120,777 constructed cases, match our frozen inputs byte for byte. Both benchmark workloads also match. The NetsLab aggregate agrees as parsed JSON; its serialized bytes differ, so we do not describe every regenerated artifact as byte-identical.

We repeated the same 36-job packet protocol in a separately installed clean VM on Workstation 2. Its findings agree in direction: flood benefit, avoidance of the tested benign restriction with corroboration, and recognition of the no-op's lack of benefit. This establishes **same-hardware clean-environment repeatability**, not replication on a second packet-test physical host. Windows timings and packet outcomes are reported separately rather than pooled.

`cross_host_fixed_output_checks` contains the exact fixed-summary comparisons. `regenerated_case_identity` lists the 42 case-file hashes and counts without historical machine paths. `regeneration_summary.json` distinguishes parsed equality from byte equality and preserves packet source/return identities. The result exporter checks aggregate structure and packet arithmetic, but does not reread every raw Windows timing observation or rerun gateway decisions. Hash verification demonstrates identity, not scientific improvement.

## Lessons retained with the successful runs

Developmental v3/v4 packet attempts were incomplete and are not mixed with the 36-episode result sets. The v4 logs establish UDP send timeouts as the immediate failure; the underlying kernel/socket cause was not conclusively reproduced. Later diagnostics motivated a versioned permanent-neighbor setup applied consistently across methods. The successful comparative episodes used the repaired v7 protocol. Qualification ran at 10,000 kbit/s, whereas the comparative pilot used 1,000 kbit/s; qualification is therefore not a capacity validation of the final study condition.

## Next study

Our completed initial PoC provides a reproducible baseline for a larger confirmatory study: more paired episodes, additional independent physical hosts, realistic radio/control integration, broader benign/attack patterns, recovery from harmful actions, and state/load engineering. These next steps extend the measured scope; they do not replace the mixed outcomes already reported in Stages 2, 5 and 6. We retain operator thresholds, policy semantics and standards locators as explicit review items in the release checklist.

[Column meanings and units](DATA_DICTIONARY.md)

[Results guide](../README.md) · [Previous stage](../06_packet_feedback/README.md)
