# Completed Windows evaluation: what the paper can now claim

Date: 2026-09-23. Orders 0–5 are complete. Original policy v0.1 is unchanged.
The Ubuntu packet-level experiment and a clean second-machine reproduction
have not been completed by this evaluation.

## Main conclusion in easy words

The implemented trust layer consistently enforced the policy we gave it in
the tested cases. It adds a small processing cost for small action/state
workloads, but the cost grows with existing-action state. It processed the
lowest tested request rate without loss; the two higher rates overloaded this
single-worker prototype. Permission to act is still not proof that an action
is necessary or beneficial.

This supports **policy-conformance validity, robustness within the declared
test space, and bounded local computational feasibility**. It does not
validate the complete agentic O-RAN security architecture or universal safety.

## What was completed

| Order | Evidence | What it establishes—and what it does not |
|---|---|---|
| 0 | Frozen v0.1 policy, original-artifact inventory, separate declarative reference, seeds and protocols; 128 baseline files unchanged | Traceable comparison. Authors still must verify the reference table and operator assumptions. |
| 1 | 777 constructed cases; 669 normalized configurations; all 1,346 feasible declared pair assignments and 128 targeted three-way assignments covered; 14/14 targeted mutations detected; 25/25 scoped property witnesses passed | The suite detects the deliberately tested faults and matches the declared policy. Not exhaustive verification of every possible interaction. |
| 2, NetsLab | 20 control-generation seeds; 20,000 constructed proposals; 19,945 normalized configurations | Input/control robustness in dataset and standards contexts—not 20,000 independent real incidents or resampled telemetry trials. |
| 2, 5G-NIDD | All 1,215,890 source rows reconciled; all 733,693 eligible unique records evaluated; 20 controlled panels | Greater source coverage plus controlled policy testing. Unsupported records remain excluded under the frozen rules. |
| 3 | All 12 declared one-factor-at-a-time conditions completed without gateway-reference, reason or audit disagreements | Sensitivity was measured; settings that did not cross a decision boundary are explicitly uninformative about that boundary. |
| 4 | 20 paired process blocks per dataset; four comparators and two timing boundaries; 320 cells | Repeated local latency comparison, including block-level uncertainty. Not detector, LLM or network end-to-end timing. |
| 5 | Five state sizes, multiple state paths and separate resource runs; 1,440 scaling cells; 60 load cells across two datasets, three rates and five paired blocks | State-dependent cost, queue overflow, scheduling limitations and a tested operating range on this host. Not production capacity certification. |

The final selection contains 18 performance partitions and 1,820 cells.
All are complete; no gateway reference disagreements were reported.
The six load conditions offered 7,320,000 measurement requests in total,
excluding warm-up. Repeated calls are not independent security trials.

## Validity and robustness results

| Suite | Policy-block-required proposals admitted by full gateway | Policy-permitted proposals admitted |
|---|---:|---:|
| Common validity | 0 / 647 | 130 / 130 |
| NetsLab controlled proposals, 20 seeds | 0 / 16,000 | 4,000 / 4,000 |
| 5G-NIDD controlled conformance, 20 seeds | 0 / 75,000 | 20,000 / 20,000 |

The contract-plus-RBAC comparator admitted 9,606/16,000 of the NetsLab
block-required proposals and 60,000/75,000 of the 5G-NIDD block-required
proposals. These are controlled ablations on deliberately constructed
violations, not real-world unsafe-action prevalence estimates.

Important qualifications:

- The 130 common-suite permissions include **12 admitted legacy-limitation
  probes**. Do not rename all permitted actions “safe actions.”
- All 733,693 natural 5G-NIDD proposals were permitted by all four methods.
  They reduce to **33 normalized configurations** and contain no
  block-required denominator. Their blocking rate is **not applicable**,
  not evidence of superior blocking or zero real-world risk.
- The 95,000 controlled 5G-NIDD proposals reduce to **162 configurations**.
  Source panels overlap: the largest panels contain 20,000 record occurrences
  but 14,831 unique records. Seeds are not independent datasets.
- All **5,000 forced benign false-alarm mitigation probes were admitted** by
  every comparator. This separate group has one normalized configuration.
  It demonstrates that policy permission alone does not establish necessity.
- All seven 5G-NIDD sensitivity conditions changed zero decisions. Packet
  budgets changed 29,964 or 8,100 proposal payloads, but not decisions.
  NetsLab reduction60 changed 326 decisions, TTL300 changed 4,112 and TTL600
  changed 2,055; reduction90 changed none. Do not describe inactive settings
  as newly exercised decision boundaries.
- No independent-trial safety confidence interval is inferred from these
  repeated/constructed counts. The timing intervals below concern process
  blocks, not a probability of security failure.

## How fast is it compared with no trust layer?

Matched local processing, including buffered event logging; mean of the
20 paired process-block p95 differences. Units are microseconds (µs).

| Workload | Full gateway block-p95 mean | Bypass block-p95 mean | Added versus bypass, 95% block-bootstrap interval | Added versus contract + RBAC, 95% interval |
|---|---:|---:|---:|---:|
| NetsLab | 127.515 | 14.530 | 112.984 [108.913, 117.972] | 89.648 [85.514, 94.765] |
| 5G-NIDD | 106.246 | 13.020 | 93.225 [90.386, 96.345] | 70.808 [67.986, 73.781] |

Thus the added block-p95 difference is approximately **0.113 ms / 0.093 ms**.
These are differences of block percentiles, not the p95 of per-request added
time. Bootstrap: 2,500 draws, analysis seed 9000. The workload is a declared
balanced mixture of allow, deny, escalate, malformed and conflict paths;
NetsLab and 5G-NIDD have different action mixes. Logging is buffered, not
durable storage. Small-workload timing cannot be extrapolated to large state.

### Existing-action state matters

Full-gateway evaluator-component timing, no-conflict path, ordinary payload;
mean block p95 in **milliseconds**, five process blocks per point.

| Existing actions | NetsLab | 5G-NIDD |
|---:|---:|---:|
| 0 | 0.095 | 0.096 |
| 1 | 0.110 | 0.109 |
| 10 | 0.277 | 0.326 |
| 100 | 1.935 | 2.107 |
| 1,000 | 19.367 | 19.006 |

Conflict-first, conflict-last, malformed-last and near-limit input conditions
are retained separately in the detailed report. The state position matters;
a fast early-conflict result must not substitute for a full-state scan.

### Offered-load limits matter

One consumer, 100 fixed nonconflicting existing actions, queue capacity 1,000;
10 seconds warm-up, 60 seconds measured offering and at most 30 seconds drain.
Rates are **action proposals/second, not network packets/second**. Each row
uses all five process blocks; ranges are observed seed minima/maxima, not CIs.

| Offered rate/s | NetsLab gateway completed/offered, mean [range] | 5G-NIDD gateway completed/offered, mean [range] | Bypass, both datasets |
|---:|---:|---:|---:|
| 100 | 100% [100, 100] | 100% [100, 100] | 100% |
| 1,000 | 66.993% [51.943, 75.240] | 67.098% [56.893, 73.503] | 100% |
| 5,000 | 14.382% [12.705, 15.337] | 14.927% [12.606, 16.122] | 100% |

All non-completions in these final runs were queue overflows; no admitted
measurement requests remained right-censored at the drain bound. Completion
can include drain time, so these fractions are not steady-state capacity.
Two NetsLab cells were generator-limited and remain included and flagged:
trust_boundary at 1,000/s, seed4002; direct at 5,000/s, seed4002. All other
final load cells were unflagged. Host background activity was not controlled
or certified absent.

At 100/s, mean block p95 scheduled-arrival-to-completion latency was
**3.118 ms versus 0.923 ms** for NetsLab, and **3.006 ms versus 0.903 ms** for
5G-NIDD (gateway versus bypass). Under overload, gateway completion p95 rose
to roughly 1.66–1.92 seconds on average across blocks. Such completion-only
latencies must always be shown with overflow fractions. Deadlines of
1/10/100 ms are illustrative measurements, not standards-mandated SLAs.

Maximum observed gateway consumer peak RSS across load cells was about
37.1 MiB. The workload generator and supervisor have their own memory costs;
there is no claim that this is total system memory. CPU/RSS observations and
all per-seed metrics are retained in analysis.json.

## Unchanged policy limitations and outstanding work

The user explicitly chose to preserve v0.1. `rollback_policy` is not
categorized as disruptive: the protected-service and rollback-declaration
restrictions therefore do not apply to it. Existing-action expiry/authority
are not reauthorized, and same-action-ID state is skipped. A shaped evidence
pointer is not authenticated evidence; an audit checksum is not a signature
or an immutable log. The independent declarative reference is not an
independent human-expert validation.

Still required before broad/publication claims:

1. **Ubuntu closed-loop experiment:** measure actual intervention effect,
   protected/background service impact, false-positive harm and rollback in
   an isolated software network. It still would not establish real-radio
   O-RAN interoperability or production safety.
2. **Author review:** approve the reference decision table, illustrative
   thresholds, protected-service assumptions and all standards locators.
3. **Clean second-machine reproduction and public-release review:** verify
   setup, licensing and privacy; inspect diagnostics for private local paths.
   No commit, upload or publication was performed here.

## Suggested compact manuscript wording

> We evaluate a deterministic implementation of the proposed action-admission
> boundary, not the entire agentic security pipeline. The original policy is
> frozen and checked against a separately implemented declarative reference.
> Across 20 control-generation seeds for NetsLab and 20 controlled 5G-NIDD
> panels, the gateway admitted none of 16,000 and 75,000 policy-block-required
> proposals, respectively, while admitting all policy-permitted proposals.
> A common 777-case suite covered the declared feasible pairwise interactions
> and detected all 14 targeted test mutations. A census of 733,693 eligible
> 5G-NIDD records provides source coverage, but all natural proposals were
> permitted and map to only 33 normalized configurations; it is not blocking-
> superiority evidence. Twenty paired timing blocks yielded mean added
> block-p95 local-processing differences of 113 and 93 µs versus bypass.
> Feasibility is conditional: with 100 existing actions, both workloads
> completed all requests at 100 proposals/s, but only approximately 67% at
> 1,000/s and 14–15% at 5,000/s in the single-worker load experiment. At 1,000
> existing actions, no-conflict evaluator p95 averaged approximately 19 ms.
> All overload observations and scheduler-limited blocks are retained.
> Finally, all 5,000 separately constructed benign-mitigation probes were
> admitted, demonstrating that policy conformance does not establish
> mitigation necessity or benefit. These results support bounded governance
> correctness and computational feasibility, while motivating separate
> closed-loop network-outcome validation.

## Evidence and reproducibility

- [Complete numerical report](../results/evaluation_v0.2/final_verified_20260923/REPORT.md)
- [Machine-readable analysis](../results/evaluation_v0.2/final_verified_20260923/analysis.json)
- [Hashes of consumed summaries and receipts](../results/evaluation_v0.2/final_verified_20260923/manifest.json)
- [Independent 12-cell raw load accounting spot-check](../results/evaluation_v0.2/raw_spot_audit/REPORT.md)
- [Execution and reproduction notes](EVALUATION_v0.2_EXECUTION.md)
- [Monitor correction and superseded-run selection rule](../results/evaluation_v0.2/monitor_revision_protocol/ADDENDUM.md)

The synthesis verifies compact summaries, receipts and source snapshots; it
does not independently recompute every raw observation. Earlier performance
runs, pilots and failed attempts remain preserved and excluded from the
primary revised estimates. Their exclusion was fixed before revised runs,
not selected for favorable timings.

The separate raw spot-check passed for both methods in block0 of all six
load conditions: 12/60 cells, 1,708,000 arrival rows and 1,069,564 completion
rows including warm-up. It verifies accounting and recorded timing/deadline
consistency, not all latency percentiles or real-network outcomes.
