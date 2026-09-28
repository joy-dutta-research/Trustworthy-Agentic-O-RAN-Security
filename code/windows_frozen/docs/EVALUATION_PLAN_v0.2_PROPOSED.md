# Proposed evaluation plan: validity, robustness and feasibility

Date: 2026-09-23. Status: PROPOSED; NOT EXECUTED.

This document is the ordered plan requested by the authors. It does not change
the existing implementation, frozen protocols, results or portable VM bundle.
Each stage will be authorized and executed separately. Numerical run budgets
below are predeclared engineering choices, not statistical power guarantees.

## 1. What the study should establish

| Question | Operational meaning | Main evidence |
| --- | --- | --- |
| Validity | Does the implemented gateway allow, deny and escalate as the declared policy requires? | Independent expected-outcome specification, rule/interaction tests, comparative ablations. |
| Robustness | Does that behavior hold across varied inputs, source selections, boundaries and adverse control conditions? | Full eligible 5G-NIDD coverage, seeded sensitivity, generated control cases, boundary and fault tests. |
| Computational feasibility | How much local latency and resource cost does the gateway add, and under what load can it keep up? | Matched bypass comparison, repeated-process timing, active-state scaling and offered-load tests. |
| Limited operational feasibility | Do evidence checks and feedback improve service/intervention outcomes in an isolated software network? | Separately qualified Ubuntu packet experiment. |

These are bounded claims about the implemented trust boundary and reference
controller. They do not validate a learned detector, LLM planning, production
identity services, actual E2/A1 integration, radio-slice protection, or the entire
reference architecture. Passing tests is not proof of universal safety.

## 2. Existing evidence remains separate

- Original NetsLab/governance suite: 120 fixed cases, with all rows of the
  45,244-row selected lower-layer database aggregated for incident context.
  This is not 120 randomly sampled real incidents.
- 5G-NIDD: all 1,215,890 source rows audited, but only 100 records selected for
  the original action evaluation; its 475 conformance proposals, 100 natural
  proposals and 25 forced false-alarm probes remain separate groups.
- The seed in those runs controls timing order, not data sampling.
- The returned model reviews cover the original 120 cases only. They are
  model-assisted consistency review, not independent human ground truth.
- Existing boundary/adversarial unit tests are useful evidence, but not a
  completed systematic robustness campaign.

Do not overwrite, merge away or retrospectively relabel these results.

## 3. Comparison methods

Retain the four existing methods for policy and component-speed comparisons:

1. B0: bypass the trust layer; forward every proposal.
2. B1: action-contract validation only.
3. B2: contract plus authenticated-principal/role and interface authorization.
4. B3: full trust boundary, including its existing in-memory policy audit record.

These are controlled ablations, not competing IDS algorithms. B0 is deliberately
an unsafe lower bound, so the B3-versus-B2 comparison is also essential.
Natural record-derived proposals and controlled policy violations must never
be pooled into one headline safety score.

## 4. Execution order

### Stage 0 — Freeze the questions, policy and expected outcomes

Before new comparative runs:

- Preserve v0.1 and inventory source, dataset, policy and result hashes.
- Write a separate declarative decision table covering the six supported
  actions, each policy rule, and DENY-before-ESCALATE precedence. Do not call
  production engine helpers to generate the expected answers.
- Authors adjudicate policy ambiguities already raised by the reviewers,
  especially the scope of rollback_policy on protected services. Operator
  assumptions remain explicitly illustrative, not standards requirements.
- If a semantic change is approved, create a separately identified policy/core
  version, document the change, and apply it consistently to both sources.
  The default is to test existing v0.1 semantics without silent correction.
- Freeze generators, seeds, workload mixes, metrics, exclusions, resource
  bounds, expected-outcome rules and analysis before measurement.
- Add a new results namespace. Any engineering pilot is marked PILOT and kept
  separate from the frozen evaluation.

Deliverable: a reviewed protocol and claim-to-test matrix. No API key or VM is
needed. A policy judgment cannot be replaced by model agreement alone.

### Stage 1 — Systematic policy validity and test sensitivity

Run a common governance suite once; associate relevant cases with each dataset
without counting identical tests twice as independent evidence.

Cover all six implemented actions, not only the four in the original 120-case
suite. Exercise valid requests, malformed input and state, identity/role
binding, action/interface/target semantics, protected services, parameter and
time limits, risk floors, rollback declarations, conflict state and approvals.

For every applicable numeric/time limit test below, exactly at, and above the
boundary. Use adjacent representable values where appropriate. For example,
test 79%, 80% and 81% under an 80% maximum. Ensure other conditions are valid
so that an unrelated failure does not mask the boundary being examined.

Generate constrained pairwise coverage of the declared policy factors and
targeted three-way coverage for authorization × protected target × approval,
age × TTL × approval expiry, and conflict × parameter violation × approval.
Record achieved coverage and impossible combinations. Pairwise coverage is
not a claim that higher-order faults cannot occur.

Expand property tests: removing required authority must not grant admission;
an applicable protected-target violation must never ALLOW; a changed proposal
must not reuse an old approval; contract-equivalent key ordering must not alter
the decision. Scope every property carefully to the actual policy.

Add test-only mutation checks: remove or invert individual safeguards in an
isolated copy and verify that the suite detects each targeted defect. Include
precedence and approval-binding faults. Never mutate the frozen release in
place. A surviving mutation is a reported test-coverage gap.

Metrics: decision agreement; policy-block-required admissions; compliant-action
acceptance; correct denial/escalation; required reason-code and audit-field
coverage; unhandled errors; rule/interaction coverage; targeted mutations
detected. Count configurations as constructed tests, not real-world incidents.

Exit criterion: no unexplained mismatch against the independently specified
policy. Preserve failures; fixes require a new version and full regression.

### Stage 2 — Broaden dataset coverage and test sample sensitivity

#### 2A. 5G-NIDD: full eligible-record evaluation

Use unchanged eligibility and proposal-generation rules. The existing audit
gives these expected counts, which the new reader must independently reconcile:

| Label | Eligible unique records |
| --- | ---: |
| Benign | 477,716 |
| ICMPFlood | 1,154 |
| SYNFlood | 8,394 |
| UDPFlood | 246,429 |
| Total | 733,693 |

Generate the natural, unclipped proposal for every eligible record and evaluate
once with each of B0–B3: 2,934,772 comparator decisions if the counts reconcile.
Do not attach 25 or 100 timing repetitions to this census.

Stream compact results; do not hold millions of audit dictionaries in RAM.
Retain reproducible source locators, hashes, proposal parameters, decisions,
reasons and analysis provenance without publishing raw network identifiers.
Report all exclusions and unsupported labels; this is not evaluation of the
entire dataset or of independent capture sessions.

Report per-label outcomes, source-record counts, and distinct decision-relevant
proposal configurations. Many records produce equivalent action requests;
record volume is not equivalent to policy-condition diversity.

Purpose: remove dependence on one small sample within this eligible release.
It cannot remove uncertainty about other networks or omitted classes.

#### 2B. 5G-NIDD: explicit multi-seed sensitivity

- Use data-sampling seeds 0–19.
- Select nested panels of 25, 100 and 250 records per label per seed.
- Rank canonical records using a versioned, seeded SHA-256 construction;
  use the first 250, with prefixes for the smaller panels.
- Obtain natural-proposal metrics from the census results. Repeating their
  deterministic evaluation is unnecessary.
- For each largest panel, run the controlled conformance variants once:
  750 attack records × six variants + 250 benign notifications = 4,750
  proposals/seed, 95,000 proposals across 20 seeds.
- Keep 250 forced benign-mitigation probes per seed in a separate limitation
  group: 5,000 proposals, never counted as successful safe-action acceptance.

Report each seed, each class, macro and eligible-release-weighted results,
minimum/maximum across seeds, unique-record union and overlap. Seeds are not
independent populations. Sampling sensitivity is secondary to the census;
it reveals how much the original 25/class result depended on source selection.

#### 2C. NetsLab: control-input robustness, not cosmetic row resampling

Retain exhaustive aggregation of the selected lower-layer database. Its
telemetry does not currently determine a gateway-inspected action parameter;
therefore resampling telemetry rows alone is not a robustness experiment.

Keep the ten NetsLab-label bases and ten separately identified standards/
governance bases. Use control-generation seeds 1000–1019, with 50 variants per
base per seed: 10 compliant, 20 single-rule and 20 two-/three-rule violation
cases. This is 1,000 proposals/seed, or 20,000 generated proposals.

Vary actual checked inputs: authorized identity/role, interface, target,
protected slice, parameter, risk, relative request time, TTL, rollback,
approval binding/status and active conflicts. Legitimate approval fixtures
must be regenerated for their exact changed proposal digests. Systematic
boundaries from Stage 1 are additional, not left to chance.

Report category and action coverage, every seed and deduplicated meaningful
configurations. Changing only labels/IDs must not inflate semantic coverage.
Describe this as control-input robustness under dataset/standards contexts,
not telemetry generalization or additional authentic incident ground truth.

### Stage 3 — Assumption sensitivity and negative controls

Use the frozen Stage 2 generated suites and the largest 5G-NIDD panels. Keep
the primary original-policy results separate from all sensitivity results.

Vary one assumption at a time:

- Maximum rate reduction: 60%, 80%, 90% (80% is the original value).
- Maximum allowed TTL: 300, 600, 900 seconds (900 is the original maximum).
- 5G-NIDD illustrative upstream packet budget: 500, 1,000, 2,000 packets/s
  (1,000 is the original value; these are not measured network capacities).

The declarative reference must evaluate each alternative policy correctly.
Admission rates are expected to change; robustness means correct behavior
under the declared setting, not identical outcomes under different policies.
Never select the most favorable threshold as the headline result afterward.

Retain benign disruptive proposals, missing/unverifiable state, approval
tampering and stale requests as separately reported adverse conditions.
Distinguish a field's presence from verification of incident truth: the
current gateway cannot authenticate evidence content simply because an
evidence reference exists.

Metrics: per-policy decision outcomes, incorrect admissions/rejections,
false-alarm admission, and cases with no valid denominator. Show limitations
and unchanged failures rather than promising every stress test will pass.

### Stage 4 — Measure speed with and without the trust layer fairly

Run both frozen source-associated workload families separately. Report
results by action and expected path (allow, deny, escalate, malformed,
conflict), plus a predeclared workload-weighted summary. The constructed mix
does not represent natural operational frequencies.

Replay each timing/load case at its declared logical evaluation time, identically
across methods. Do not let real elapsed benchmark time silently expire requests
or approvals and change the decision-path mix. If rebasing time is necessary,
rebase all related timestamps and regenerate digest-bound approval fixtures
coherently. Wall-clock expiry remains a separate lifecycle/VM test; this timing
control is not a proposed production clock behavior.

Measure two explicitly named boundaries:

1. Component: the evaluator call, as in the original benchmark, including
   full-gateway contract parsing and policy audit construction where present.
2. Local processing path: identical raw-JSON decoding, context delivery,
   response serialization and common event logging around each method.
   B3 retains its extra policy-specific audit work; this is a legitimate cost,
   not something to hide or add artificially to the bypass.

Common event logging will use the same buffered write policy in every method.
Call it buffered, not durable. Disk persistence, network identity/approval
services, detection, planning and actuation must not be implied by the
component number. Durable logging would need a separate explicitly defined
flush/fsync and storage experiment if such a claim is later required.

Concrete schedule: 20 fresh-process paired blocks, timing-order seeds
2000–2019; 1,000 warm-up requests and 10,000 measured requests per method,
source workload and boundary in each block. Freeze the exact case mix and
warm-up design after a separate instrumentation-only engineering pilot.
Use randomized method and case order, run serially, document normal host
conditions, and retain slow runs. No disabling security controls or changing
power/CPU settings without separate permission.

Report p50, p95 and p99; absolute added time in microseconds; slowdown ratio
secondarily; and paired block-level variability. The main comparisons are
B3−B0 and B3−B2. A difference between two p95 values is not the p95 of an
incremental per-request latency distribution. Do not describe the inverse
of mean evaluator time as measured request-serving capacity.

Use 95% bootstrap intervals for paired process-block statistics, resampling
whole blocks rather than individual repeated calls. These describe variability
under the measured host/workload, not hard real-time guarantees. Retain timing
resolution and an empty-harness calibration; do not silently subtract noisy
measurements or average away instrumentation overhead.

### Stage 5 — Scaling, offered load and resource feasibility

#### 5A. Active-state scaling

The present conflict check scans and reparses active actions. Test state
sizes 0, 1, 10, 100 and 1,000, using unique valid entries and these paths:
no conflict, conflict first, conflict last, and malformed final entry.
Combinations impossible at zero state are explicitly not applicable.

Measure all four methods on both workload families. Use 5 fresh-process
runs/cell, 100 warm-up and 1,000 measured requests/run, timing-order seeds
3000–3004. Report p50/p95, decision outcomes and sample counts. Do not promote
this smaller sample to an extreme-tail guarantee. Measure peak memory in
separate matched runs so allocation tracing does not contaminate latency.
Add typical-versus-near-contract-limit input-size checks without inventing
illegal fields in a supposedly valid large payload.

This reveals algorithmic bottlenecks; an unfavorable result must remain visible.
If a cell reaches a predeclared runtime/memory bound, retain it as incomplete
or resource-limited, not as a pass. Bounds are frozen in Stage 0 after the
instrumentation pilot, before comparative runs.

#### 5B. Scheduled offered-load experiment

This needs a new local, bounded worker/queue harness; it is not already measured.

- Compare matched-envelope B0 and B3 on both source-associated workload families.
- Use one evaluator worker and 100 valid nonconflicting active entries.
- Offer 100, 1,000 and 5,000 action proposals/s, not packets/s.
- Use 5 fresh-process runs/condition, seeds 4000–4004, a 10-second warm-up,
  60-second measurement and a maximum 30-second drain.
- Cap the queue at 1,000 requests. Count overflow, timeout and unfinished
  requests; never silently remove them from the denominator.
- Use identical scheduled arrivals and proposals for each paired comparison.
  The producer must not wait for a response before scheduling the next arrival.

Timestamp scheduled arrival, actual enqueue, service start and completion.
Report offered/admitted/completed rates, generator lateness, queueing and
completion latency, drops/timeouts, maximum backlog, CPU seconds and peak
process RSS. Separately report decision errors among completed evaluations.
If the producer cannot achieve the schedule, label the condition generator-
limited rather than interpreting it as gateway capacity.

Result: a measured local operating envelope. There is no pre-assumed requirement
to sustain 5,000/s. Deadline summaries at 1, 10 and 100 ms may be shown only as
illustrative sensitivity, not standards or operator SLAs. Do not interpolate a
maximum sustainable rate from three points as if it had been measured.

Stages 0–5 can run locally on Windows without generating network attack
traffic, creating a VM, acquiring administrator privileges or using a model API.
Large runs must stream outputs and obey bounded process/memory/disk budgets.

### Stage 6 — Isolated Ubuntu closed-loop evaluation

This is a separate network-outcome experiment, not raw replay of either dataset.
Do not label namespace traffic as operational O-RAN or manufacture UE mappings.

First qualify the isolated VM and execute the already prepared pilot:
3 scenarios × 4 methods × 3 repetitions = 36 episodes. Scenarios are persistent
flood, transient benign burst and acknowledged-but-ineffective actuation.
Methods are no action, fixed-rule intervention, existing gateway, and gateway
plus evidence corroboration and outcome feedback.

Measure legitimate deadline delivery/goodput, delay with loss, suspect traffic,
unnecessary restrictions, intervention/restore timing and failures. Existing
fixed-rule/gateway similarity is expected for policy-compliant proposals.
The no-op actuator scenario tests ineffectiveness detection, not reversal of
an actually harmful action.

The existing runner is pilot-only. After qualification, use measured variability
to specify a separate confirmatory design: meaningful workload-intensity and
duration variation, fresh paired episodes, a declared precision target,
repetition count and failure/censoring rules. Freeze these before final runs.
Do not invent a statistically justified episode count before seeing technical
pilot variability; do not stop final runs when results become favorable.
The current seed changes order only, not traffic distribution.

This stage requires owner/IT-approved VM setup and guest privileges. Keep the
VM isolated, rates bounded and cleanup scoped to owned laboratory resources.
Any revised harness requires a new portable bundle; preserve the existing v1
ZIP and its hash rather than overwriting it.

### Stage 7 — Clean reproduction and paper-ready evidence

- Reproduce correctness and key timing/load conditions on the home machine or
  another clean environment. Deterministic decisions should agree; timing need
  not. Report machines separately.
- Preserve failures, missing cases and technical exclusions. Finish author
  policy/standards verification and public-artifact privacy review.
- Freeze code, configuration, inputs, environment and analysis identifiers.
  Record seeds by purpose (source selection, control generation, timing order,
  arrival schedule); do not call all of them independent data seeds.
- Prepare code, download/verification instructions, deterministic generators,
  expected-outcome specification, manifests, compact raw decisions, timings,
  analysis and reports. Do not upload anything automatically or include secrets.

Suggested result organization (new, not created by this plan):

```text
results/evaluation_v0.2/<run-id>/
  protocol/        # versioned design, policy, seed lists, expected-outcome rules
  manifests/       # source/dataset/workload/environment hashes
  validity/        # fixed rules, boundaries, interactions, mutation results
  netslab/         # generated control cases and per-seed decisions
  5gnidd/          # census, selections, conformance, false alarms, exclusions
  sensitivity/    # separately labelled alternative illustrative policies
  performance/    # raw component/local-path timing blocks
  load/           # arrival/completion/resource logs and incomplete runs
  reproduction/   # per-environment comparisons
  figures/
  REPORT.md
```

## 5. How to analyze and present the evidence

- Policy validity: report exact counts and coverage. Zero observed violations
  is not an estimated universal zero-failure probability.
- Census: describe the eligible release, with all excluded records/classes.
- Seeds: report descriptive stability and overlap. Do not compute confidence
  intervals as though overlapping panels or six variants were independent.
- Timing/load: use independent process runs as analysis blocks, paired across
  methods; report absolute differences and tails, not only relative speed.
- VM: use paired episodes, not packets or telemetry windows, as experimental
  units. Keep outcome failure distinct from technical invalidity.
- No hypothesis-test fishing or best-seed selection. Additional experiments
  motivated by observed failures receive new protocol/version identifiers.

For an approximately one-page main-text addition, prioritize one compact
validity/robustness table and a two-panel cost-versus-state/load figure. Keep
seed-level tables and engineering details in supplementary material/repository.
VM effectiveness may need extra space or a separate compact panel; do not
force all scope and limitations into an unreadably dense page.

The intended takeaway, conditional on measured results, is:

> The implemented trust boundary enforces the declared action policy over the
> evaluated input space, with measured computational cost and a reported local
> workload envelope. Evidence corroboration and feedback are evaluated separately
> for service outcomes in an isolated software-network experiment.

Do not prewrite positive numbers or claim complete-framework validation.

## 6. What is needed from the authors

1. Agreement on this study scope and staged execution.
2. Approval/adjudication of policy semantics, protected-service assumptions and
   illustrative thresholds; an actual latency/load requirement if one exists.
3. An idle measurement window on the present computer. No OpenAI API key is
   required for this deterministic evaluation.
4. An approved isolated Ubuntu VM for Stage 6 and a clean second environment
   for Stage 7. Dataset and code files already available need not be re-uploaded.

## 7. Methodological basis and local evidence

The interaction-testing design follows the principle that combinations of
inputs must be tested, not just individual rules; pairwise coverage alone is
not universal assurance. See [NIST: Combinatorial Testing](https://www.nist.gov/publications/combinatorial-testing).

Fresh processes, warm-ups and preserved raw timing distributions follow the
benchmarking principles described in [pyperf's run architecture](https://pyperf.readthedocs.io/en/latest/run_benchmark.html)
and [analysis guidance](https://pyperf.readthedocs.io/en/latest/analyze.html).
This plan does not require installing pyperf or changing system settings.

Scheduled-arrival latency avoids hiding delay when a load generator slows
with its target. See the primary [wrk2 measurement explanation](https://github.com/giltene/wrk2).
We use that measurement principle, not its HTTP tool for this Python gateway.

Local evidence reviewed: docs/experiment_protocol.md, docs/5gnidd_protocol.md,
docs/assurance_case.md, docs/closed_loop_protocol.md, docs/EXPERIMENT_CONTEXT.md,
configs/paper_policy.json, the existing adapters, case generators, benchmark,
engine and baselines, and results/5gnidd_v0.1_verified/REPORT.md.
