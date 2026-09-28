# Closed-loop packet-level experiment protocol

## Status and scope

**NOT RUN. No measured packet-level results or comparative benefit are available.**
The current Windows host does not provide a usable Linux network-namespace
runtime: WSL is absent and the Docker daemon is stopped. No live model
credentials have been supplied. Unit tests, static validation, configuration
generation, and successful construction of a harness must not be described as
successful execution of this experiment.

This protocol specifies a small **Linux packet-level network-emulation
experiment**. It is not a discrete-event simulation, a live O-RAN deployment,
or a detection-accuracy benchmark. It complements, rather than replaces, the
completed policy-conformance experiments. Their code, policies, and results
remain separate and unchanged.

The initial experiment uses a **deterministic reference proposal controller**.
It does not evaluate an LLM, autonomous reasoning quality, RAG retrieval, or
the full multi-agent architecture. Its question is narrower:

> Under controlled offered traffic and injected faults, what do evidence
> corroboration and post-action feedback add to pre-action policy checking?

The experiment has not yet established any improvement. An equivalent or
better result for conventional automation is an admissible outcome.

## Physical experiment boundary

Implementation entry point: `scripts/run_closed_loop.py`; frozen *pilot*
configuration: `configs/closed_loop_pilot.json`. `--preflight` is read-only and
checks platform/root/tool availability, not kernel support or experimental
validity. `--execute-isolated-lab` is required for any namespace actuation.

Create four uniquely named, isolated Linux network namespaces:

- a legitimate UDP client;
- a suspect UDP client;
- a router;
- a UDP echo server.

Use virtual Ethernet links and explicitly scoped private lab routes between
these namespaces. There must be **no external link, host bridge, NAT, DNS
dependency, or default route**. Do not attach the lab to a RIC, SMO, CU, DU, UE,
public interface, or production network. Namespace names, interfaces, ports,
addresses, and process ownership must be recorded in the run manifest.

A kernel-managed shared `netem` bottleneck on the router supplies a bounded
queue and service capacity. The actuator changes a scoped ingress policer for
the suspect source. Limiting suspect traffic therefore changes actual packet
forwarding through the shared bottleneck; it does not directly set an outcome
metric. Collect packet receipts and echo timings independently of the
controller and actuator logs.

The existing gateway's `E2`/`UE` proposal vocabulary may be mapped to synthetic
lab targets by a documented adapter. Such a mapping is **not E2 signaling,
an E2 service-model implementation, UE radio control, or O-RAN interoperability
validation**. Report the evaluated actuator as a Linux ingress policer.

Before a measured run, verify topology isolation, baseline connectivity,
bottleneck placement, policer placement, configuration readback, and scoped
cleanup in a disposable Linux environment. Configuration intent alone does
not establish that the kernel enforced the intended rate or queue.

## Compared methods

All methods receive the same scheduled offered traffic and the same type of
observable telemetry. The reference proposal controller and its settings are
held constant where a proposal is used.

| Identifier | Behavior | Question |
| --- | --- | --- |
| `no_action` | Observe and record; perform no mitigation. | What happens without intervention? |
| `fixed_rule` | A frozen deterministic alert-to-cap rule applies the bounded lab action without the policy gateway. | What does conventional automation achieve? |
| `current_gate` | Submit the same reference proposal to the existing pre-action gateway before the bounded lab action. | What does pre-action policy checking alone achieve? |
| `evidence_feedback` | Add fresh, target-linked corroboration before authorization and observe service after execution, with rollback or escalation when conditions require it. | What do evidence and outcome checks add? |

Basic laboratory containment, maximum action lifetime, bounded traffic,
process timeouts, and final cleanup apply to **every method**. They are not
exclusive advantages of `evidence_feedback`. Only that method uses measured
post-action benefit or worsening to decide an early rollback. Record natural
expiry separately from feedback-triggered rollback.

Do not insert different favorable proposals into the full method or provide it
with hidden information unavailable to the other methods. Its extra logic is
the ablated intervention, not a different workload or privileged ground truth.
If its extra corroboration or observation delays response, count that delay in
the outcome.

## Scenarios and ground truth

The workload generator and offline scorer know the scenario. Neither the
proposal controller nor evidence evaluator may read the scenario name, true
attack label, expected action, injected-fault flag, or future workload schedule.
They receive only bounded observations available at that point in the episode.

### Persistent flood

A bounded suspect source sustains offered load sufficient to stress the shared
bottleneck while legitimate requests continue. Assess legitimate delivery,
goodput and response delay before and after intervention. Measure suspect load
at the receiver as well as offered traffic; limiter configuration is not proof
that load was reduced.

### Transient benign burst / false alert

The suspect source is legitimate in this scenario. A brief burst triggers the
reference alert condition, but may subside before sufficiently persistent
corroboration is available. Count every restriction of that legitimate source
and its lost delivery, as well as effects on the protected client.

This is a deliberately constructed negative control. Success would show
suppression of the tested transient alarm, not general discrimination between
benign and malicious traffic. A legitimate sustained surge can satisfy the
same rate and service-impairment conditions as a flood. Incident truth is not
proved by corroboration, authentic provenance, or two consecutive windows.

### Injected ineffective action

With sustained overload present, the fault-injection layer acknowledges an
action without changing its forwarding configuration. This acknowledged
no-op is isolated to the laboratory actuator and hidden from the controller.
The monitoring logic must judge the observed service outcome rather than
treating the acknowledgment as evidence of mitigation success.

Record whether lack of benefit triggers rollback and escalation, the delay,
and the readback of the restored configuration. **A no-op does not by itself
demonstrate reversal of an actually harmful configuration change.** It tests
ineffective-action detection and the restoration path. A stronger claim about
reversing harm requires an additional separately specified adverse-but-bounded
configuration-change test.

## Evidence and feedback rules

Before intervention, `evidence_feedback` requires target-linked observations
that meet the frozen freshness limit and show both suspect-rate excess and
legitimate-delivery impairment in two consecutive windows. Window width,
required completeness, rate threshold, impairment threshold, clock basis,
and baseline definition belong in versioned configuration. Document whether
the corroborating measurements share a collector; do not call correlated
measurements independent evidence.

Evidence must be bound to the actual lab target and observation interval.
Missing, stale, malformed, incomplete, or mismatched evidence cannot authorize
an action. A filename, in-band assertion, or arbitrary `evidence_refs` string is
not such verification. This layer is additional to the unchanged current
gateway, whose evidence references provide traceability rather than incident
verification.

Before applying an allowed action, save the exact previous scoped actuator
configuration and record its identity. Recheck freshness and target binding
at execution. After execution, observe legitimate delivery over the frozen
assessment interval. On insufficient improvement or worsening, request
rollback, verify restoration by readback, and escalate. Record attempted,
acknowledged, verified, failed, and timed-out operations separately. The system
must never label an unverified acknowledgment as successful restoration.

In this initial implementation the prior actuator state must be an absent
ingress limiter in a newly created topology; arbitrary pre-existing policies
are not supported. An early restoration stops further intervention and records
`operator_review_required` locally. It does not contact an operator or implement
a human approval/escalation service. At most one intervention is applied per
episode. Normal expiry can therefore restore unmitigated load while a flood
persists; this limitation must remain visible in the timeline and outcomes.

Use monotonic time for local deadlines and durations; record UTC timestamps
for provenance. Cap the number of actions and transitions per episode. Define
what happens when telemetry or rollback fails and terminate safely rather than
retrying without a bound. Action expiry restores the previous scoped state for
all methods. Final cleanup is mandatory even when an earlier step fails.

Post-action improvement can coincide with a traffic change and is not alone a
causal estimate. Paired method comparisons and the no-action condition provide
the counterfactual evidence available in this controlled setting.

## Metrics and denominators

Primary service outcomes are measured over preregistered episode intervals,
including intervention waiting time; do not score only a favorable interval
after recovery.

| Metric | Definition and reporting requirement |
| --- | --- |
| Legitimate delivery ratio | Unique legitimate requests echoed successfully within the scoring deadline divided by legitimate requests actually offered. Report counts, duplicates and late receipts separately. |
| Legitimate goodput | Successfully delivered legitimate application payload bytes per scoring second; exclude duplicate payloads. |
| Legitimate RTT p95 | 95th percentile of matched successful request/echo durations. Always report delivery and timeout counts alongside it: dropping slow requests can otherwise improve apparent latency. |
| Suspect received load | Unique suspect payload bytes received per second. Report offered load too, and distinguish attack traffic from legitimate burst traffic in offline scoring only. |
| Interventions | Proposed, authorized, applied, acknowledged-no-effect and verified actions; include target, time, duration, and decision reason. |
| Unnecessary restrictions | Actions and restricted time affecting the benign suspect source in the negative control; also show its delivered load. |
| Rollback delay | Time from the declared feedback trigger to verified restoration, and time from action acknowledgment to that trigger. Report both clocks, success/failure counts, expiry and censoring. |
| Failures | Setup, traffic generation, telemetry, authorization, execution, restoration and cleanup failures, with reasons and denominators. |

The implemented online and primary offline service metric is delivery of each
send cohort within **500 ms**, not replies received in the same wall-clock
window. Online observations mature 500 ms after window end; final logs retain
all later replies during a fixed two-second drain, with loss/deadline misses
kept in the denominator. The main event interval is [4,14) seconds in the
initial configuration. The comparison table's suspect metric is **echoed
payload goodput at the client** over that interval, not direct server ingress.
Independent server receive counters are cross-checked against client accounting
and reported separately over the whole offered episode, including drain
receipts. Do not conflate their intervals or denominators.

Offered-load validation checks both whole-episode and every send-window count
against the integrated planned schedule: at least 90% of scheduled sends, at
most 102%, with one-packet rounding tolerance per window. This is a pilot
technical acceptance bound, not a learned detector threshold. Send/receive
accounting errors abort the run; packet loss and lack of mitigation benefit
are outcomes, never technical exclusions. Per-window checks prevent a missed
short burst from being hidden by an acceptable whole-episode average.

Do not identify recovery solely from a configured policer rate. If reporting
recovery time, freeze the service threshold, sustained-window requirement and
maximum observation time before the final run; include non-recoveries and
right-censored observations rather than dropping them.

## Pairing, freezing, and analysis

1. Use development/pilot seeds to establish that traffic, collection and
   isolation behave as intended. Pilot measurements are not confirmatory
   results, and must be stored separately.
2. Freeze source, configuration, thresholds, generator schedule, traffic bounds,
   method definitions, metrics, exclusion rules, statistical procedure and
   held-out seed list before comparative evaluation. Record their hashes.
3. Use a newly created topology for each episode. Within each scenario/seed
   block, use the same offered-load schedule across methods and randomize
   execution order. Run episodes serially unless independence from host
   contention has been demonstrated.
4. Repeat independent episodes, with repetition count justified by the pilot
   variability and practical precision target. A convenient repetition count
   is exploratory, not an automatic power calculation or assurance guarantee.
5. Analyze paired episode-level differences. The independent experimental unit
   is an episode, not a packet, a telemetry window, or a repeated policy call.
   Report per-scenario results and uncertainty; do not conceal false-alarm
   harm by averaging it with flood recovery.
6. Retain failed runs. Technical exclusions must follow the frozen rules,
   disclose counts and reasons, and preserve the original artifacts. An action
   failing to help is an outcome, not an exclusion.
7. If inspection of held-out results causes changes, create a new version and
   new confirmatory set. Do not replace an unfavorable prior run silently.

Record Python, OS, kernel and `iproute2` versions, host resource information,
source/configuration hashes, random seeds, all commands and return statuses,
raw packet/event logs, per-window observations, controller inputs and outputs,
gateway decisions, configuration snapshots, restoration readbacks, and an
artifact manifest. Generated workload identifiers must not contain subscriber
identities or private network details. Exact live timing need not reproduce
bit-for-bit across machines; configuration, workload construction, analysis
and reported variability must be reproducible.

The current runner is **pilot-only** and reports descriptive paired deltas,
not confirmatory confidence intervals. Its seed randomizes execution order
only; traffic pacing is fixed. Changing this seed does not create an unseen
traffic distribution. A confirmatory workload/sensitivity design must therefore
be specified separately after integration testing. Retained pilot artifacts
are per-cohort counts and RTT samples, observations, decisions, command/readback
logs, configuration and source hashes—not packet captures or a per-packet trace.
Collect tool versions and host resource/load details during Linux qualification
before making a public empirical release. Fixed-rule/current-gate similarity
is expected because this experiment supplies policy-compliant proposals;
the previous conformance tests establish the gate's policy-blocking behavior.

## Safety and execution prerequisites

- Use a dedicated disposable Linux VM or laboratory host whose owner explicitly
  authorizes network-namespace and traffic-control operations. Root or scoped
  network capabilities may be required; do not request broader privileges than
  the harness actually needs.
- Validate exact owned namespace/interface identifiers before cleanup. Never
  flush host routes, host firewall rules, or unrelated `tc` configuration.
- Refuse arbitrary external destinations or unbounded traffic settings. Keep
  rates, datagram sizes, outstanding requests, queue lengths, episode count and
  run duration bounded.
- Perform an isolation preflight before generating traffic. Check for unexpected
  external/default routes and fail closed if the topology differs from the
  recorded lab design.
- Track child processes and apply a finalizer on normal exit, exceptions and
  interruption. Verify cleanup; report residual owned resources rather than
  claiming success when removal failed.
- Never add API secrets, credentials, raw private telemetry or sensitive model
  prompts to public artifacts. This initial controller requires no model key.

No packet-level outcome is publishable until a real run has passed these
checks, raw measurements have been inspected, and another clean environment
has reproduced the principal findings.

## Model adapter and deployment transfer

A subsequent model-enabled experiment would need a chosen accessible model,
secure local credential provisioning, an explicit call/cost budget, a bounded
tool/action schema, timeout and abstention behavior, and logging of the model
identifier, settings, prompts, supplied evidence and returned proposals. Its
agent must interact with observations and feedback in the evaluated loop. The
blinded external model-review packages do not provide this evidence.

Adding that adapter changes the evaluated system and requires new runs. It
must not retroactively turn deterministic-controller results into LLM results.
An offline response archive can support analysis replay, but is not a fresh
live-model reproduction.

Transfer to O-RAN further requires a validated observation/control mapping,
supported service-model or management interface, authenticated production
identity/evidence, target inventory, operator-approved service constraints,
and separate integration and fault testing. None is established by Linux
namespace measurements or by the dataset-based conformance experiments.

## Publication boundary

`docs/paper/closed_loop_experiment.tex` is a **protocol-only insertion**, not a
results section. Replace its status only after measured outcomes have been
audited. A compact table of paired service and intervention outcomes plus a
representative, transparently selected service timeline could fit approximately
one additional manuscript page; detailed protocols and all runs belong in the
public repository or supplement.

Acceptable eventual scope: a controlled packet-level demonstration of
pre-action governance, evidence corroboration and observed recovery behavior
with a deterministic reference controller. Do not claim validated detection
accuracy, LLM planning effectiveness, universal safety, complete agentic
security, O-RAN interoperability, or production mitigation effectiveness.
