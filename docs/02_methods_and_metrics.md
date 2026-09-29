# Methods and measurement definitions

## Experimental design: why these tests?

The paper presents the essential design and results; this guide explains the choices behind them. The checks address different responsibilities: whether an action is permitted, whether current evidence justifies intervention, whether service improves afterwards, and how much processing the safeguards require. Use the [study overview](01_study_overview.md) for their connection to the proposed architecture.

### Complementary observations and explicit rules

NetsLab-5GORAN-IDD contributes lower-layer observations from the physical O-RAN testbed at University College Dublin. 5G-NIDD contributes flow-level observations from the University of Oulu's 5G test network. Evaluating the two separately broadens the network contexts examined while retaining their different measurement levels. The [dataset guide](../data/README.md) gives acquisition instructions, exact input identities and transformations.

These datasets describe network activity, not the permission to execute a mitigation. We explicitly construct proposed actions, permissions, approval evidence and operating context, and derive expected decisions from the declared operator policy. Every comparator is evaluated against that same reference, while implementing progressively more of its checks. The packet experiments then examine action consequences using separate controlled synthetic traffic, not replays of either dataset.

The policy combines security and governance principles with configurable operator choices. The existing [rule-to-source mapping](../code/windows_frozen/docs/standards_traceability.csv) distinguishes standards-informed principles, threat-derived checks and operator assumptions. For example, authentication, authorization, input validation and oversight have an external conceptual foundation; the particular action permissions, parameter limits and lifetimes are explicit experimental choices. The mapping records the rationale and source locators without presenting those numerical choices as mandatory standards requirements or an operator-certified deployment policy.

The [frozen configuration](../code/windows_frozen/configs/paper_policy.json) records the settings, and the [reference specification](../code/windows_frozen/configs/evaluation_v0.2/reference_policy_v0.1.json) records expected rule behavior. Its documented review status and known policy gap remain visible. Keeping the original policy unchanged preserves the comparison; a correction can be evaluated as a separately versioned study.

### Coverage, variation and practical consequences

| Evaluation | What varies or is checked | Why it is included | Detailed evidence |
|---|---|---|---|
| 777 constructed policy cases | Adversarial inputs, values near boundaries, combinations of two or three rule conditions, and known-policy-limitation probes | Check how safeguards behave both individually and together, including when a well-formed command lacks authority or conflicts with another action | [Validity results and coverage](../results/01_policy_validity/README.md) |
| 20-seed dataset evaluations | NetsLab proposal generation around fixed aggregate observations; 5G-NIDD record selection and associated proposal tests | Broaden coverage beyond one constructed collection or sampled panel | [Dataset coverage, seed records and eligibility](../results/02_dataset_robustness/README.md) |
| 12 sensitivity conditions | One operator setting changes at a time, including the original settings for each dataset | Make dependence on chosen limits explicit and reproducible | [Settings and decision/proposal changes](../results/03_sensitivity/README.md) |
| Processing benchmarks | Repeated measurements of the evaluator and matched local processing with buffered logging | Measure the local cost of adding verification | [Timing protocol and results](../results/04_processing_cost/README.md) |
| State and load tests | More actions already in force and more arriving action proposals | Identify conflict-checking work, queue behavior and priorities for scaling | [State and load results](../results/05_scaling_and_load/README.md) |
| Isolated packet tests | Sustained flooding, a brief benign burst and an acknowledged action that deliberately has no effect | Observe mitigation benefit, unnecessary-restriction avoidance and the no-benefit review trigger | [Packet protocol and all outcomes](../results/06_packet_feedback/README.md) |
| Reproduction checks | A second physical Windows workstation and a separately installed packet VM on Workstation 2 | Check fixed-output agreement, regeneration and clean-environment repeatability | [Reproduction evidence](../results/07_reproducibility/README.md) |

The 777-case suite contains 669 distinct semantic configurations. Its 25 selected consistency checks and 14 predefined test-only faults are described with their outcomes in the validity results. This is targeted coverage of declared rules and interactions, not a sample of 777 independently observed incidents.

For NetsLab, all 45,244 selected lower-layer rows contribute to aggregate context. Twenty control-generation seeds vary the constructed responses rather than resampling those raw rows. For 5G-NIDD, source-selection seeds support nested panels of 25, 100 and 250 records per eligible label, alongside the natural census and constructed conformance/false-alarm tests. Repeated variants and overlapping panels retain their identities and are counted as proposal occurrences, not independent attacks. The [sampling record](../results/02_dataset_robustness/sampling_and_eligibility.json) preserves the details.

### What the 12 sensitivity conditions mean

| Operator choice | Original setting | Alternatives | What it controls |
|---|---|---|---|
| Maximum traffic reduction | 80% | 60% and 90% | Largest permitted requested reduction |
| Maximum action lifetime | 900 s | 300 s and 600 s | Longest permitted action lifetime |
| Upstream packet-rate budget, 5G-NIDD only | 1,000 packets/s | 500 and 2,000 packets/s | Assumed budget used to construct response parameters |

NetsLab has five conditions: its original setting, two alternative reduction limits and two alternative lifetime limits. 5G-NIDD has those five plus two packet-budget alternatives, giving seven. Thus, the reported total is 12 conditions including both baselines, not 12 changed thresholds or all possible combinations. Packet-budget values here are different from the action-proposal arrival rates in the load benchmark.

Tighter NetsLab settings change some expected decisions. The tested 5G-NIDD budget alternatives change response parameters without changing decisions. Both kinds of outcome are retained: sensitivity testing makes the effect of an assumption visible, rather than requiring every setting change to alter the answer. The [design file](../code/windows_frozen/configs/evaluation_v0.2/study_design.json) preserves the initial plan; the linked final results establish what was completed, since historical status fields in that plan were not rewritten.

### Environments and exact reproduction

The [environment table](04_provenance_and_scope.md#experimental-computers-and-environments) already records both workstation specifications, Python versions, VM allocations and CPU-only execution. Windows policy/dataset summaries and all 12 sensitivity summaries agree across the two physical workstations. The [regeneration evidence](../results/07_reproducibility/README.md) records 42 byte-identical constructed-case files containing 120,777 cases, while distinguishing the NetsLab aggregate's parsed-JSON agreement from byte identity.

Both packet VMs ran on Workstation 2. Their separate 36-episode runs establish same-host clean-environment repeatability, with three paired repetitions per condition. They are not two independent physical packet-test hosts. Follow the [reproduction guide](03_reproduce.md) for verification and execution commands, and keep new outputs separate from the saved evidence.

## Policy comparison

| Method identifier | Meaning |
|---|---|
| `direct` | Accept the proposed action without the additional policy checks |
| `contract` | Check the action contract |
| `contract_rbac` | Add role/action authorization and interface checks to the contract |
| `trust_boundary` | Apply the full frozen policy, including relevant constraints, conflicts, approvals and expiry |

The result views may call `trust_boundary` the **full boundary** or **full gate**. They refer to the same Windows comparator. `ALLOW`, `DENY` and `ESCALATE` are reference-policy decisions. A block-required case is one requiring denial or escalation. “Permitted” is not a synonym for operationally safe in every circumstance.

NetsLab contributes lower-layer aggregate context. 5G-NIDD contributes selected flow-level source information. The datasets do not supply action authorization, approval or post-mitigation ground truth; those control-plane fixtures are constructed and labelled separately. The natural 5G-NIDD census and controlled conformance/false-alarm panels answer different questions and retain separate denominators.

## Cost and load

- **Component-only time:** the evaluated local component's processing boundary.
- **Matched local time:** matched processing with buffered event logging. It excludes model inference, network/actuator delay and durable remote audit storage.
- **Block p50/p95:** percentiles calculated within a process block, then summarized across blocks. Do not interpret the mean of block p95 values as a percentile pooled over all requests.
- **Active-action state:** the policy-relevant state inspected during conflict/state checks. Its size and ordering can change evaluation work.
- **Offered load:** action proposals per second, not network packets per second.
- **Completion fraction:** completed requests divided by all offered requests, including the declared bounded drain. Completed-only delay does not account for rejected/overflowed requests by itself.
- **Deadline success:** the explicitly defined all-offered fraction meeting the illustrative deadline. The 10-ms threshold is an experiment assumption, not a standards certification.

We keep Workstation 1 and Workstation 2 measurements separate. Different hardware, host activity and scheduling can change measured times; this is a cross-host reproduction, not an isolated causal experiment on CPU model. The [environment record](04_provenance_and_scope.md) maps these names to preserved data identifiers.

## Packet comparison

| Method identifier | Meaning |
|---|---|
| `no_action` | Observe the controlled workload without mitigation |
| `fixed_rule` | Apply a bounded deterministic response to an alert |
| `current_gate` | Submit the reference proposal through the frozen pre-action policy boundary |
| `evidence_feedback` | Add fresh corroboration before intervention and check measured benefit afterwards |

All methods share laboratory containment and final cleanup. Packet proposals are policy-compliant, so similar fixed-rule and boundary-only flood outcomes are expected. The comparison does not give only the full method different favorable proposals or privileged ground truth.

Each episode lasts 20 seconds. The event cohort contains requests sent during seconds 4–14. The comparative bottleneck is 1 Mbit/s; the action has a six-second lifetime and at most one intervention is allowed. Technical qualification separately used 10 Mbit/s.

**Protected timely delivery** is the fraction of all protected requests sent in the event cohort whose echo arrived within 500 ms. Missing or late responses stay in the denominator. Changes are in **percentage points**, not relative percent.

**Suspect goodput** is echoed application payload for the event cohort, in decimal kbit/s. It is not router-ingress throughput. In the benign-burst scenario, this traffic is legitimate, so an avoidable reduction is a collateral effect.

**Received-only RTT** excludes missing replies. A low received-only RTT cannot establish good service when many requests are lost.

**Paired comparison** means a method is compared with the same repetition's no-action episode within one VM. There are three episode pairs per scenario/method/VM. Packets are observations inside an episode, not independent experimental repetitions. The two VMs share Workstation 2 and are not pooled as independent hosts.

**Apply-decision delay** is recorded before command dispatch. Extra observation time is distinct from local CPU cost or actuator acknowledgment latency. In the no-op scenario, restoration/operator-review flags establish feedback behavior; they do not establish reversal of actual harm or a human response.

## Model-assisted review

We gave the two reviewers equivalent answer-masked policy materials for the original 120 constructed cases. We report decision agreement, reference agreement, completeness and explanatory traceability separately. Model identities/settings are author-reported where the saved outputs do not expose verifiable display metadata. Agreement is useful consistency evidence, not independent human validation or a runtime security capability.
