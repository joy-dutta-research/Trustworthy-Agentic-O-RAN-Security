# Methods and measurement definitions

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
