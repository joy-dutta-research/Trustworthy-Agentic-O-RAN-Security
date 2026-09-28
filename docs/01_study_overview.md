# What the proof of concept demonstrates

## The practical question

An intrusion alert alone does not tell an operator whether a proposed response is permitted, necessary or effective. For example, reducing a source's traffic may satisfy an authorization policy but still interrupt legitimate work if the alert reflects a short benign burst. An accepted actuator command may also produce no service improvement.

We address this by separating reasoning, verification, execution and feedback. Our PoC implements selected functions deterministically so their behavior can be examined without changing a language model between tests.

Throughout this repository, **Stages 0–7 means eight steps in our evaluation plan**, numbered from zero. These are neither O-RAN architecture layers nor eight runtime steps performed for each alert. Some establish traceability, some test behavior or processing cost, and others examine packet consequences and repeatability. Dataset-grounded checks are one part of this plan, not the basis of every stage.

## Three connected evaluations

**Policy conformance:** construct proposals from declared operator rules and dataset-grounded context, then compare direct execution with progressively stronger checks. The experiment asks whether each method enforces the same reference policy. It does not use intrusion labels as ground truth for the correct network action.

**Processing feasibility:** measure local processing, state-dependent work and scheduled-arrival load on Workstation 1 and Workstation 2, two physical Windows computers. The experiment quantifies the cost of the safeguards and the operating conditions relevant to deployment engineering.

**Operational feedback:** run real packets inside an isolated Linux namespace topology. Persistent flooding, a benign burst and an acknowledged no-op action illustrate the different roles of mitigation, corroboration and benefit verification. The clean-VM repeat checks the same protocol in a separately installed environment on Workstation 2.

## How the experiment connects to the paper

| Implemented responsibility | Paper terminology | What the evidence supports |
|---|---|---|
| Explicit action checks and decision records | Safe Action Verification; Verification Agent; Trust Boundary | Reproducible conformance to the stated policy |
| Fresh target-linked observations | Observe; Decision | Corroborating a service-affecting condition before intervention |
| Scoped Linux traffic restriction | Mitigation; Execution Agent; Safe Action Enforcement | Controlled packet-level actuation |
| Checking whether service improved | Rollback / Escalation | Recognizing lack of benefit and requesting restoration/local review |
| Versioned rules and traceable decisions/outcomes | Governance; Audit | An inspectable policy and evidence trail |

The packet actuator is a Linux policer. It is not an E2/A1/O1 implementation. The no-op condition tests ineffective-action recognition, not recovery after a genuinely harmful action. Full agent coordination, continuous learning, learned detection and live LLM reasoning remain beyond the implemented services.

## Eight evaluation steps, from a fixed baseline to repetition

We first make the experiment traceable, then check rule enforcement and robustness, measure processing cost and load behavior, observe the consequences of actions on packets, and repeat the protocol in fresh environments. Each step answers a different question about the framework.

| Stage and question | What we did and why it matters to the framework | Result location |
|---|---|---|
| **0. Fix the starting point:** can we trace what was tested? | Preserve the baseline, scientific code, policies, input identities and environment. This gives **Governance and Audit** a stable record and allows later comparisons to use the same starting point. | [Overview](../results/00_overview/README.md) and [evidence](../evidence/README.md) |
| **1. Check the rules:** is a proposed action permitted? | Compare four methods on 777 constructed policy cases, with targeted rule checks. This tests **Safe Action Verification at the Trust Boundary** against the frozen reference policy, not against detector labels. | [Policy validity](../results/01_policy_validity/README.md) |
| **2. Vary the cases:** does behavior hold beyond a small example? | Use NetsLab-5GORAN-IDD and 5G-NIDD context, declared mappings, census coverage and seeded panels. This extends **policy-conformance coverage** while retaining the distinction between source records and constructed proposals. | [Dataset robustness](../results/02_dataset_robustness/README.md) |
| **3. Vary the assumptions:** what depends on operator choices? | Examine 12 predefined settings for illustrative operator limits. Decision, reason and proposal changes make **governance assumptions** explicit instead of treating chosen thresholds as universal requirements. | [Sensitivity](../results/03_sensitivity/README.md) |
| **4. Measure the cost:** how much processing do the safeguards add? | Prepare fixed workloads and measure local processing under the declared timing boundary. This quantifies the **feasibility cost of verification**, rather than claiming end-to-end network response time. | [Processing cost](../results/04_processing_cost/README.md) |
| **5. Increase the workload:** what happens as state and demand grow? | Increase retained state and scheduled request arrivals. This examines **scaling and load behavior**, including the prototype's measured operating limits. | [Scaling and load](../results/05_scaling_and_load/README.md) |
| **6. Observe packet consequences:** was intervention necessary and useful? | Run real packets in an isolated lab under flooding, a benign burst and an acknowledged ineffective action. These conditions connect **verification, corroboration, enforcement and outcome feedback** to observable traffic effects. | [Packet feedback](../results/06_packet_feedback/README.md) |
| **7. Repeat in fresh environments:** what reproduces? | Repeat Windows evaluation on a second physical workstation and the packet protocol in a separately installed VM on the same packet workstation. This checks **cross-host Windows reproduction and same-host clean-VM repeatability**, without conflating them. | [Reproducibility](../results/07_reproducibility/README.md) |

All eight steps are complete for the initial PoC. The packet protocol has 36 episodes per VM, with three paired repetitions per condition; both VMs ran on Workstation 2. The larger confirmatory packet study remains future work.

The model-review folder is an **additional consistency study of the original 120 cases**, not Stage 8, not a runtime-agent test and not the expanded 777-case suite. Its separate placement prevents those different populations from being mixed.

We included this review to examine whether the written policy could be interpreted consistently, alongside the software tests of rule enforcement and packet tests of intervention consequences. The two separately prompted model reviewers agreed with the reference decisions on all 120 original cases. This adds evidence for policy interpretability and explainable decisions; it does not turn model agreement into physical-network safety validation. The [review guide](../model_review/README.md) preserves the model-identification and citation-completeness qualifications.

## How to use this evidence

Use the results to explain why the Trust Boundary and feedback are complementary. Use the measured costs to define realistic engineering requirements. Use the exact conditions and source identities to make the PoC inspectable and repeatable. Claims about broader deployment should follow further measurements rather than be inferred from source availability or passing checksums.
