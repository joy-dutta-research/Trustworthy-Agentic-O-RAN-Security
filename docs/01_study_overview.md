# What the proof of concept demonstrates

## The practical question

An intrusion alert alone does not tell an operator whether a proposed response is permitted, necessary or effective. For example, reducing a source's traffic may satisfy an authorization policy but still interrupt legitimate work if the alert reflects a short benign burst. An accepted actuator command may also produce no service improvement.

We address this by separating reasoning, verification, execution and feedback. Our PoC implements selected functions deterministically so their behavior can be examined without changing a language model between tests.

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

## The completed sequence

| Stage | Purpose | Result location |
|---|---|---|
| 0 | Preserve baseline, source/input identities and environment | [Overview](../results/00_overview/README.md) and [evidence](../evidence/README.md) |
| 1 | Check policy validity and comparator behavior | [Policy validity](../results/01_policy_validity/README.md) |
| 2 | Examine dataset-grounded cases and seeded panels | [Dataset robustness](../results/02_dataset_robustness/README.md) |
| 3 | Examine declared policy sensitivity variants | [Sensitivity](../results/03_sensitivity/README.md) |
| 4 | Prepare fixed workloads and measure local processing | [Processing cost](../results/04_processing_cost/README.md) |
| 5 | Examine state scaling and offered-load behavior | [Scaling and load](../results/05_scaling_and_load/README.md) |
| 6 | Evaluate the controlled packet protocol | [Packet feedback](../results/06_packet_feedback/README.md) |
| 7 | Compare the second Windows host and clean packet VM | [Reproducibility](../results/07_reproducibility/README.md) |

The model-review folder is an **additional consistency study of the original 120 cases**, not an eighth runtime experiment and not the expanded 777-case suite. Its separate placement prevents those different populations from being mixed.

We included this review to examine whether the written policy could be interpreted consistently, alongside the software tests of rule enforcement and packet tests of intervention consequences. The two separately prompted model reviewers agreed with the reference decisions on all 120 original cases. This adds evidence for policy interpretability and explainable decisions; it does not turn model agreement into physical-network safety validation. The [review guide](../model_review/README.md) preserves the model-identification and citation-completeness qualifications.

## How to use this evidence

Use the results to explain why the Trust Boundary and feedback are complementary. Use the measured costs to define realistic engineering requirements. Use the exact conditions and source identities to make the PoC inspectable and repeatable. Claims about broader deployment should follow further measurements rather than be inferred from source availability or passing checksums.
