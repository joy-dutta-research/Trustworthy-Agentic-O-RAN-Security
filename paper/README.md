# How the evidence supports our framework

Our paper, **Trustworthy Agentic O-RAN Security: From Threat Detection to Safe Action, Governance, and Standardization**, is under review. This repository provides the supporting code, experimental results and reproducibility instructions. We will add the accepted-paper citation and link when available.

We intentionally keep the manuscript text, publication figures and direct reproductions of the paper's tables out of this repository during review. This folder contains a research-to-evidence map and paper status only. Numerical result files elsewhere in the repository remain available so readers can inspect the experiments and reproduce their calculations.

## Research questions and supporting evidence

| Research question | Where to inspect the evidence |
|---|---|
| Does a separate deterministic boundary enforce the declared action policy? | [Policy validity](../results/01_policy_validity/README.md) and [dataset evaluation](../results/02_dataset_robustness/README.md) |
| Do the conformance findings reproduce across computers, and how do they depend on the stated assumptions? | [Dataset evaluation](../results/02_dataset_robustness/README.md), [sensitivity](../results/03_sensitivity/README.md) and [reproduction](../results/07_reproducibility/README.md) |
| What processing, state-scaling and load costs accompany the safeguards? | [Processing](../results/04_processing_cost/README.md) and [state/load behavior](../results/05_scaling_and_load/README.md) |
| How do fresh evidence and outcome checking complement pre-action permission? | [All packet scenarios](../results/06_packet_feedback/README.md) |
| Can separately prompted model reviewers interpret the written policy consistently? | [Auxiliary model review](../results/08_model_review/README.md), including metadata and traceability qualifications |
| Can the implementations, inputs and calculations be traced and reproduced? | [Evidence](../evidence/README.md), [asset acquisition](../evidence/ASSET_GUIDE.md) and [provenance](../docs/04_provenance_and_scope.md) |

## What the combined evidence contributes

We examine three complementary responsibilities: deciding whether an action is permitted, checking whether the observed situation justifies it, and measuring whether it helped. The policy experiments support Safe Action Verification. The controlled packet experiments connect Mitigation to Rollback / Escalation and Audit. The model-assisted review adds an inspectable check of policy interpretation, alongside software enforcement and measured intervention outcomes.

We retain the full condition set, including benign-traffic, ineffective-action and high-load results. These observations clarify the useful operating range of the current implementation and guide its next development steps. They do not establish complete implementation of every proposed agent, detector accuracy, production O-RAN integration or recovery from an actually harmful action. [The research guide](../docs/05_research_directions.md) explains the next steps and how they follow from the evidence.

## Reading and reproducing the results

Start with the [ordered results](../results/README.md) for study-level interpretation, then use the accompanying CSV/JSON files for exact values. We keep Workstation 1 and Workstation 2 separate and report the two packet VMs as separate installations on Workstation 2. The [methods guide](../docs/02_methods_and_metrics.md) defines denominators, units and measurement boundaries. The [reproduction guide](../docs/03_reproduce.md) distinguishes compact-result checks, reanalysis of saved evidence and new experimental runs.
