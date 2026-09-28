# Trustworthy Agentic O-RAN Security

## From a proposed response to an accountable action

An alert arrives. A security system proposes limiting a source's traffic. **Is that action allowed, is intervention justified, and did it actually help?** These are different questions. Our proof of concept makes the checks explicit and leaves an evidence trail that readers can inspect and reproduce.

This repository accompanies **“Trustworthy Agentic O-RAN Security: From Threat Detection to Safe Action, Governance, and Standardization,”** currently **under review**. The PoC is an integral part of the paper's evaluation. We will add the accepted-paper citation when available. Manuscript text, publication figures and direct copies of paper tables are intentionally excluded; code, numerical evidence and repository-specific explanations are provided here.

**New here?** Start with the [findings in plain language](results/00_overview/README.md), then explore the [connection to our framework](paper/README.md). To work with the evidence, choose a route below.

## How this example shaped our experiment

To turn these questions into a practical evaluation, we organized our experiments around the journey from a proposed traffic restriction to its observable consequences.

We began with the first decision: **should the proposed action be allowed?** We compared direct execution with progressively stronger checks, ending with the full **Trust Boundary**, the component that verifies an action against the operator’s policy. Each method received the same policy cases, allowing us to examine which checks prevent actions that violate the stated rules.

We then asked whether the findings extended beyond a small collection of examples. We used **[NetsLab-5GORAN-IDD](https://netslab.ucd.ie/netslab-datasets/netslab-5goran-idd/) for O-RAN-related context** and **[5G-NIDD](https://github.com/yushan1986/5g-nidd) for complementary 5G intrusion context**, together with multiple seeds and variations in operator settings. These datasets provide context for constructed action proposals, while the declared policy determines which actions are permitted. This lets us examine both broader case coverage and the influence of our chosen assumptions.

A useful safeguard must also have a measurable processing cost. We therefore measured the overhead of verification and examined how the prototype behaves as stored state and incoming requests increase.

Finally, we returned to the practical traffic example. In a separate, isolated packet experiment, we examined a sustained flood, a short benign burst and an action that was acknowledged but had no effect. These conditions let us distinguish **blocking an impermissible action, avoiding an unnecessary intervention, and recognizing when an executed action has not helped**. We also repeated the Windows evaluation on a second physical workstation and the packet protocol in a separately installed VM on the same packet workstation.

Together, these experiments examine policy enforcement, robustness, processing feasibility and operational feedback. Each contributes a different piece of evidence supporting the framework.

## Our evaluation, step by step

We organized this evaluation into **eight stages, numbered 0–7**. The sequence begins with a traceable baseline, progresses through rule checking, robustness and processing measurements, and concludes with packet-level testing and reproducibility checks.

The table below explains each stage and links it to its results. These numbers organize the evaluation and its evidence, rather than describing the runtime steps taken for every alert.

| Stage and purpose | What we check and why it matters | Open the evidence |
|---|---|---|
| **0. Establish the baseline** | Record the code, policies, inputs and environments so every later result can be traced to a defined starting point. | [Baseline and provenance](results/00_overview/README.md) |
| **1. Check policy enforcement** | Compare four methods on 777 constructed cases to test whether the Trust Boundary enforces the stated policy. | [Policy validity](results/01_policy_validity/README.md) |
| **2. Broaden the case coverage** | Use two dataset contexts and multiple generation or sampling seeds to examine behavior beyond a small illustrative case set. | [Dataset robustness](results/02_dataset_robustness/README.md) |
| **3. Vary operator assumptions** | Change declared operator limits to make their effect on decisions and proposed actions visible. | [Policy sensitivity](results/03_sensitivity/README.md) |
| **4. Measure processing cost** | Measure the additional local processing required by action verification compared with simpler methods. | [Processing cost](results/04_processing_cost/README.md) |
| **5. Increase the workload** | Increase stored state and incoming requests to examine scaling behavior and the prototype’s operating limits. | [Scaling and load](results/05_scaling_and_load/README.md) |
| **6. Observe packet consequences** | Examine flooding, benign traffic and an ineffective action to assess mitigation, corroboration and outcome feedback. | [Packet feedback](results/06_packet_feedback/README.md) |
| **7. Check reproducibility** | Repeat Windows tests on a second physical host and the packet protocol in a clean VM on the same packet host. | [Reproducibility](results/07_reproducibility/README.md) |

All eight stages are complete for the **initial PoC**. The [study overview](docs/01_study_overview.md) explains how they connect to the framework’s verification, enforcement, feedback and governance responsibilities.

## What the evidence adds

The findings support three complementary safeguards:

1. **Permission:** the Trust Boundary checks whether a proposed action complies with the operator’s policy.
2. **Corroboration:** fresh observations linked to the proposed target help establish whether intervention is justified.
3. **Benefit:** outcome feedback checks whether the action helped and requests restoration or operator review when benefit is not observed.

For the traffic-limiting example, permission alone cannot establish that an alert reflects a genuine service problem. Likewise, an accepted command cannot establish that service improved. The [packet results](results/06_packet_feedback/README.md) make these distinctions observable, alongside the [policy-conformance results](results/01_policy_validity/README.md) and [processing-cost measurements](results/04_processing_cost/README.md).

The completed evaluation includes two dataset contexts, Windows measurements on two physical workstations, and a **36-episode packet protocol repeated in a separately installed clean VM**. Both packet VMs ran on **Workstation 2**, so this is a same-hardware clean-environment repeat, not a second physical-host packet experiment. The larger confirmatory packet study remains future work.

### An additional check of policy interpretation

We also included an **answer-masked model-assisted consistency review** of the original 120 policy cases. Both supplied reviewers agreed with the reference decisions on all 120 cases.

This step complements the implementation tests by examining whether two separately prompted models interpret the written policy consistently. Their original responses, explanations and differences in citation completeness are preserved in the [model-review evidence](results/08_model_review/README.md).

The review supports policy interpretability. It is a supplementary study, not Stage 8, independent human-expert validation, or an evaluation of models operating the network.

## What would you like to do?

| I want to... | Start here | What I need |
|---|---|---|
| Understand the findings and their meaning | [Results overview](results/00_overview/README.md), followed by [the ordered results](results/README.md) | A browser |
| Check the downloaded repository without running experiments | [Quick start below](#quick-start-check-the-repository-without-running-an-experiment) | Git access and Python 3.11 or newer |
| Recalculate the saved packet outcomes | [Packet reanalysis](docs/03_reproduce.md#2-reanalyse-the-saved-packet-observations) | Python and the two matching packet archives |
| Run a new Windows evaluation, including the two-dataset checks in Stages 0–5 | [Dataset acquisition](data/README.md), then [Windows execution](docs/03_reproduce.md#4-windows-stages-05) | Windows, Python 3.12, both verified dataset inputs and a quiet host |
| Repeat the packet experiment and clean-VM check in Stages 6–7 | [Isolated packet execution](docs/03_reproduce.md#5-packet-stage-6-in-an-authorized-disposable-ubuntu-vm), then [clean-environment repetition](docs/03_reproduce.md#6-clean-environment-stage-7) | An explicitly authorized, disposable Ubuntu VM and the documented isolation controls |
| Inspect what the two model reviewers returned | [Model-assisted policy review](model_review/README.md) | A browser; Python for the offline comparison, with no API key |

Reading results, recalculating saved measurements and collecting new measurements are separate activities. The [complete reproduction guide](docs/03_reproduce.md) explains each route and the checks to complete before proceeding.

## Quick start: check the repository without running an experiment

Clone the repository, then run these commands from its root. Python 3.11 or newer is sufficient; the read-only helpers use the standard library.

```text
git clone https://github.com/joy-dutta/Trustworthy-Agentic-O-RAN-Security.git
cd Trustworthy-Agentic-O-RAN-Security
python tools/verify_repository.py --without-raw-assets
python tools/build_result_views.py --check
python tools/analyze_model_reviews.py --check
```

The repository is currently private, so cloning requires an authorized GitHub account until its visibility changes.

These commands check the downloaded files and reproduce the compact result views in memory. They do not create VMs, generate traffic, download datasets or contact a model. The first check explicitly reports any missing companion archives and still checks archives that are present. It does not verify absent files.

## Obtain the datasets and larger evidence files

**Original dataset inputs and saved experimental evidence serve different purposes.**

- To **collect new Windows measurements**, obtain the required dataset files from their creators using the [data guide](data/README.md).
- To **inspect or recalculate our recorded measurements**, obtain the relevant companion archives using the [asset guide](evidence/ASSET_GUIDE.md).

All six companion archives are available in our [read-only evidence folder](https://drive.google.com/drive/folders/1vaiQhjLWn-viAMDSxuBOzmFYOnNER1jP?usp=sharing), with an [accompanying README](https://drive.google.com/file/d/1XG_CpFmeNoJiUm7IOpQz0bhVa_5L0-Hi/view?usp=drivesdk). The asset guide explains each file’s purpose, exact destination and checksum.

Download only the files required by your chosen route. Keep their recorded filenames and verify their hashes. With all matching assets present, run:

```text
python tools/verify_repository.py --deep-assets
```

This also checks the archived members without executing the experiments.

Downloading the original datasets supports new runs; it cannot recreate our historical timing or packet observations. Raw third-party datasets are obtained from their creators, not redistributed as original datasets here. Dataset-derived evidence retains its separate attribution and licensing requirements.

## Find your way around

| Folder | What it contains |
|---|---|
| [docs/](docs/README.md) | Study questions, methods, reproduction instructions, environments and research directions |
| [results/](results/README.md) | Ordered findings, interpretation notes and numerical CSV/JSON exports |
| [code/](code/README.md) | Separately identified, preserved Windows and packet implementations |
| [data/](data/README.md) | Official dataset sources, exact input identities and acquisition instructions |
| [evidence/](evidence/README.md) | Source snapshots, saved summaries, companion-archive links and provenance |
| [model_review/](model_review/README.md) | Original reviewer inputs, supplied responses and post-review comparison materials |
| [tools/](tools/README.md) | Read-only verification, reanalysis and fresh-workspace preparation helpers |
| [tests/](tests/README.md) | Tests for this repository’s reproduction and publication helpers |
| [paper/](paper/README.md) | Paper status and the research-to-evidence map, without manuscript content |
| [licenses/](licenses/README.md) | Software, documentation and third-party reuse terms and attribution |
| [release/](release/README.md) | Verification records, integrity manifest, Git file selection and release checklist |
| [.github/](.github/GUIDE.md) | Contribution and safety rules, plus the scope of automated software checks |

Each authored folder has a Markdown guide explaining its purpose and next steps. The `.github` guide is named `GUIDE.md` so that the main research README remains the repository homepage.

Preserved historical instructions document how the work developed. Use the current reproduction guide to select what to run, rather than automatically executing historical paths or launchers.

## Experimental environments

**Workstation 1** is a Dell Pro 14 Premium PA14250 with an Intel Core Ultra 7 268V and 32 GB RAM.

**Workstation 2** is an HP Omen 16 with an Intel Core i9-13900HX and 64 GB DDR5 RAM.

Both ran the Windows evaluation. Workstation 2 hosted both isolated Ubuntu packet VMs. These computations did not use GPU acceleration.

The [environment and provenance guide](docs/04_provenance_and_scope.md) records software versions, VM configurations and the mapping to historical machine identifiers.

## Interpretation and next steps

Every result family states its units, denominator and host or VM identity. We retain all tested conditions, including the operating limits and mixed findings that guide [future development](docs/05_research_directions.md).

The experiments support selected verification, enforcement, feedback and audit responsibilities. They do not establish production O-RAN integration, detector accuracy or an evaluated runtime LLM.

Each packet VM contributes three paired repetitions per condition. The completed initial PoC provides a baseline for a larger confirmatory study with more repetitions, additional physical hosts and broader operational conditions.

Integrity checks establish file identity. Software tests and reproducible calculations support inspection of the implementation and evidence; they do not independently establish scientific improvement.

## Citation, licensing and responsible use

This reproducibility package accompanies the collaborative work of the paper’s authors. It brings together the code, experimental evidence and reproduction instructions supporting our shared research. The GitHub account provides the hosting location for this research artifact.

When referring to this work, acknowledge the research team and identify the repository version or commit used. Once the paper is accepted, we will provide its official citation with the **complete author list** and publication link. Repository ownership or software-maintainer metadata should not be interpreted as sole authorship of the research.

Software, author-owned guides/results and third-party data have separate terms. Please consult the [licensing and attribution guide](licenses/README.md) before reuse or redistribution.

The [verification record](release/VALIDATION.md) explains the completed checks and their boundaries. The [contribution guidance](.github/CONTRIBUTING.md) explains how to extend the work while preserving the recorded baseline.

Execute packet experiments only in an explicitly authorized, isolated laboratory, following the [safety guidance](.github/SECURITY.md). Keep new measurements separate from the original evidence and document any deviations from the supplied protocol.

Repository visibility, evidence-download access and paper acceptance are separate statuses.
