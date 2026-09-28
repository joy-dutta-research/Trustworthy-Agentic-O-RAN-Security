# Trustworthy Agentic O-RAN Security

## From a proposed response to an accountable action

An alert arrives. A security system proposes limiting a source's traffic. **Is that action allowed, is intervention justified, and did it actually help?** These are different questions. Our proof of concept makes the checks explicit and leaves an evidence trail that readers can inspect and reproduce.

This repository accompanies **“Trustworthy Agentic O-RAN Security: From Threat Detection to Safe Action, Governance, and Standardization,”** currently **under review**. The PoC is an integral part of the paper's evaluation. We will add the accepted-paper citation when available. Manuscript text, publication figures and direct copies of paper tables are intentionally excluded; code, numerical evidence and repository-specific explanations are provided here.

**New here?** Start with the [findings in plain language](results/00_overview/README.md), then explore the [connection to our framework](paper/README.md). To work with the evidence, choose a route below.

## What do Stages 0–7 mean?

They are **eight evaluation steps**, numbered from zero: our plan for checking the proof of concept. They are not O-RAN architecture layers and not eight actions that run whenever an alert arrives.

| Stage and simple name | What we check and why it matters | Open the evidence |
|---|---|---|
| **0. Fix the starting point** | Record the baseline, code, inputs and environment so every later result is traceable. | [Baseline and provenance](results/00_overview/README.md) |
| **1. Check the rules** | Compare four methods on 777 constructed cases to test whether the Trust Boundary enforces the stated policy. | [Policy conformance](results/01_policy_validity/README.md) |
| **2. Vary the cases** | Use NetsLab-5GORAN-IDD and 5G-NIDD context with seeded panels to examine behavior beyond one small case set. | [Dataset coverage](results/02_dataset_robustness/README.md) |
| **3. Vary the assumptions** | Change declared operator limits to make their effect on decisions and proposed actions visible. | [Policy sensitivity](results/03_sensitivity/README.md) |
| **4. Measure the cost** | Measure local processing overhead to understand the cost of action verification. | [Processing cost](results/04_processing_cost/README.md) |
| **5. Increase the workload** | Increase stored state and incoming requests to examine scaling and the prototype's operating limits. | [Scaling and load](results/05_scaling_and_load/README.md) |
| **6. Observe packet consequences** | Use isolated real packets to distinguish action permission, intervention necessity and measured benefit. | [Packet feedback](results/06_packet_feedback/README.md) |
| **7. Repeat in fresh environments** | Repeat Windows tests on a second physical host and the packet protocol in a clean VM on the same packet host. | [Reproducibility](results/07_reproducibility/README.md) |

The logic is straightforward: establish a traceable starting point, check the rules and their robustness, measure the cost, observe packet consequences, then repeat the protocol. The [study overview](docs/01_study_overview.md) explains how each step supports the framework. The model-assisted review is a supplementary check of policy interpretation, **not Stage 8**.

## What would you like to do?

| I want to... | Start here | What I need |
|---|---|---|
| Understand the findings and their meaning | [Results overview](results/00_overview/README.md), followed by [the ordered results](results/README.md) | A browser |
| Check the downloaded repository without running experiments | [Quick start below](#quick-start-check-the-repository-without-running-an-experiment) | Git access and Python 3.11 or newer |
| Recalculate the saved packet outcomes | [Packet reanalysis](docs/03_reproduce.md#2-reanalyse-the-saved-packet-observations) | Python and the two matching packet archives from [the asset guide](evidence/ASSET_GUIDE.md) |
| Run a new Windows evaluation, including the two-dataset checks, Stages 0–5 | [Dataset acquisition](data/README.md), [workspace preparation](docs/03_reproduce.md#3-prepare-a-fresh-scientific-workspace), then [Windows execution](docs/03_reproduce.md#4-windows-stages-05) | Windows, Python 3.12, both verified dataset inputs and a quiet host |
| Repeat the packet experiment and clean-VM check, Stages 6–7 | [Isolated packet execution](docs/03_reproduce.md#5-packet-stage-6-in-an-authorized-disposable-ubuntu-vm), then [clean-environment repetition](docs/03_reproduce.md#6-clean-environment-stage-7) | An explicitly authorized, disposable Ubuntu VM and the documented isolation controls |
| Inspect what the two model reviewers returned | [Model-assisted policy review](model_review/README.md) | A browser; Python for the offline comparison, with no API key |

Reading results, recalculating saved measurements and collecting new measurements are separate activities. The [complete reproduction guide](docs/03_reproduce.md) explains each route and the checks to complete before proceeding.

## What the evidence adds

We separate security reasoning from the authority to change a network. Three complementary safeguards connect the experiments to the framework:

1. **Permission:** a deterministic **Trust Boundary** checks a proposed action against an explicit operator policy.
2. **Corroboration:** fresh, target-linked observations help distinguish sustained service impairment from a short benign burst.
3. **Benefit:** outcome feedback checks whether the action helped and requests restoration or operator review when benefit is not observed.

For the traffic-limiting example, permission alone cannot tell us whether the alert reflects a genuine service problem. Likewise, an accepted command cannot establish that service improved. The [controlled packet results](results/06_packet_feedback/README.md) make these distinctions tangible, alongside [policy conformance](results/01_policy_validity/README.md) and [processing-cost measurements](results/04_processing_cost/README.md).

These eight evaluation steps are complete for the **initial PoC**. They include the two-dataset checks, Windows measurements on two physical workstations, and a 36-episode packet protocol repeated in a separately installed clean VM. Both packet VMs ran on **Workstation 2**, so that repeat is not a second physical-host packet experiment. The larger confirmatory packet study remains future work.

The additional **answer-masked model-assisted consistency review** concerns the original 120 policy cases. Both supplied reviewers agreed with the reference decisions on all 120 cases. Their [responses, explanations and traceability differences](results/08_model_review/README.md) support policy interpretability, not certification of a runtime LLM or real-network safety.

## Quick start: check the repository without running an experiment

Clone the repository, then run these commands from its root. Python 3.11 or newer is sufficient; the read-only helpers use the standard library.

```text
git clone https://github.com/joy-dutta/Trustworthy-Agentic-O-RAN-Security.git
cd Trustworthy-Agentic-O-RAN-Security
python tools/verify_repository.py --without-raw-assets
python tools/build_result_views.py --check
python tools/analyze_model_reviews.py --check
```

The repository is currently private, so cloning requires an authorized GitHub account until its visibility changes. These commands check the source-only checkout and reproduce the compact result views in memory. They do not create VMs, generate traffic, download datasets or contact a model. The first check explicitly reports any of the six large evidence archives that are absent; it does not verify missing files.

To inspect our exact saved measurements, obtain the required archives using [the asset guide](evidence/ASSET_GUIDE.md). All six are available in our [read-only evidence folder](https://drive.google.com/drive/folders/1vaiQhjLWn-viAMDSxuBOzmFYOnNER1jP?usp=sharing), with an [accompanying README](https://drive.google.com/file/d/1XG_CpFmeNoJiUm7IOpQz0bhVa_5L0-Hi/view?usp=drivesdk). Keep their recorded filenames and verify their hashes. With all matching assets present, `python tools/verify_repository.py --deep-assets` checks the archived members as well.

**Dataset inputs and saved evidence are different.** Downloading the original datasets supports new runs; it cannot recreate our past timing or packet observations. Raw third-party datasets are obtained from their creators using [the data guide](data/README.md), not redistributed as original datasets here.

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
| [tests/](tests/README.md) | Tests for this repository's reproduction and publication helpers |
| [paper/](paper/README.md) | Paper status and the research-to-evidence map, without manuscript content |
| [licenses/](licenses/README.md) | Software, documentation and third-party reuse terms and attribution |
| [release/](release/README.md) | Verification records, integrity manifest, Git file selection and release checklist |
| [.github/](.github/GUIDE.md) | Contribution and safety rules, plus the scope of automated software checks |

Each authored folder has a Markdown guide explaining its purpose and next steps. Preserved historical instructions are provenance: use the current reproduction guide to select what to run.

## Environments, interpretation and responsible use

**Workstation 1** is a Dell Pro 14 Premium PA14250 with an Intel Core Ultra 7 268V and 32 GB RAM. **Workstation 2** is an HP Omen 16 with an Intel Core i9-13900HX and 64 GB DDR5 RAM. Both ran the Windows evaluation; Workstation 2 hosted both isolated Ubuntu packet VMs. These computations did not use GPU acceleration. [Environment and provenance details](docs/04_provenance_and_scope.md) preserve versions and the mapping to historical identifiers.

Every result family states its units, denominator and host or VM identity. We retain all tested conditions, including operating limits that guide [future development](docs/05_research_directions.md). These experiments support selected verification, enforcement, feedback and audit responsibilities. They do not establish production O-RAN integration, detector accuracy or an evaluated runtime LLM. Integrity checks establish file identity; they do not by themselves demonstrate scientific improvement.

The package is maintained by **Joy Dutta**. See [citation metadata](CITATION.cff), [licensing and attribution](licenses/README.md), [completed verification](release/VALIDATION.md), [safe use](.github/SECURITY.md) and [contribution guidance](.github/CONTRIBUTING.md). Execute packet experiments only in an explicitly authorized isolated laboratory. Repository visibility, evidence-download access and paper acceptance are separate statuses.
