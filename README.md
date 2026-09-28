# Trustworthy Agentic O-RAN Security: Reproducible Proof of Concept

This repository contains the proof of concept for **“Trustworthy Agentic O-RAN Security: From Threat Detection to Safe Action, Governance, and Standardization.”** The paper is **under review**. This PoC is an integral part of its evaluation. We will add the accepted paper's citation and link when they become available.

We provide the code, prepared case inputs, results and reading guides needed to inspect and reproduce the study. Original third-party datasets are obtained from their creators using our acquisition guide. We intentionally exclude the manuscript text, publication figures and direct reproductions of paper tables while the paper is under review.

## What this proof of concept contributes

We separate security reasoning from the authority to change a network. Our implementation makes that separation concrete and examines three questions:

1. **May this action be executed?** A deterministic Trust Boundary checks the proposed action against an explicit operator policy.
2. **Does the observed situation justify intervention?** Fresh, target-linked evidence helps distinguish sustained service impairment from a short benign burst.
3. **Did the action produce the intended benefit?** Outcome feedback checks what happened and requests restoration or operator review when benefit is not observed.

Dataset-grounded policy tests, processing-cost measurements and an isolated packet experiment examine these complementary responsibilities. The result is a reproducible illustration of selected framework services, rather than an implementation of every proposed agent.

## Read the repository in this order

| Step | Read | What you will understand |
|---|---|---|
| 1 | [Study overview](docs/01_study_overview.md) | The research questions, the framework connection and the completed scope |
| 2 | [Results overview](results/00_overview/README.md) | The main findings and where each comes from |
| 3 | [Stage-by-stage results](results/README.md) | The experiment sequence, numerical outputs and interpretation |
| 4 | [Model-assisted review](results/08_model_review/README.md) | How the two supplied model reviews interpreted the original policy cases |
| 5 | [Reproduction guide](docs/03_reproduce.md) | How to verify evidence, rebuild result tables or run a new experiment |
| 6 | [Research directions](docs/05_research_directions.md) | How the observations guide the next development and evaluation steps |

For the connection to our framework, start with [the research-to-evidence map](paper/README.md). For code, start with [the two preserved implementations](code/README.md). For detailed measurements and the six optional large archives, start with [the asset guide](evidence/ASSET_GUIDE.md).

## What is included

- Completed initial PoC **Stages 0–7**, including the two-dataset Windows evaluation and its second-physical-host reproduction.
- A 36-episode controlled packet study and the same protocol repeated in a separately installed clean VM on **Workstation 2**.
- Readable result tables, machine-readable CSV/JSON exports, measurement definitions and interpretation notes.
- The supplied answer-masked model-assisted consistency review of the original 120-case suite, kept separate from the expanded experiments.
- Preserved scientific source versions, configurations, seeds, public-data acquisition guidance, raw-evidence assets and provenance records.
- Read-only verification and analysis tools, plus explicit instructions for new measurements in an authorized isolated environment.

## Start without running an experiment

Python 3.11 or newer is sufficient for the repository's read-only analysis tools. No model API key is needed.

```text
python tools/verify_repository.py --without-raw-assets
python tools/build_result_views.py --check
python tools/analyze_model_reviews.py --check
```

These commands check the source-only checkout and its compact result views. The first command explicitly excludes the six large raw-evidence assets; it does not verify files that are absent. None of these commands creates VMs, generates traffic, downloads datasets or contacts a model. See [the asset guide](evidence/ASSET_GUIDE.md) for the difference between downloading public datasets, regenerating measurements and obtaining our exact saved evidence. Once all matching assets are present, run `python tools/verify_repository.py --deep-assets` for the full archive check. See [the reproduction guide](docs/03_reproduce.md) before using the separate experiment commands.

The [verification record](VALIDATION.md) lists the completed checks and their boundaries.

## Where we ran the experiments

We use **Workstation 1** and **Workstation 2** consistently in the reader-facing guides. Workstation 1 is a Dell Pro 14 Premium PA14250 with an Intel Core Ultra 7 268V and 32 GB RAM. Workstation 2 is an HP Omen 16 with an Intel Core i9-13900HX and 64 GB DDR5 RAM. Both ran the Windows experiments; the two isolated Ubuntu packet VMs ran on Workstation 2. These computations did not use GPU acceleration. [The environment record](docs/04_provenance_and_scope.md) gives the relevant specifications and maps these names to unchanged historical identifiers.

## How to read the findings

The strongest conclusion is that **policy permission, incident corroboration and measured effectiveness provide complementary safeguards**. Policy-conformance results describe agreement with the frozen reference policy. Packet results describe controlled episode outcomes. Performance results describe the stated local processing or scheduled-arrival boundary. Model review describes consistency with a supplied policy, not an LLM operating the network.

Every result family explains its denominator, units, host/VM identity and interpretation. All tested conditions are retained. Observed operating limits guide the next engineering steps; capabilities not yet evaluated are clearly identified as future work. The larger confirmatory packet study remains outside the completed initial PoC.

## Repository and evidence layout

| Folder | Purpose |
|---|---|
| [paper/](paper/README.md) | Paper status and research-to-evidence map, without manuscript text or publication displays |
| [docs/](docs/README.md) | Plain-language study, method, reproduction and development guides |
| [results/](results/README.md) | Ordered final results with tables, CSV/JSON data and explanations |
| [model_review/](model_review/README.md) | Review materials, supplied model responses and post-review comparison inputs |
| [code/](code/README.md) | Browsable, separately identified Windows and packet-v7 implementations |
| [data/](data/README.md) | Dataset sources, input identities and acquisition instructions |
| [evidence/](evidence/README.md) | Source snapshots, summaries and documented raw-evidence archives |
| [tools/](tools/README.md) | Verification, analysis and fresh-workspace preparation tools |
| [tests/](tests/README.md) | Tests of this publication/reproduction layer |

Every authored folder includes a Markdown guide. Historical files inside preserved archives remain identifiable as historical evidence. Generated working directories and Git internals are not part of the reading path.

## Paper, citation and release

We maintain the software at [Trustworthy-Agentic-O-RAN-Security](https://github.com/joy-dutta/Trustworthy-Agentic-O-RAN-Security) under Joy Dutta's GitHub account. The paper is under review, so the software citation does not stand in for an accepted-paper citation. See [paper status](paper/PAPER_STATUS.md), [citation metadata](CITATION.cff), [licensing](LICENSES.md), [safe use](SECURITY.md) and [the release checklist](RELEASE_CHECKLIST.md). Repository access and companion-asset access are separate; a working evidence link does not imply that the GitHub repository is publicly visible.

The six large raw-evidence archives are excluded from ordinary Git history and are available in our [read-only evidence folder](https://drive.google.com/drive/folders/1vaiQhjLWn-viAMDSxuBOzmFYOnNER1jP?usp=sharing). Start with its [README](https://drive.google.com/file/d/1XG_CpFmeNoJiUm7IOpQz0bhVa_5L0-Hi/view?usp=drivesdk), then use [the asset guide](evidence/ASSET_GUIDE.md) for individual links, destinations and checksum checks. Public dataset links support new runs, but they cannot replace our exact saved timing or packet observations. A source-only clone can read compact results and run software checks; reanalysis of every saved measurement additionally requires the matching evidence assets.
