# Obtain the evidence or run the experiment yourself

We separate three things so that readers can choose the work they need:

1. **Code and compact results.** These are included in Git. They support inspection, software checks, case replay and verification of our saved result exports.
2. **Original dataset inputs.** NetsLab and 5G-NIDD are obtained from their creators. The [data guide](../data/README.md) gives the exact files, sources, hashes and placement instructions.
3. **Our recorded measurements.** Six ZIP files hold our original Windows measurements, packet events and supporting provenance. They are companion release assets, not dataset downloads and not ordinary Git objects.

Downloading NetsLab or 5G-NIDD lets a reader make **new runs**. It cannot recover our past processing times, packet observations or repair history. Exact reanalysis of those historical observations requires the corresponding asset below. A new run is valuable replication evidence, but it should not be renamed or presented as our original run.

The Windows evidence includes limited dataset-derived records and the campaign evidence includes derived aggregates. They retain the source datasets' rights and attribution requirements. Read [the third-party notice](../data/THIRD_PARTY_NOTICES.md), and download the accompanying attribution README with any selected archive. We do not claim that all archived content was newly created by us.

Each public ZIP also carries the dataset notices and existing software licence in its root README. Adding these notices changes the archive checksum, not the scientific evidence. Use the current catalogue's identities; earlier pre-notice ZIPs are retained privately for provenance.

## Publication status and download location

The six companion archives are available in our [read-only evidence folder](https://drive.google.com/drive/folders/1vaiQhjLWn-viAMDSxuBOzmFYOnNER1jP?usp=sharing), together with a [README explaining each file](https://drive.google.com/file/d/1XG_CpFmeNoJiUm7IOpQz0bhVa_5L0-Hi/view?usp=drivesdk). The machine-readable [asset catalogue](RELEASE_ASSETS.json) contains the individual links, exact byte counts and SHA-256 hashes. In that catalogue, `published` means that the companion evidence is downloadable; it does not describe GitHub repository visibility or paper acceptance.

Our software repository is [Joy Dutta / Trustworthy-Agentic-O-RAN-Security](https://github.com/joy-dutta/Trustworthy-Agentic-O-RAN-Security). A source-only checkout does not contain the six large archives. Open an individual Drive link below and choose **Download**, keeping the original filename. If Drive says an archive is too large for its virus scan, do not treat that message as an integrity check: verify the downloaded file against our published hash before inspecting it. None of these ZIPs needs to be executed to read the results.

On 28 September 2026, we checked Viewer permissions and independently downloaded all six archives and the README without signing in. Every downloaded byte count and SHA-256 matched the intended release file. The [download-verification record](DOWNLOAD_VERIFICATION.json) documents that check. Readers should still verify their own copies using the steps below: a past successful download does not guarantee future availability, and byte identity is separate from scientific interpretation.

## The six assets and where to put them

Download only the assets needed for the inspection you want to perform. Keep their names unchanged and place the ZIP files at the repository-relative paths below. No extraction is needed for the repository's integrity or packet-recomputation tools.

| File | Destination relative to the repository root | Purpose |
|---|---|---|
| [university_windows_final.zip](https://drive.google.com/file/d/1G3QzEujtQjFyYLHnKTcYqERfQ0wOYBQv/view?usp=drivesdk) | `evidence/raw_archives/university_windows_final.zip` | Workstation 1 Windows outcomes, including individual processing requests and load arrivals/completions. |
| [workstation_windows_final.zip](https://drive.google.com/file/d/1tzGtWpYJf8F4Bhph60uDMMQgjciUUyiK/view?usp=drivesdk) | `evidence/raw_archives/workstation_windows_final.zip` | Workstation 2 Windows outcomes for the same frozen protocol. |
| [packet_primary.zip](https://drive.google.com/file/d/1aHKIrLyLXN-Bq_CL14JOhFCp58Q8jfsS/view?usp=drivesdk) | `evidence/raw_archives/packet_primary.zip` | Primary VM qualification and 36 initial packet episodes on Workstation 2. |
| [packet_repeat.zip](https://drive.google.com/file/d/1jhZEgZ9mmPHUANw3GLMwXmZteG8KxzTg/view?usp=drivesdk) | `evidence/raw_archives/packet_repeat.zip` | Separate clean-VM qualification and 36 repeated episodes, also on Workstation 2. |
| [campaign_provenance.zip](https://drive.google.com/file/d/1YhpdZQijS1UIhSK6mn7bpDu2tVNNqIQy/view?usp=drivesdk) | `evidence/raw_archives/campaign_provenance.zip` | Stage 0 baselines, workload preparation and campaign/regeneration records. |
| [packet_development_context.zip](https://drive.google.com/file/d/1mN43KzIFbLNM4H-5SBRoIx3QpG27dUj0/view?usp=drivesdk) | `evidence/history/packet_development_context.zip` | Optional failure-and-repair history, separate from final comparative episodes. |

We retain `university` and `workstation` in historical filenames and JSON identifiers to protect their recorded identities. They mean **Workstation 1** and **Workstation 2**, respectively. Both packet VMs ran on Workstation 2, not one VM on each workstation.

The [catalogue](RELEASE_ASSETS.json) gives the exact byte count and SHA-256 for every asset. These values also occur in [the repository manifest](../release/REPOSITORY_MANIFEST.json). For example, after placing the files, use PowerShell to inspect their hashes without extracting or executing them:

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath 'evidence/raw_archives/university_windows_final.zip'
Get-FileHash -Algorithm SHA256 -LiteralPath 'evidence/raw_archives/workstation_windows_final.zip'
Get-FileHash -Algorithm SHA256 -LiteralPath 'evidence/raw_archives/packet_primary.zip'
Get-FileHash -Algorithm SHA256 -LiteralPath 'evidence/raw_archives/packet_repeat.zip'
Get-FileHash -Algorithm SHA256 -LiteralPath 'evidence/raw_archives/campaign_provenance.zip'
Get-FileHash -Algorithm SHA256 -LiteralPath 'evidence/history/packet_development_context.zip'
```

With all six assets in place, run from the repository root:

```text
python tools/verify_repository.py
python tools/verify_repository.py --deep-assets
python tools/recompute_packet_evidence.py
```

The deep check streams archived members against their recorded public manifests. Packet recomputation reads both packet ZIPs and recalculates outcomes without generating network traffic. If you have only some or none of the six assets, use `python tools/verify_repository.py --without-raw-assets`; the report identifies the missing assets and explicitly labels the check partial. A checksum verifies byte identity, not scientific correctness by itself.

## What works without any of the six ZIPs

From the repository root:

```text
python tools/verify_repository.py --without-raw-assets
python tools/build_result_views.py --check
python tools/analyze_model_reviews.py --check
python tools/prepare_workspace.py --kind windows --destination work/windows_replay
```

From the newly prepared `work/windows_replay` directory:

```text
python -m unittest discover -s tests
python scripts/workstation_reproduce.py --plan --phase replay
python scripts/workstation_reproduce.py --execute --phase replay
```

The replay requires Windows for bounded process supervision and at least 10 GiB free disk for its preflight. It checks the supplied frozen cases and produces a new session under `results/local/workstation_runs/`; it is not fresh raw-dataset regeneration or a timing measurement. The two `--check` tools above recompute the compact views from the included saved summaries and original model responses, not from absent raw request or packet files. No API key is needed.

The pinned Windows and packet public source snapshots are included in Git under `evidence/source_snapshots/`. They are different from the six companion measurement ZIPs. These public transport copies omit a legacy manuscript template while preserving scientific source bytes; [the source guide](source_snapshots/README.md) records the original-to-public identities.

## Windows measurements

This route applies to both `university_windows_final.zip` and `workstation_windows_final.zip`.

**To inspect our recorded observations:** obtain the corresponding release asset. The Workstation 1 archive contains the `final_verified_20260923/` analysis and supervised result directories such as `rev1_stage4_micro_5gnidd_.../work/`. The Workstation 2 archive contains `full_..._stage1_validity_.../work/` and the other completed partition directories. Each archive has `PUBLIC_MANIFEST.json` and folder guidance. The result cells retain `job.json`, `summary.json`, and, as appropriate, `requests.csv`, `arrivals.csv` and `completions.csv`.

**To make a new full run instead:** obtain the exact `Lower_Layer_Data.db` and `Combined.zip` inputs using the [data guide](../data/README.md). From the repository root:

```text
python tools/prepare_workspace.py --kind windows --destination work/windows_full --netslab-db "PATH_TO_Lower_Layer_Data.db" --nidd-zip "PATH_TO_Combined.zip"
```

Use a trusted Python 3.12 environment on Windows, at least 10 GiB free disk, and a quiet host with packet VMs stopped. We recorded Python 3.12.14 for the original Windows campaigns. From the new `work/windows_full` directory:

```text
python scripts/workstation_campaign.py --plan
python -m unittest discover -s tests
python scripts/workstation_campaign.py --execute
```

The full campaign creates a fresh `results/local/full_campaign_runs/SESSION/` and supervised partitions under `results/evaluation_v0.2/`. It regenerates the aggregate contexts, case panels, census and sensitivity outcomes, then prepares the performance workloads. Inspect `COMPLETE.json`, `AGGREGATE_COMPARISON.json`, `CASE_REGENERATION_COMPARISON.json` and `WORKLOAD_COMPARISON.json` before proceeding. Stop on an incomplete campaign or input mismatch.

After those checks pass, run the separate timing, scaling and load phase once:

```text
python scripts/workstation_reproduce.py --execute --phase performance --quiet-host-confirmed
```

This creates a new `results/local/workstation_runs/SESSION/` and its measured partitions. Summarize using the actual two session paths and a new output directory:

```text
python scripts/summarize_workstation_reproduction.py --session "results/local/workstation_runs/PERFORMANCE_SESSION" --full-campaign-session "results/local/full_campaign_runs/FULL_CAMPAIGN_SESSION" --output "results/local/workstation_runs/MY_NEW_COMPARISON"
```

The new session is not a replacement for either original asset. Keep each physical computer's measurements separate. Policy/case identities can be compared exactly, while processing costs and offered-load outcomes depend on the recorded hardware, software and host conditions. Retain all conditions and failed attempts; do not repeat measurements until a preferred result appears.

## Packet measurements

This route applies to `packet_primary.zip` and `packet_repeat.zip`. Neither requires the two third-party dataset downloads.

**To inspect our recorded observations:** obtain both assets for `tools/recompute_packet_evidence.py`. Their `handoff_runs/` directories retain qualification sessions and final pilot sessions with `session_receipt.json`, environment/containment records and `packet_pilot/` episode evidence. The two final runs are separate samples with three paired repetitions per condition, not independent physical-host experiments.

**To make new observations instead:** prepare the included v7 source from the repository root:

```text
python tools/prepare_workspace.py --kind packet --destination work/packet
```

Use an explicitly authorized disposable Ubuntu VM. Install the documented Python/network tools before removing **all VM network adapters**. Do not use a bridge, NAT, public interface or production network. Our recorded VM allocation was four vCPUs and 4 GiB RAM, with Ubuntu 24.04 and kernel 6.8.0-139-generic. The [execution guide](../docs/03_reproduce.md) and the source runbooks describe containment and prerequisites.

Transfer the prepared packet source locally into that VM. From its root, inspect the plan first:

```text
python3 scripts/home_lab_run.py
```

Only inside the authorized isolated VM, qualify the environment, then use the successful session path printed by qualification:

```text
sudo python3 scripts/home_lab_run.py --qualify --acknowledge-isolated-vm
sudo python3 scripts/home_lab_run.py --run-pilot --acknowledge-isolated-vm --qualification results/local/handoff_runs/QUALIFICATION_SESSION --repetitions 3 --order-seed 220926
```

The second command creates 36 episodes: three scenarios, four methods and three paired repetitions. Keep every new directory under `results/local/handoff_runs/`, including unsuccessful qualification attempts. Successful initial runs are marked `PILOT_COMPLETE_NOT_CONFIRMATORY`; that is the intended scope, not a larger confirmatory study.

For the clean-environment repeat, install a **separate clean VM**, import the same canonical source, and repeat the same qualification and pilot commands. Do not reuse the first VM's qualification receipt. Keep the repeat's evidence separate. If both VMs run on one physical host, report that explicitly, as we do for Workstation 2.

## Campaign provenance

`campaign_provenance.zip` records how the original campaigns were prepared and checked. Its historical `university/` and `workstation/` roots correspond to Workstation 1 and Workstation 2. It includes Stage 0 inventory records, Stage 4 prepared workloads and the Workstation 2 full-campaign orchestration/regeneration receipts. It is not another experiment dataset.

To audit those **original** receipts, obtain this matching release asset. To create an equivalent evidence trail for a **new** campaign, follow the Windows commands above. `workstation_campaign.py --execute` creates fresh baseline inventories and `TRANSFER_BASELINE.json`, source-before/source-after checks, workload comparisons and completion records automatically. Keep them together with the performance session and prepared-workspace receipt. The workload bytes can be checked against the frozen inputs; new paths, timestamps and receipts will intentionally differ. A third-party dataset download cannot reconstruct the original receipts.

## Development history

`packet_development_context.zip` is optional when reproducing the completed protocol, but needed to inspect the detailed historical failure-and-repair evidence. Its `history/` tree preserves earlier packet qualification/transport attempts separately from final outcomes.

There is no command or public dataset that regenerates these past attempts as historical evidence. Use the matching companion asset if that audit is needed. Do **not** run obsolete launchers or attempt to recreate failures merely to manufacture an identical history. For new work, use the final v7 source and qualification route above; preserve any failures that actually occur in the new environment. The main [packet results guide](../results/06_packet_feedback/README.md) explains the completed protocol and its limits without requiring this archive.

## Interpretation and preservation

We keep raw measurements, inputs, software and provenance distinct so that their roles are clear. Read timing units and metric boundaries before interpreting results. Windows load is offered action proposals per second, not packets per second. Fields ending in `_ns` are nanoseconds. Packet delivery uses the actually sent cohort, including missing or late replies. Received-only RTT is not delivery reliability.

Keep new work under `work/` or another separate experiment directory. Do not overwrite our saved assets, rename new runs to their filenames, launch historical machine-specific scripts, or treat checksum success as proof of physical-network safety. The original evidence and a new independent reproduction answer different, complementary questions.
