# Reproduce at the level you need

There are three different tasks: inspect the saved findings, recompute results from saved measurements, or make new measurements using the same protocol. Choose explicitly. None of the read-only commands launches the experiment.

## 1. Read and verify the local artifact

Open a terminal at this repository's root, with Python 3.11 or newer:

```text
python tools/verify_repository.py --without-raw-assets
python tools/build_result_views.py --check
python tools/analyze_model_reviews.py --check
```

After obtaining all matching raw-evidence assets, `python tools/verify_repository.py --deep-assets` streams their archive members through the recorded hashes. It needs no VM and changes no files, but reads several gigabytes of uncompressed evidence.

The first command checks the source-only distributed files, documented folders and links, explicitly excluding the six large raw-evidence assets. The next two rebuild the compact result views in memory and compare them with the saved exports. These are integrity/transcription checks, not new scientific runs.

The [asset guide](../evidence/ASSET_GUIDE.md) describes all six excluded archives, their exact locations and reproduction routes. Public dataset downloads support new experiments, but do not replace our saved measurements. Obtain the matching evidence assets before reanalysing those saved measurements. Never interpret a source-only check as verification of absent measurements.

## 2. Reanalyse the saved packet observations

```text
python tools/recompute_packet_evidence.py
```

This reads the two packaged packet-evidence ZIPs and recomputes cohort delivery, goodput, received-only RTT and paired contrasts. It does not extract scripts or generate traffic. It prints a concise outcome; optional output must go to a new path outside the frozen evidence. Read [the metric definitions](02_methods_and_metrics.md) before comparing the results.

Windows request/arrival/completion files and the original analysis implementations are also retained in the raw assets and code snapshots. The saved result-view generator reads the supplied cross-host analysis: it does not claim to freshly recompute every request-level Windows statistic. The earlier evidence review recalculated 24 selected raw Windows cells. Preserve this distinction when describing verification.

## 3. Prepare a fresh scientific workspace

The browsable `code/` trees have added documentation for readers. Prepare a clean execution workspace from the pinned public source snapshot, with its internally consistent transport manifest:

```text
python tools/prepare_workspace.py --kind windows --destination work/windows
python tools/prepare_workspace.py --kind packet --destination work/packet
```

Choose a normal local destination, not a symlink or directory junction. The preparation tool deliberately refuses reparse-point paths, existing destinations and mismatched source/input hashes; an interrupted preparation is kept with an incomplete receipt for inspection.

The helper verifies the snapshot SHA-256, validates archive members and refuses an existing destination. It writes a separate preparation receipt. It performs no installation, VM creation, network request or scientific experiment. The public packages omit an old manuscript-writing template, including its nested bootstrap copy. Experimental code, configurations, tests and input fixtures are unchanged; archive and transport-manifest identities reflect the documented packaging change. See [public source provenance](../evidence/source_snapshots/README.md). The other historical documentation is retained; use this current guide to select the correct workflow.

To prepare Windows full regeneration with already acquired inputs, use a **new** destination:

```text
python tools/prepare_workspace.py --kind windows --destination work/windows_full --netslab-db "PATH_TO_Lower_Layer_Data.db" --nidd-zip "PATH_TO_Combined.zip"
```

Replace both `PATH_TO_...` values with your actual files. The helper verifies their exact scientific identities before copying. Original frozen acquisition metadata remains historical provenance; a new preparation receipt records the current import separately. See [data acquisition](../data/README.md). Raw third-party datasets are not redistributed with this draft.

## 4. Windows Stages 0–5

Use Windows and a trusted Python 3.12 runtime for the full campaign; the recorded runs used Python 3.12.14. Run as an ordinary user, keep at least 10 GiB free for the campaign, stop packet VMs and avoid concurrent benchmark workloads. Core Python code uses the standard library. Do not assume a normal installed wheel includes the necessary adjacent fixtures and configurations: use the prepared source checkout.

From the new `work/windows_full` workspace:

```text
python scripts/workstation_campaign.py --plan
python -m unittest discover -s tests
python scripts/workstation_campaign.py --execute
```

Inspect the newly created `COMPLETE.json`, aggregate comparison, case-regeneration comparison and workload comparison. Proceed only when they report successful completion and the required input equivalence. Each experiment must create a new result directory.

Then run the performance campaign once:

```text
python scripts/workstation_reproduce.py --execute --phase performance --quiet-host-confirmed
```

This runs the defined timing, state-scaling and load conditions. It is not a short software check. Instrumentation pilots remain separate from final measurements. Preserve all outputs and interrupted attempts; do not rerun until a preferred result appears.

The comparison tool accepts the newly printed session paths:

```text
python scripts/summarize_workstation_reproduction.py --session "results/local/workstation_runs/PERFORMANCE_SESSION" --full-campaign-session "results/local/full_campaign_runs/FULL_CAMPAIGN_SESSION" --output "results/local/workstation_runs/MY_NEW_COMPARISON"
```

Use the actual session names and a new output directory. We preserve the original Workstation 1 synthesis as the comparison reference; historical paths and identifiers still use `university`. New hardware is expected to change timings; successful reproduction means the declared source/input/protocol and interpretation are preserved, not that every latency repeats digit-for-digit.

For a lighter software check, prepare `work/windows` without raw data and run its unit tests. Frozen fixtures are included. This does not replace raw-dataset regeneration or the full measured campaign.

## 5. Packet Stage 6 in an authorized disposable Ubuntu VM

Packet execution changes Linux network namespaces and traffic-control state. It requires an explicitly authorized isolated environment. Do not run it against a public/production interface, live RIC, shared host network, bridge or NAT connection.

Prepare Ubuntu with the documented Python/network tools before removing its network adapters. Both recorded VMs ran on Workstation 2, each with four vCPUs, 4 GiB RAM, Ubuntu 24.04, Python 3.12.3 and kernel 6.8.0-139-generic; detailed versions are retained in the evidence. Keep the prepared packet-v7 source local to that VM. The original setup/runbooks in `code/packet_v7/docs/` explain the containment requirements; machine-specific historical transfer launchers are not needed.

From the canonical prepared packet workspace, first inspect the read-only plan:

```text
python3 scripts/home_lab_run.py
```

Only inside the authorized isolated VM, qualify the lab:

```text
sudo python3 scripts/home_lab_run.py --qualify --acknowledge-isolated-vm
```

After a successful qualification, use its actual session directory:

```text
sudo python3 scripts/home_lab_run.py --run-pilot --acknowledge-isolated-vm --qualification results/local/handoff_runs/QUALIFICATION_SESSION --repetitions 3 --order-seed 220926
```

This is the completed initial protocol: three scenarios, four methods and three paired repetitions, giving 36 episodes. Use the supplied v7 settings and stable-neighbor implementation. The qualification and comparative pilot use different bottleneck settings, documented in the methods; do not describe qualification as a completed larger-study capacity test.

## 6. Clean-environment Stage 7

Install a separate clean VM, prepare the same canonical packet source, and repeat qualification and the identical 36-episode protocol. Preserve a separate source/environment/run manifest. If both VMs use the same physical computer, describe the result as a clean-VM repeat, not independent physical-host replication.

The Windows cross-host reproduction is the other Stage 7 component. Keep its host-specific measurements separate. Never run it concurrently with packet VM measurements.

## 7. Model-assisted consistency review

The supplied original outputs can be analysed offline without an API key. Follow [model_review/README.md](../model_review/README.md) to understand the blinding and the post-review mapping. If conducting a new review, use fresh independent conversations, record actual model/settings metadata and preserve original responses. Do not provide completed answers or the post-review mapping to a new blinded reviewer. A new review is a new result, not a replacement for the supplied one.

## Record and interpret a new reproduction

Preserve source hashes, exact input identities, settings, seeds, commands, environments, completion/cleanup records and all measured conditions. Keep new outputs separate from the published originals. Report deviations and their cause where established. The original raw evidence lets readers reproduce the published calculations; newly measured performance examines behavior in a new environment.
