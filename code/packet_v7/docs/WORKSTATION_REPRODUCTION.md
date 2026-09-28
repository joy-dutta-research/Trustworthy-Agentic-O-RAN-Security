# Stage 7: clean second-workstation reproduction

Use a **new extraction** of the verified transfer package. Python 3.12, standard
library only; run this stage as the normal Windows user, not as administrator.
Administrator access is relevant to separately approved VM installation, not to
these offline decisions or timings. No API key or network dataset is needed.

The transfer package includes 42 frozen constructed-case files: 777 common
validity cases, 20,000 NetsLab cases, 95,000 5G-NIDD conformance cases and 5,000
separate false-alarm probes. Replaying these checks software/decision consistency
on a second host. They are **not new independent observations**. The raw dataset
census and original generators are **not rerun** by this compact transfer test.
Original results remain separate reference evidence.

From the extracted repository root, using the actual Python executable:

```powershell
python scripts/workstation_reproduce.py --plan
python -m unittest discover -s tests
python scripts/workstation_reproduce.py --execute --phase replay
```

Check the replay `COMPLETE.json`, `replay/summary.json` and logs. Findings must not
be rewritten into expected labels. A policy-compliant false-alarm ALLOW is the
known policy limitation, not a successful mitigation.

Then stop the Ubuntu VM and other CPU/disk-intensive jobs, keep power/security
settings unchanged, and confirm the workstation can remain idle except for this
experiment. Timing is sequential; do not run tests or agents doing background
analysis concurrently. Run:

```powershell
python scripts/workstation_reproduce.py --execute --phase performance --quiet-host-confirmed
```

Alternatively, `--phase all` runs replay followed by performance. Planning is the
default; the script never silently starts experiments without `--execute`.

Performance repeats the same frozen workloads, seeds, request counts and bounds:
six instrumentation-pilot partitions (84 cells, excluded), then 18 final
partitions (1,820 cells): both datasets, all microbenchmark blocks, five active
state sizes, and three offered rates. Expect several hours; load measurements
alone require at least 70 minutes of scheduled offering. A faster CPU is not
assumed to produce a favorable result. Report all queue drops, unfinished work,
generator limits and timing distributions separately for each host. Never pool
the two hosts' raw timing observations or replace slower original results.

Every execution creates `results/local/workstation_runs/<timestamp>_<id>/` with a
plan, host context, source snapshots and final COMPLETE or INCOMPLETE receipt.
Replay records are inside that directory. The unchanged Windows supervisor puts
performance partitions under `results/evaluation_v0.2/s7_<id>_*`; the session's
`PARTITION_*.json` receipts index them. A new transfer-specific baseline is stored
under `results/evaluation_v0.2/stage0_*` and referenced by `TRANSFER_BASELINE.json`.
It is **not** the original workstation's Stage 0 baseline. Use the package return
collector to include every new session, all associated partitions, failures and
baseline receipts; do not return only a summary or selected favorable run.

The owned Windows Job bounds only its child tree: 2 GiB commitment/RSS guards,
one-hour per-run wall limit, 5 GiB new-output bound and 10 GiB preflight free disk.
Unsupported supervision fails closed. A failed run is retained and stops the
campaign. There is no automatic retry/resume or winner selection. Inspect the
failure first; explicitly rerun a fresh phase only after documenting the reason,
or return the partial evidence for a reviewed partition-resumption plan. Do not
relax guards, edit a policy, delete failed outputs, or shorten seeds/counts to
obtain completion. Review local logs for private paths before public release.

Stage 7 checks clean-transfer execution and reproducibility, not policy adequacy,
detection accuracy, a real O-RAN integration, or network mitigation benefit.
Author approval of assumptions, standards locators and publication privacy is
still a human responsibility. Stage 6 has its own isolated Ubuntu procedure.
