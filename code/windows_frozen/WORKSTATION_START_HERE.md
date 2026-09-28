# Workstation handoff: a fresh Orders 0-7 campaign

Release: 2026-09-24. Target: a separately owned/authorized Windows x86-64
workstation, reportedly i9 / 64 GB RAM. Actual OS, disk space and virtualization
support must be checked. This is a continuation package, not completed results.

## What you do

1. Copy BOTH delivered ZIPs (code and private dataset companion) and their
   `.sha256` files to the other workstation. The 24 GB parent archive is not needed.
   Compare both SHA-256 values with the supplied release checksums. Extract only
   the CODE ZIP into a **new, ordinary local folder**, not OneDrive or another
   synchronized folder. Keep the data companion zipped for the verified importer.
2. Open the extracted `oran-workstation-lab` folder in your local, workspace-enabled
   coding assistant. Use your requested GPT-6 Astra / Ultra setting if your
   account offers it; record the actual setting. An ordinary web chat with an
   uploaded ZIP cannot, by itself, operate your computer or its Ubuntu console.
3. Paste all of `WORKSTATION_ASSISTANT_PROMPT.txt`. The assistant should inspect
   and verify the package before installation or experiments.
4. Stay available for Windows elevation/restart, Ubuntu installation and guest
   console steps. Enter passwords privately; never paste them into the chat.
   Ask the assistant to complete the **before-you-sleep checklist first** and
   confirm tested unattended readiness before you leave; see
   `docs/WORKSTATION_BEFORE_YOU_SLEEP.md`. Setup may still need hands-on input.
5. After completion, privacy-review the collected results. Return the generated
   `ORAN_WORKSTATION_RESULTS_<date>.zip` and its checksum to the original task.
   Do not send the entire VM, virtual disks, credentials or the large raw datasets.

No OpenAI/Gemini API key is needed. The assistant helps with code and execution;
it is not the model under experimental evaluation. No automatic upload occurs.

## What is inside

| Part | Purpose |
|---|---|
| `reference/university/` | Compact preserved Orders 0-5 reports, original source hashes and receipts. Not all original raw output. |
| `data/workstation_reproduction/` | Exact 42 frozen case files: 120,777 constructed cases; both performance workloads and designs. No raw dataset archive. |
| `scripts/workstation_campaign.py` | Fresh Windows baseline, raw-input/aggregate verification, case regeneration, full 5G-NIDD census, all 12 sensitivity conditions and workload regeneration. |
| `scripts/workstation_reproduce.py` | Frozen-case cross-check and full 1,820-cell Windows performance reproduction, with 84 pilot cells separate. Run performance once, not twice. |
| `scripts/workstation_data.py` | Verify/import the separate 33 MB input companion without overwriting existing files. |
| `stage6_bootstrap/ORAN_STAGE6_PILOT_v2.zip` | Verified, separately packaged Ubuntu pilot source and safe VM/transfer helpers. |
| `docs/WORKSTATION_STAGE6_FINALIZATION.md` | Qualification, pilot, final-harness development, protocol freeze and measured study requirements. |
| `scripts/workstation_bundle.py` | Source verification and indexed return ZIP, including failures and source changes. |

## Recommended experiment arrangement

Front-load VM approvals, installation, console steps and qualification while
you are awake. Do not wait for a long Windows run before discovering that guest
setup needs you. The assistant must verify a working execution/collection path
and final protocol before claiming it can continue unattended.

Run Orders 0-5 on **Windows on the new workstation**, matching the original
operating environment. Compare these against the university results without
pooling timings. Orders 0-3 regenerate the evidence; Orders 4-5 measure the same
declared full workload once. The frozen-case replay is an additional software
cross-check, not a substitute for regeneration and not a new independent dataset.

Run Order 6 inside the isolated Ubuntu VM. Order 7 closes the clean-transfer
checks and clean-environment packet repeat. Do not move the Windows benchmarks
inside Ubuntu and call any timing difference a hardware effect: that would
change the operating system/virtualization as well. The full campaign may take
many hours; the assistant should estimate from qualification, not promise a
completion time from the CPU/RAM specification alone.

The Ubuntu harness already implements a **36-episode technical pilot**. It is
not a finished journal-final study. The destination assistant must qualify the
lab and complete a separately versioned final harness/protocol before final
measurement. Do not relabel pilot outputs as final results.

## Resources and boundaries

Suggested starting VM: 4 vCPU, 4 GiB RAM, new 40 GiB disk, **zero network adapters**
during experiments. Plan roughly 80 GiB free host disk for VM, installer, clean
repeat and evidence, subject to actual disk use. The Windows reproduction checks
at least 10 GiB free independently. High-end hardware does not remove OS/firmware
requirements. Stage7 and the Ubuntu VM must not benchmark concurrently.

The primary route is Hyper-V on a supported Windows edition, with an authenticated
Ubuntu Server 24.04 installer. Admin access does not override employer policy.
Ask before OS-feature installation, firmware changes, reboot, another hypervisor,
or temporary guest provisioning connectivity. Never disable security products.

Read `docs/WORKSTATION_CONTEXT.md`, `docs/WORKSTATION_FULL_CAMPAIGN.md`, then the
Stage6 and Stage7 guides. If the data companion is unavailable, only the explicitly
labelled replay/performance fallback can run; that is NOT a full Orders 0-5 rerun.
The old
`START_HERE.md` and `HOME_ASSISTANT_PROMPT.txt` describe the earlier pilot package;
they are historical context, not the entry point for this release.

Official assistant workspace guidance: https://developers.openai.com/codex/app/
Official Hyper-V requirements: https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/get-started/install-hyper-v
