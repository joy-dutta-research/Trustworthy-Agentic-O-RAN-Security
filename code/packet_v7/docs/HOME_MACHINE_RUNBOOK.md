# Home machine: complete setup, pilot and return procedure

## 0. Scope and approvals

The supported initial route is a NEW isolated Hyper-V Ubuntu Server VM on a
Windows x86-64 machine that actually supports Hyper-V. Having 64 GB RAM does
not establish OS edition, available disk, firmware configuration or permission.
First inspect these read-only. Windows Home may not provide this route. If
Hyper-V is unavailable, stop and agree an alternative; do not enable features,
switch hypervisors or reboot automatically. Linux on a dedicated disposable
machine is possible after equivalent isolation checks, not on a personal host
containing other workloads.

Check the institution permits using its account on your personal device. Do not
copy institutional data or credentials. This package contains research code,
synthetic fixtures and a de-identified aggregate; no raw dataset is needed.
All setup privileges are scoped to new lab resources. Do not run the whole
assistant with permanently unrestricted/admin access.

The assisting model needs local filesystem/terminal tools to operate Windows.
An ordinary web chat alone cannot create a VM on your PC, and Windows terminal
access is not automatically guest access. The owner may need to type commands
in the Hyper-V guest console. The assistant should acknowledge unavailable
tools instead of pretending setup ran.

Official OpenAI guidance supports Windows-local terminal workflows and keeping
sandbox/approval boundaries in place:
[Windows app documentation](https://learn.chatgpt.com/docs/windows/windows-app).
Requested assistant: GPT-6 Astra, Ultra if offered by your account. Record actual
displayed settings without inventing availability. It is not an experimental
LLM planner, and no API account or key is used by the pilot.

## 1. Verify and extract the package

On Windows, compare the original ZIP hash with its adjacent checksum and the
hash supplied in the original conversation. In PowerShell:

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath 'C:\your-chosen-folder\ORAN_HOME_LAB_v1.zip'
```

Use File Explorer Extract All into a NEW folder. The root is `oran-home-lab`.
Keep the original ZIP for offline guest transfer. Python 3.11+ is required;
Ubuntu 24.04 normally provides Python 3.12. The host also needs a trusted GPG
installation to authenticate the Ubuntu installer. If absent, the owner must
approve installation from official Python/GnuPG or Git-for-Windows sources.
Do not download an unofficial prebuilt VM or disable signature verification.

From the extracted source root:

```powershell
python scripts/portable_bundle.py verify-tree
python scripts/home_lab_run.py
```

Both are non-actuating. The first must report VERIFIED_SOURCE_TREE. Do not edit
files to make a checksum pass. If source changes are needed, retain the original
bundle and prepare a separately versioned correction.

## 2. Create/install the isolated Ubuntu VM

Read `docs/UBUNTU_VM_SETUP.md` and the scripts before elevation. Its old host
inventory refers to the university computer, not the home machine; recheck all
prerequisites. Use 4 vCPU, 4 GiB static RAM, new 40 GiB VHDX, Generation 2, Linux
UEFI CA Secure Boot, zero NICs. More host RAM does not require increasing these
resources; record any owner-approved change as an environment difference.

```powershell
python scripts/vm/download_ubuntu_iso.py --gpg 'C:\Program Files\Git\usr\bin\gpg.exe' --download
.\scripts\vm\create_oran_vm.ps1 -Plan
```

Adapt only the GPG executable location after locating a trusted installation.
The download is several GB and can take time. If the pinned official image is
unavailable, stop; do not fabricate the receipt or replace hashes silently.
When verification finishes, in an owner-approved elevated PowerShell session:

```powershell
.\scripts\vm\create_oran_vm.ps1 -Create
```

This leaves the new VM OFF and does not install Ubuntu. Inspect its receipt.
Start it in Hyper-V Manager and install normal Ubuntu Server (not minimized),
offline, onto **only the newly created 40 GiB virtual disk**. The owner confirms
this disk and chooses a local password privately. Skip online services and SSH.
Eject the installer and boot the installed guest. Never replace Windows.

Guest prerequisites: python3, iproute2 (`ip`, `tc`), procps (`sysctl`), and kmod
(`modprobe`, useful for diagnostics). Confirm with `command -v` and version
checks. If packages are missing, stop for a separately owner-approved package
provisioning step. Standard `sudo apt update` / `sudo apt install python3
iproute2 procps kmod` require connectivity: they will not work in a NIC-free
guest. Any approved temporary provisioning must occur before experiments;
remove the NIC and recheck isolation afterward. Do not improvise a bridge/NAT
or run packet experiments while a management adapter remains attached.

## 3. Move code into the VM without networking

Follow **docs/HOME_VM_TRANSFER.md**. The helper prepares only a NEW 1 GiB FAT32
virtual transfer disk after explicit confirmation and exact disk checks. It
copies the original source ZIP, verifies it, and dismounts the host copy.
Attach it to the stopped lab VM. Never mount it on host and guest simultaneously.

Inside Ubuntu, inspect the expected transfer volume; mount read-only for input.
Verify SOURCE.zip against SOURCE.sha256. Ensure /opt/oran-home-lab does not yet
exist before extracting with Python (details in the transfer guide). Then:

```bash
cd /opt/oran-home-lab
sudo python3 scripts/portable_bundle.py verify-tree
python3 scripts/home_lab_run.py
```

Use /opt/oran-home-lab consistently to keep personal names out of command logs.
The source transfer drive is a virtual data disk, not a VM network connection.
Unmount it before running the lab. The experiment does not write to it.

## 4. Qualify before the pilot

From /opt/oran-home-lab in the guest console:

```bash
sudo python3 scripts/home_lab_run.py --qualify --acknowledge-isolated-vm
```

This requires Ubuntu, root, zero non-loopback guest network interfaces and no
pre-existing namespaces. It tests code, creates only scoped lab namespaces,
checks topology, measures bounded traffic and limiter/restoration behavior,
and tests cleanup. Inspect its session receipt and logs. A successful software
test or command acknowledgment alone does not prove actual packet behavior.
Never bypass a failed isolation/traffic/accounting check to proceed.

The wrapper prints a new session directory under results/local/handoff_runs.
Record the exact qualification directory. A failure is useful evidence: keep
it, diagnose without broad changes, and return the package if blocked.

## 5. Run the bounded pilot

Replace QUALIFICATION_SESSION below with the actual successful directory name:

```bash
sudo python3 scripts/home_lab_run.py --run-pilot --acknowledge-isolated-vm \
  --qualification results/local/handoff_runs/QUALIFICATION_SESSION \
  --repetitions 3
```

This runs the prepared pilot: 36 serial episodes (four methods, three scenarios,
three repetitions). Keep the host awake/on power, do not suspend the VM, and
avoid concurrent heavy workloads or configuration edits. Actual runtime varies.
Do not launch two experiments concurrently. The wrapper records environment,
tests, command logs, run receipts and raw packet/cohort/controller measurements.
Every run uses a new directory; failures are retained.

If interruption leaves owned resources, do not issue broad namespace/route/
firewall deletion. Preserve logs, inspect ownership and recover only exact lab
resources with owner approval. The next qualification refuses ambiguous state.

### Abrupt interruption or power loss: preserve the stale lock

The wrapper normally removes its `.active-run.lock` after preserving evidence.
A power failure/forced termination can leave it behind. Both running and export
then refuse to proceed. **Never remove/move a lock merely because a command
looks slow.** First confirm no new run has started and, with owner approval,
cleanly reboot only this disposable Ubuntu guest (not Windows). This ends old
guest processes; after reboot recheck zero VM NICs and do not restart a run yet.

Only after that checkpoint, from /opt/oran-home-lab, inspect the exact lock and
move it into a new evidence directory rather than deleting it. Replace the
dated name with a fresh one; never overwrite a previous recovery:

```bash
cd /opt/oran-home-lab
set -eu
test -f results/local/handoff_runs/.active-run.lock
test ! -L results/local/handoff_runs/.active-run.lock
test ! -e results/local/handoff_runs/recovered_lock_YYYYMMDD_HHMMSS
sudo mkdir results/local/handoff_runs/recovered_lock_YYYYMMDD_HHMMSS
sudo mv --no-clobber -- results/local/handoff_runs/.active-run.lock \
  results/local/handoff_runs/recovered_lock_YYYYMMDD_HHMMSS/active_run_lock.txt
```

Stop if any check fails or the lock is a symlink/unexpected file. This does not
alter failed measurements or make them successful. The exporter retains the
recovery directory as unclassified evidence. Tell the receiving assistant that
the guest was rebooted and a stale lock preserved. Export the failed attempt
before any further troubleshooting; a future pilot requires fresh qualification.

Pilot outcomes may be neutral, adverse or fail integration. Do not select only
favorable runs. Stop after the planned pilot and return evidence; final sample
size, sensitivity conditions and confirmatory analysis must be frozen later.

## 6. Export and return evidence

Inspect logs locally before sharing. In particular check stderr for personal
paths; do not upload credentials, host inventories unrelated to the lab, guest
passwords or full VM images. Do not edit raw measurements. If secrets appear,
stop export and agree a redaction procedure preserving originals privately.

Use a new dated output name each time (replace YYYYMMDD). The exporter includes
ALL sessions, even incomplete qualification/pilot attempts, and the current
source snapshot. It refuses overwrite, links, unexpected file types and common
credential patterns. Automated scanning is not a substitute for your review.

```bash
sudo python3 scripts/portable_bundle.py return --reviewed-for-sharing \
  --output deliverables/ORAN_HOME_RESULTS_YYYYMMDD.zip
sudo python3 scripts/portable_bundle.py verify-zip \
  deliverables/ORAN_HOME_RESULTS_YYYYMMDD.zip
```

Two files are created: the result ZIP and `<same-name>.zip.sha256`. Copy both to
the transfer disk's RETURN directory using the offline guide, unmount cleanly,
shut down the guest, detach its transfer disk, and collect it read-only on
Windows. Upload the result ZIP to the **original conversation**; the companion
checksum is useful too. Keep all original artifacts locally.

## How the returned ZIP is organized

```text
oran-home-results/
  READ_RESULTS_FIRST.md
  RESULTS_INDEX.json             all sessions, reported status and hashes
  BUNDLE_MANIFEST.json           integrity hashes of every exported file
  received_source_manifest.json exact original source manifest, when present
  SOURCE_CHANGES.json            original-vs-returned source comparison
  source_snapshot/               source/configuration/tests used at export
  runs/<session>/
    session_receipt.json        observed completion/failure status
    ...                         environment, unit tests, qualification evidence
    ...                         packet plan, summary, report and raw logs
```

Receipt names inside sessions are authoritative only when checked against raw
evidence. The receiving assistant must verify integrity, source/configuration,
technical validity, all failures and scoring before giving the paper takeaway.
Missing receipts mean interrupted/unclassified, never implicit success.

## Not yet journal-final

A successful return establishes that the packet pilot ran, not that the full
agentic architecture is validated. A second clean environment, frozen final
evaluation and author approvals remain separate. The original machine has not
run this packet study, so the first home run is not yet an independent repeat
of a previously measured packet result.
