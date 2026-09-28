# Offline source and result transfer: Windows ↔ Ubuntu

This optional helper provides a complete transfer route without an Internet
connection, shared folder, SSH server, clipboard transfer, or VM network adapter.
It creates **one new 1 GiB transfer disk**, separate from Ubuntu's 40 GiB system
disk. Do not put raw datasets, passwords, API keys, or VM images on it.

**Status:** the PowerShell script has passed syntax and read-only plan checks on
Windows. Disk creation, Hyper-V attachment, guest mounting, and result collection
still require first-use verification on the home machine. They have not been
executed on the institutional computer. Stop on an unexpected result; do not
weaken the checks or guess a disk number to make the procedure continue.

## Rules to keep throughout

- Only the machine owner runs approved administrator operations.
- Ubuntu must be **shut down**, not paused or saved, when attaching/detaching
  the transfer disk. Use `sudo poweroff` inside Ubuntu and wait for **Off**.
- The VM has **zero network adapters** during transfer and experiments.
- Never mount the same transfer disk in Windows and Ubuntu simultaneously.
- Never initialize/format any existing physical disk, USB disk, Ubuntu disk,
  or a VHDX selected manually. The helper formats only its own newly created,
  repeatedly verified fixed-path disk.
- Do not create checkpoints while the transfer disk is attached. A checkpoint
  may reference it and prevent safe host collection. The helper refuses disks
  referenced by any VM or snapshot, including through VHD parent chains.
- Do not enable Internet sharing, NAT, a bridged switch, or remote access to
  avoid a transfer problem. Ask for help with the error instead.

## 1. Prepare Ubuntu first

Follow `docs/UBUNTU_VM_SETUP.md` and the home package's main instructions. Install
Ubuntu Server 24.04 LTS in the new `ORAN-Security-Lab` Hyper-V VM. Ensure `python3`,
`iproute2`, `procps`, and `kmod` are installed, using an owner-approved provisioning
connection if necessary; then remove the VM network adapter before the lab.
Shut down Ubuntu cleanly. Do not attach a transfer disk during Ubuntu installation,
so there is no second disk that the installer could accidentally select.

## 2. Create the transfer disk on Windows

Extract the home package to a normal local NTFS directory. Open an
**owner-approved elevated PowerShell** in the extracted `oran-home-lab` directory.
Keep the original source ZIP and its `.sha256` next to the extracted directory.
If institution/device policy blocks a script, stop and use the approved process;
these instructions do not require changing group membership or bypassing policy.

First inspect the read-only plan:

```powershell
./scripts/vm/prepare_transfer_disk.ps1 -Plan
```

Read the SHA256 from the supplied package checksum file. Substitute your actual
source ZIP path and that independently supplied 64-character checksum below:

```powershell
./scripts/vm/prepare_transfer_disk.ps1 -Create `
  -SourceZip 'C:\Research\ORAN_HOME_LAB.zip' `
  -SourceSha256 'REPLACE_WITH_THE_64_CHARACTER_PACKAGE_SHA256' `
  -ConfirmNewTransferDisk
```

The source ZIP filename may differ; use the actual delivered filename. The
example checksum is intentionally invalid and must not be copied literally.
Do not compute a replacement checksum to dismiss a mismatch with the supplied
one. Verify the original package provenance instead.

The helper checks the target VM is Off and has no adapters. It refuses existing
transfer paths. It creates only:

```text
oran-home-lab/.vm-local/transfer/
  ORAN-TRANSFER.vhdx
  transfer_receipt.json
```

Before initializing or formatting, it verifies the newly created VHDX's exact
path, identifier, disk number, 1 GiB size, virtual bus, stable disk UniqueId,
empty RAW state, and that it is neither a boot nor a system disk. It copies the
checksum-verified source ZIP, creates a fresh transfer ID, and **dismounts the
VHDX from Windows**. No VM attachment is performed automatically.

Record the printed transfer ID. Only a `READY: host-detached transfer disk` result
means this step succeeded. A failure preserves the partial disk for inspection;
do not delete it or rerun formatting commands as a workaround.

## 3. Attach only the transfer VHDX to the stopped VM

In Hyper-V Manager, select **ORAN-Security-Lab → Settings → SCSI Controller →
Hard Drive → Add**. Choose the exact `ORAN-TRANSFER.vhdx` printed by the helper.
Keep the existing 40 GiB Ubuntu system disk unchanged. Verify there are now two
hard disks: the original 40 GiB disk and the new 1 GiB transfer disk, and no
network adapters. Start the VM and use its console.

## 4. Read and verify the source inside Ubuntu

First inspect disks:

```bash
lsblk -o NAME,SIZE,TYPE,FSTYPE,LABEL,MOUNTPOINTS
sudo blkid -t LABEL=ORANXFER -o device
```

There must be exactly **one** `ORANXFER` FAT32 partition on a **1 GiB** secondary
disk, not the disk containing `/`. Do not assume a name such as `/dev/sdb1`.
Do not run `mkfs`, `fdisk`, `wipefs`, or formatting commands in Ubuntu.

After the visual checks, this block finds the unique labeled partition, checks
its parent size, refuses an already mounted partition, and mounts it read-only:

```bash
set -eu
oran_transfer_count=$(sudo blkid -t LABEL=ORANXFER -o device | wc -l)
test "$oran_transfer_count" -eq 1
oran_transfer_partition=$(sudo blkid -t LABEL=ORANXFER -o device)
oran_transfer_parent=$(lsblk -nro PKNAME "$oran_transfer_partition")
test -n "$oran_transfer_parent"
test "$(lsblk -bdnro SIZE "/dev/$oran_transfer_parent")" -eq 1073741824
if findmnt -rn -S "$oran_transfer_partition"; then
    echo 'Already mounted: stop and inspect before continuing.'
    exit 1
fi
sudo mkdir -p /mnt/oran-transfer
if mountpoint -q /mnt/oran-transfer; then
    echo 'Mount directory already in use: stop.'
    exit 1
fi
sudo mount -t vfat -o ro,nosuid,nodev,noexec "$oran_transfer_partition" /mnt/oran-transfer
python3 -m json.tool /mnt/oran-transfer/TRANSFER_ID.json
(cd /mnt/oran-transfer && sha256sum -c SOURCE.sha256)
```

**Pause and compare the displayed transfer ID with the Windows receipt and the
displayed source SHA256 with the delivered package checksum.** If either differs,
unmount and stop. The label alone is not an identity check.

The package ZIP contains an `oran-home-lab/` root. Extract only if the destination
does not already exist:

```bash
test ! -e /opt/oran-home-lab
sudo python3 -m zipfile -e /mnt/oran-transfer/SOURCE.zip /opt
sudo umount /mnt/oran-transfer
cd /opt/oran-home-lab
```

If the destination exists, do not merge/overwrite it. Preserve that attempt and
ask for guidance. The experiment runner also refuses to overwrite run outputs.

## 5. Qualify, run, inspect, and export

Follow the package's main experiment instructions. Typical commands are:

```bash
cd /opt/oran-home-lab
sudo python3 scripts/home_lab_run.py --qualify --acknowledge-isolated-vm
```

Review the qualification result. Continue only if it passed. Substitute the
exact qualification session path printed by the tool:

```bash
sudo python3 scripts/home_lab_run.py --run-pilot \
  --qualification results/local/handoff_runs/REPLACE_WITH_QUALIFICATION_SESSION \
  --repetitions 3 --acknowledge-isolated-vm
```

Keep failed attempts and logs. Do not adjust policies or workload parameters to
obtain a preferred result. Review the exported file list for private information
before sharing. The example date in the output filename can be replaced by the
actual run date; use a new name for each export:

```bash
sudo python3 scripts/portable_bundle.py return --reviewed-for-sharing \
  --output /opt/oran-home-lab/deliverables/ORAN_HOME_RESULTS_YYYYMMDD.zip
```

This produces the result ZIP and adjacent `ORAN_HOME_RESULTS_YYYYMMDD.zip.sha256`.
The packet runner uses a deterministic reference controller, not a live AI model.
No API key or private account information belongs in the result archive.

## 6. Put only the result ZIP pair on the transfer disk

Recheck the labeled device and size as in step 4. Reuse neither an assumed disk
name nor stale variables from another console session. Mount **that same verified
partition** with write access, again using `nosuid,nodev,noexec`:

```bash
sudo mount -t vfat -o rw,nosuid,nodev,noexec "$oran_transfer_partition" /mnt/oran-transfer
python3 -m json.tool /mnt/oran-transfer/TRANSFER_ID.json
```

Compare the transfer ID again. Copy with no replacement; these examples assume
the output filename used above:

```bash
test ! -e /mnt/oran-transfer/RETURN/ORAN_HOME_RESULTS_YYYYMMDD.zip
test ! -e /mnt/oran-transfer/RETURN/ORAN_HOME_RESULTS_YYYYMMDD.zip.sha256
sudo cp --no-clobber -- /opt/oran-home-lab/deliverables/ORAN_HOME_RESULTS_YYYYMMDD.zip /mnt/oran-transfer/RETURN/
sudo cp --no-clobber -- /opt/oran-home-lab/deliverables/ORAN_HOME_RESULTS_YYYYMMDD.zip.sha256 /mnt/oran-transfer/RETURN/
(cd /mnt/oran-transfer/RETURN && sha256sum -c ORAN_HOME_RESULTS_YYYYMMDD.zip.sha256)
sync
sudo umount /mnt/oran-transfer
sudo poweroff
```

Wait until Hyper-V reports **Off**. In VM Settings, remove **only the 1 GiB
ORAN-TRANSFER.vhdx attachment**. Removing the attachment must not delete its file.
Do not remove the Ubuntu system disk. Confirm the transfer VHDX is no longer
listed in the VM. If a snapshot references it, stop and request guidance; do not
delete checkpoints or merge disks merely to bypass this check.

## 7. Collect the result on Windows

Back in the elevated PowerShell at the extracted `oran-home-lab` directory:

```powershell
./scripts/vm/prepare_transfer_disk.ps1 -Collect
```

This refuses an active VM or any VM/snapshot attachment, checks the recorded disk
identity, mounts it **read-only**, validates each ZIP's SHA256, copies ZIP/checksum
pairs to a new directory, and then dismounts it. It does not format or delete
anything. Its output identifies:

```text
oran-home-lab/.vm-local/returned/run_<UTC>_<random>/
  ORAN_HOME_RESULTS_YYYYMMDD.zip
  ORAN_HOME_RESULTS_YYYYMMDD.zip.sha256
  collection_receipt.json
```

Upload the **result ZIP and matching `.sha256`** in the original research
conversation. Keep the host-only collection receipt for your records. Do not
upload the VHDX, Ubuntu password, host account information, or whole `.vm-local`
directory. If result collection fails, keep the original disk and error text;
the authoritative logs remain inside Ubuntu and on the transfer disk.

## First-use stop conditions

- No `ORANXFER` device or more than one: stop; do not guess.
- Unexpected size, transfer ID, source hash, or result hash: stop.
- A script reports that a disk is boot/system, RAW state changed, the UniqueId
  changed, or there is an existing path: stop; do not weaken the guard.
- Windows collection has no automatically assigned drive letter: stop and ask
  for the exact error to be reviewed; do not format the disk.
- An operation fails or the computer reboots mid-transfer: retain all files;
  manually verify which environment owns the mount before continuing.
- Never attach the disk to Ubuntu after a failed Windows dismount. The helper
  prints a warning if cleanup cannot dismount it.
