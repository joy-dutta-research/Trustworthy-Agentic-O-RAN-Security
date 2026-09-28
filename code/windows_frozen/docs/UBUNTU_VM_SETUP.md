# Isolated Ubuntu VM preparation

**Preparation instructions, not an installed or qualified environment.**
Creating a VM does not install Ubuntu, validate traffic isolation inside the
guest, or produce experiment results. Installation, source transfer, Linux
qualification and the packet experiment remain separate checkpoints.

## Chosen configuration

Use the existing Hyper-V installation with a new Generation 2 VM named
`ORAN-Security-Lab`: four virtual processors, 4 GiB static RAM and a dynamically
expanding VHDX with 40 GiB maximum capacity. The guest has **no virtual network
adapter**, no automatic startup and no automatic checkpoints. Secure Boot stays
enabled with the `MicrosoftUEFICertificateAuthority` Linux template.

The current host audit found Windows 11 Education, 32 GiB RAM (approximately
12 GiB available at audit), eight CPU cores and approximately 216 GiB free on
the system drive. These are observations, not a performance guarantee. The
creation script checks memory and disk headroom again before mutation.

**Permission checkpoint:** Hyper-V is present and running, but the current
account/session is neither elevated administrator nor authorized to manage
Hyper-V. An owner-approved administrator or institutional IT must perform the
creation and console steps. Do not add this account to administrative groups,
disable security controls or change PowerShell execution policy to work around
the restriction. If policy blocks the reviewed script, ask IT to run it using
the organization's approved method. Type any administrator credentials only
into the operating system's trusted prompt, never into chat, source files or
the repository.

## Installation media and private artifacts

All local VM artifacts are under the repository's ignored `.vm-local/`
directory. Do not commit or upload the ISO, VHDX, configuration, local account
information, console captures or receipts without a separate privacy review.

Pinned official image:

- Filename: `ubuntu-24.04.5-live-server-amd64.iso`
- URL: <https://releases.ubuntu.com/noble/ubuntu-24.04.5-live-server-amd64.iso>
- SHA256: `97f3d7ffb032c3eb3b23d2c8be9cc76e60c2c1f2c0146ba5ba9fe01cafae0fd8`
- Checksum list: <https://releases.ubuntu.com/noble/SHA256SUMS>
- Detached signature: <https://releases.ubuntu.com/noble/SHA256SUMS.gpg>
- Expected Ubuntu signing-key fingerprint:
  `843938DF228D22F7B3742BC0D94AA3F0EFE21092`

The download/verification step must finish **before** VM creation. The creator
does not download anything and requires both:

```text
.vm-local/media/ubuntu-24.04.5-live-server-amd64.iso
.vm-local/media/ubuntu-24.04.5-live-server-amd64.iso.verified.json
```

The provided helper verifies Ubuntu's signing-key fingerprint, GPG signature
and complete ISO SHA256. On this computer, use the existing GnuPG installation:

```powershell
python .\scripts\vm\download_ubuntu_iso.py --gpg 'C:\Program Files\Git\usr\bin\gpg.exe' --download
```

If a download is interrupted, retain its `.part` file and use `--resume` on a
later invocation only after confirming the previous runner has ended. Do not
run two downloaders together or manually promote an incomplete image. The
exclusive `prepare.lock` is removed automatically on normal completion/error;
a forcibly killed process can leave a stale lock for careful owner inspection.

The verification receipt must contain `status` equal to
`VERIFIED_SIGNATURE_AND_SHA256`, `iso_sha256` equal to the pinned digest, and
`signing_key_fingerprint` equal to the fingerprint above. This receipt is the
output of actual signature and checksum verification, not a substitute for it;
do not hand-create a successful receipt. The creator rehashes the ISO itself.

Use the official Server ISO, not an Azure VHD or an unofficial prebuilt VM.
Canonical says its published Azure VHD artifacts are not usable for local
Hyper-V deployment. A QCOW `.img` also cannot be made into a VHDX by renaming it.

## Plan, review and create

From the repository root, the default command is read-only. It needs neither
administrator access nor Hyper-V management permission:

```powershell
.\scripts\vm\create_oran_vm.ps1 -Plan
```

After the media is verified and an administrator has reviewed the script, run
this in an approved elevated PowerShell session:

```powershell
.\scripts\vm\create_oran_vm.ps1 -Create
```

The script refuses to reuse an existing VM with the same name or an existing
VM directory/disk. It does not change Windows features, services, groups,
execution policy, virtual switches or physical adapters. It does not restart
Windows or start the VM. Newly created resources are confined to:

```text
.vm-local/vms/ORAN-Security-Lab/
```

Successful creation includes configuration readback and a local
`creation_receipt.json` with status `CREATED_STOPPED_OS_NOT_INSTALLED`. A failure
preserves the partial resources and original error; it does not delete them or
silently retry over them. Ask the owner/IT to inspect any partial setup before
deciding its disposition. Do not delete unrelated VMs or disks to resolve a
name collision.

## Owner-operated offline installation

1. Open **Hyper-V Manager** using authorized access, select exactly
   **ORAN-Security-Lab**, and inspect its settings against the local receipt.
   Confirm zero network adapters and exactly one new 40 GiB virtual disk.
   No physical host disk or existing disk should be attached.
2. Open its console, start this VM and boot the attached Ubuntu Server ISO.
   Select the normal **Ubuntu Server** installation, not the minimized image.
3. Continue without a network connection. Do not attach the Default Switch,
   an external switch, Wi-Fi bridge or NAT just to proceed with installation.
   If the installer unexpectedly requires Internet access, stop and report the
   exact screen; do not improvise network exposure.
4. Use only the new 40 GiB virtual disk (approximately 43 GB in decimal units).
   The disk-formatting confirmation refers
   to that guest disk, not the Windows computer. The owner must inspect and
   confirm this target. Stop if the installer shows another disk or capacity.
5. Choose a local lab username and strong password privately in the console.
   Do not use production credentials or paste the password into chat. Skip
   optional third-party software and online account/service enrollment.
6. Complete installation. When prompted to remove installation media, eject
   the ISO from this VM's virtual DVD drive using its console/settings and
   continue the guest reboot. Do not reboot the Windows host. If the installer
   starts again, stop the guest and correct its media/boot order rather than
   reinstalling over an uncertain target.
7. Verify the installed guest boots and login works. Keep the VM disconnected.
   Record Ubuntu and kernel versions without publishing local credentials.

No automated password provisioning or unattended disk-formatting configuration
is used. Console installation intentionally retains the owner's disk and
credential checkpoints.

## What remains after installation

- **Source transfer:** prepare an allowlisted, checksummed code bundle with no
  raw datasets, API keys, private review mappings or host filesystem secrets.
  A separate read-only virtual ISO is preferable to automatic host sharing.
  The portable handoff now supplies an allowlisted code ZIP and a separate
  guarded offline FAT32 transfer VHDX route. See `HOME_MACHINE_RUNBOOK.md` and
  `HOME_VM_TRANSFER.md`. This transfer route has passed read-only checks but
  still needs first-use validation; it was not executed on this computer.
- **Guest qualification:** verify Python, `ip`, `tc`, `sysctl`, namespace/veth,
  netem and policing support; then verify owned-resource readback and cleanup
  under success and injected failure. Confirm no routes or interfaces connect
  the experiment namespaces to the management/host network.
- **Baseline preservation:** after installation and qualification, take an
  explicitly named clean checkpoint or export with owner approval, and record
  its provenance. This setup script does not claim such a checkpoint exists.
- **Pilot and results:** run the bounded reference-controller pilot only after
  qualification, retaining invalid/failed runs. Follow
  [the closed-loop protocol](closed_loop_protocol.md) and
  [the experiment status](CLOSED_LOOP_STATUS.md).

The non-LLM reference-controller pilot requires no API key. Live AI planning
would need a separately designed adapter and controlled API access; do not
connect the isolated traffic environment to the Internet for that purpose.
Blinded model reviews are not an implemented live planner.

This remains software packet-level network emulation, not O-RAN E2 signaling,
a radio testbed, a detector-accuracy benchmark or complete-system validation.

## Official sources

- [Ubuntu's pinned release directory](https://releases.ubuntu.com/noble/)
- [Ubuntu image verification](https://ubuntu.com/tutorials/how-to-verify-ubuntu)
- [Canonical cloud-image artifact limitations](https://ubuntu.com/docs/public-images/public-images-reference/artifacts/)
- [Microsoft: Generation 2 and supported Ubuntu guests](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/plan/should-i-create-a-generation-1-or-2-virtual-machine-in-hyper-v)
- [Microsoft: Generation 2 Secure Boot templates](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/learn-more/Generation-2-virtual-machine-security-settings-for-Hyper-V)
- [Microsoft: virtual switch configuration](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/get-started/create-a-virtual-switch-for-hyper-v-virtual-machines)

PowerShell Direct is documented for Windows guests, not Ubuntu. Do not assume
`Invoke-Command -VMName` supplies a network-free Ubuntu command channel. See
[Microsoft's guest requirements](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/powershell-direct).
