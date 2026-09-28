# Closed-loop implementation handoff — 2026-09-22

**IMPLEMENTATION PREPARED; PACKET EXPERIMENT NOT RUN.**

## Portable home-machine handoff

The source ZIP workflow is now implemented: start with `START_HERE.md`,
`HOME_ASSISTANT_PROMPT.txt`, and `docs/HOME_MACHINE_RUNBOOK.md`. It includes
strict source/return manifests, an offline VM transfer disk helper, measured
guest qualification, pilot orchestration, and an exporter retaining all
successful/failed sessions. No raw datasets or private reviewer mappings are
required. These additions do not mean a VM or packet experiment has run.

The first home execution is a **pilot**. Final sensitivity conditions,
repetitions and confirmatory analysis remain to be frozen after integration
evidence is reviewed. Unit tests and Windows plan-mode checks cannot substitute
for first-use Hyper-V/disk safety readback or real Linux kernel qualification.

## Available now

- Versioned pilot settings, frozen-original-comparator checks, and opt-in CLI.
- Independent namespaces, fixed internal targets, topology readback, finite
  UDP traffic, bounded ingress policing, readback and owned-resource cleanup.
- Reference controller with fresh two-window corroboration, proposal/evidence
  hashes, dispatch expiry, post-action feedback and missing-telemetry watchdog.
- Send-cohort deadline accounting, late/lost packets, per-window offered-load
  checks, server/client cross-checks, paired descriptive pilot summaries.
- Unit tests of logic and mocked OS/socket operations; no privileged packet
  test has run on this machine.
- Proposed manuscript insertion: `docs/paper/closed_loop_experiment.tex`.
  This is protocol text, not empirical findings; its page layout is unverified.

The original Downloads manuscript has not been overwritten. The existing
NetsLab and 5G-NIDD result directories and frozen policy/core remain unchanged.

Verification on the current Windows host: **157 unit tests passed** (the 99
existing tests plus 58 closed-loop tests); source/script compilation passed;
all nine checksum-pinned original comparator files matched their frozen
digests. These checks do not exercise real namespace packets or a live model.

## Confirmed environment blocker

**VM preparation update (2026-09-22):** the user selected an isolated Ubuntu VM.
Hyper-V is already installed and running; an official Ubuntu Server image
download and signature/checksum verification helper plus guarded VM creation
script are prepared. The current Windows account/session cannot manage Hyper-V.
An approved administrator or institutional IT must create the VM. See
`docs/UBUNTU_VM_SETUP.md`; creating a stopped VM is not installation or guest
qualification, and the packet experiment remains NOT RUN.

The current host is Windows. WSL reports no installed Linux subsystem;
the Docker client is present but its engine is not running. Read-only preflight
reports missing Linux/root/`ip`/`tc`/`sysctl` prerequisites. An execution request
fails closed with NOT_RUN before creating any namespace or result directory.
No operating-system installation or configuration change was made.

## Required next steps, in order

1. Select an owner-approved dedicated Linux lab host or disposable Ubuntu VM.
   A Linux lab machine is preferred if available; otherwise an isolated Ubuntu
   VM on this computer is suitable to investigate. WSL2 is a fallback requiring
   separate kernel/traffic-control verification. Do not use a production host.
2. Qualify the environment: kernel/iproute2/Python versions, CPU/RAM and load,
   namespace/veth/netem/u32-police support, no external lab routes, baseline
   connectivity, readback and cleanup under success and injected failure.
3. Execute and inspect a pilot. Unexpected topology/readback, pacing or logging
   failures invalidate the run and must be retained, investigated and fixed.
   Passing unit tests is not permission to skip this qualification.
4. Inspect achieved bottleneck and limiter effects using receiver measurements;
   a configured rate/policer readback does not prove achieved traffic rates.
5. Freeze the confirmatory settings, accepted variability/precision target,
   sensitivity conditions, repetitions and exclusion rules; run paired episodes
   and reproduce the findings on a second clean environment.
6. Only then generate the results table/timeline and replace the NOT RUN
   manuscript text with accurately bounded empirical findings.

## AI and paper claims

No API key is needed for the implemented **non-LLM reference-controller pilot**.
To evaluate actual AI planning, a separately chosen live model adapter, secure
credential provisioning, cost budget and new loop evaluations are still needed.
Never paste keys in chat or commit them. Blinded Astra/Gemini policy reviews do
not replace that experiment. No model superiority is currently claimed.

Even after successful Linux testing, this is a packet-level software-network
experiment—not E2 signaling, a radio testbed, a detector-accuracy benchmark or
validation of the complete agentic architecture. The acknowledged-no-op fault
tests ineffective-action detection, not reversal of an actually harmful change.

## Reproduction entry points

Read-only (current host supported):

```text
python -m unittest discover -s tests -v
python scripts/run_closed_loop.py --preflight
```

Opt-in, only on the qualified isolated Linux environment:

```text
sudo python3 scripts/run_closed_loop.py --execute-isolated-lab --repetitions 1
```

Outputs are new directories under `results/local/`. A default three-repetition
pilot comprises 36 serial episodes; each is bounded but the overall run will
take time. No guessed duration, performance benefit or safety guarantee is
promised. Review raw stderr/logs for local filesystem paths before any public
release. Nothing has been uploaded or committed by this implementation task.
