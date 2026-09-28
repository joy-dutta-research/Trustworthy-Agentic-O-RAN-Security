# Order 6: qualify, pilot, freeze, measure, reproduce

## 1. What already exists, and what must be completed here

The supplied Linux code implements a deterministic proposal controller, four
methods, three scenarios and a 36-episode technical pilot (three repetitions).
Pilot seeds change method/episode order; they do not establish traffic-parameter
robustness. `home_lab_run.py --run-pilot` is intentionally not a final-study
command. Do not bypass its limits or rename its output.

This handoff authorizes development of a **separate final-study version**,
following the requirements below. The original gateway, policy, existing pilot
release and historical Windows results stay immutable. No final packet benefit
has yet been measured. Positive results are not a completion requirement.

## 2. Host and guest setup: follow the existing safety route

First verify the outer bundle using `scripts/workstation_bundle.py verify-tree`.
Extract `stage6_bootstrap/ORAN_STAGE6_PILOT_v2.zip` into a NEW sibling directory
outside the outer `oran-workstation-lab`, e.g. `guest-workspace/oran-home-lab`.
Use the **child folder as the working directory** for every legacy VM helper.
Keep its original ZIP and supplied SHA. Never mix host VM state directories
created by two different extractions.

Read the child's `docs/HOME_MACHINE_RUNBOOK.md`, `docs/UBUNTU_VM_SETUP.md`,
`docs/HOME_VM_TRANSFER.md`, and relevant scripts completely. They supply the
exact plan/create/download/transfer commands and disk-identity safeguards.
In their old examples, replace only the old `ORAN_HOME_LAB_v1.zip` pathname
and hash with the actual v2 child ZIP and its verified sidecar value. An old
description of university hardware is not an inventory of this workstation.

Check Windows edition, CPU virtualization/SLAT, firmware state, available disk,
trusted Python 3.11+ and GPG, and Hyper-V availability. Use read-only `-Plan`
first. Ask the owner before installations, Windows feature changes, reboot,
or elevated creation of the new lab VM. Do not silently substitute WSL,
Docker, another hypervisor, bare-metal Linux, or a production machine.

The existing route authenticates the official Ubuntu Server installer using
the pinned SHA and Ubuntu CD-image signing key. It creates a new 4-vCPU,
4-GiB, 40-GiB-disk VM with zero NICs. The owner confirms the NEW guest disk
and privately enters credentials in its console. No Windows disk is erased.

Guest tools: Python 3, iproute2 (`ip`, `tc`), procps (`sysctl`), kmod for
diagnostics. If offline installation lacks tools, pause for an explicitly
approved provisioning step. No measurements with any VM NIC attached, host
bridge, NAT, external interface, default route or unexplained namespace.
Do not expose SSH/RDP simply to give the assistant guest access.

The existing offline transfer disk is **1 GiB**, newly created and identity
checked. Transfer the small child ZIP, not the outer replay data or raw datasets.
Host and guest must not mount the same disk concurrently. Check free space
before each return. Never silently resize, format, replace or reuse a disk.
If evidence outgrows it, request a separately validated transfer plan while
preserving every attempt. Run destination experiments only after isolation
checks, and only inside uniquely owned lab namespaces.

Plan a reviewed offline deployment step for **each revised source release**.
The assistant may need to author final code in a separate Windows sibling
workspace and ask the owner to operate the guest console. The current transfer
helper creates `SOURCE.zip` once; it has no update-input mode and refuses an
existing transfer disk. Preserve that original file. Use fresh versioned release
names, checksums and provenance through a separately approved, validated transfer
mechanism; never overwrite `SOURCE.zip`, rerun disk creation on an existing disk,
or attach networking simply to make iterative development convenient.

## 3. Technical qualification and pilot

Verify the child source tree; run unit tests and its qualification workflow.
Record environment, source hashes, exact commands, topology, kernel queue/
policer readback, traffic receipts, and cleanup evidence. Existing qualification
at 10,000 kbit/s is not enough by itself: final qualification must also establish
the bottleneck at the actual 1,000-kbit/s study setting, baseline headroom,
overload response, mitigation impact on suspect ingress, and restoration.

Use the documented pilot with three repetitions (36 episodes). It answers
whether the lab and measurement mechanism work and informs variance/runtime,
not whether the paper's claims are proven. Keep all pilot results separately.
The original baseline payload load is 901.12 kbit/s before headers; do not
casually lower capacity or change legitimate load to force a benefit. Qualify
the unperturbed network's measured delivery and account for packet overhead.

## 4. Required final-study implementation

Create a fresh versioned source copy. Use the original gateway as an unchanged
component; implement new orchestration/adapters/configs with their own tests.
Document exact differences from the delivered pilot. Keep the original child
manifest as received; create a new release manifest and requalify new code.
Do not recompute the old manifest in place to make modified code appear original.

Keep the four methods: `no_action`, `fixed_rule`, `current_gate`,
`evidence_feedback`. The latter adds corroboration and outcome feedback, not
an LLM. Use the same proposal controller and target vocabulary. All methods
share containment, action TTL, timeouts and final cleanup. Report early
feedback rollback separately from TTL expiry and end-of-episode cleanup.

Implement and qualify these scenario families:

1. Persistent overload: assess legitimate service recovery when a suspect
   source is restricted. Include independently varied bounded workload
   intensity and duration, not only shuffled execution order.
2. Transient benign burst: count inappropriate restrictions of the benign
   source and its lost delivery, including cases where corroboration fails.
3. Ineffective actuator: the action is recorded but deliberately does not
   take effect. Measure detection/escalation delay; a no-op is not proof of
   successful reversal of harmful actuation.
4. Harmful wrong-target actuation: the common controller proposes the same
   policy-permitted suspect action, but a separately logged lab fault injector
   applies a restrictive policer to the synthetic legitimate-client ingress.
   This is a scoped **actuator fault**, not a change in the policy or a hidden
   favorable proposal. The controller receives only measured telemetry, not
   the fault flag. Verify actual wrong-target kernel state and service harm;
   feedback may restore the prior owned state early. Other intervention
   methods retain the identical TTL backstop. No-action has no actuator fault
   because it takes no action. Measure restoration readback AND service
   recovery, retaining cases with no observed harm or no recovery.

Traffic/fault generators and the offline scorer may know ground truth. The
controller cannot access scenario names, true labels, future schedules, seed
identities encoding labels, or injected-fault flags. Tests should demonstrate
this separation. Keep independent packet receipts/timestamps, offered and
received counts, and legitimate and suspect metrics, not just action logs.

The pilot assumes 400 packets/s and derives an absolute cap from it. Generalize
the final workload/cap mapping explicitly. The actuator must receive a declared
absolute rate derived from observable/declared reference information, not hidden
true attack intensity. Log both the requested reduction and effective kernel
rate. Qualify each rate family. Never quietly change what an 80% reduction means.

Add failure-path tests: wrong namespace/target rejected, malformed config,
readback mismatch, missing/stale telemetry, TTL safety expiry, crash cleanup,
restore-idempotence, and source/protocol-change refusal. Clean only owned
objects; fail closed and retain evidence when ownership is uncertain.

## 5. Freeze the scientific design before final data collection

Use the technical pilot to estimate runtime and episode-level variability.
An initial design candidate is two bounded intensities and two event durations
for sustained/fault scenarios, multiple benign burst durations, and 20 paired
seed blocks per condition. This is a planning candidate, **not a frozen powered
sample size**. Freeze exact conditions/repetitions only after checking technical
feasibility and a stated practical precision target; show the owner the runtime
and disk budget. Pilot-informed variance cannot guarantee a future CI width.
The candidate final campaign plus clean repeat can require many hours; the
36-episode pilot runtime must not be presented as the whole remaining workload.

The immutable, timestamped protocol must specify:

- exact workload cells, fixed seed list, method order randomized within paired
  blocks, repetitions, source/config hashes and environment;
- primary contrast(s), e.g. evidence_feedback versus current_gate, with fixed
  reference windows and sign conventions; all four methods still reported;
- primary legitimate delivery/recovery outcome and benign/harmful restriction
  outcome; secondary goodput, RTT, action delay, exposure duration, early
  rollback time, escalation and resource use;
- event-to-action and observation/decision/actuation boundaries. Do not replace
  end-to-end response time with the much smaller gateway processing time;
- episode-level uncertainty (paired-block bootstrap or another justified
  method), bootstrap seed/draws, and descriptive/multiplicity treatment;
- technical-invalidity, missing-pair, timestamp failure, recovery-censoring and
  retry rules. Report all exclusions and failed attempts. No recovery is
  censored/failed as declared, never a zero latency. Packet counts are not
  independent episode replications;
- fixed stopping/resource budget. No increasing samples until significance or
  discarding unfavorable seeds. Retain pilot/development data outside final
  estimation. Any later protocol revision creates a new labelled experiment.

Run sequentially with the host quiet, not alongside Stage7 performance. Record
thermal/power mode and background-work limitations without disabling security
software or forcing unapproved power settings. High-end hardware may alter
timings; it does not guarantee improved scientific outcomes.

## 6. Completion and clean reproduction

Final evidence needs a cell inventory, complete paired-block accounting,
independent packet metrics, owned actuator readback, rollback/recovery evidence,
episode-level uncertainty and traceable analysis code. Export negative and
inconclusive outcomes equally. Record any invalid condition explicitly.

Then copy the frozen final release into a clean source/environment, preferably
a new equivalently isolated VM after owner approval, and rerun the declared
protocol without retuning. Retain both attempts. This is a same-hardware clean
environment repeat, not a second physical packet-test machine or independent
research-team validation. If the owner declines another VM, document the exact
weaker clean-state reset; do not label it a clean OS install.

Follow `WORKSTATION_RETURN_SCHEMA.md` to bring every attempt, source version and
protocol back to the outer Windows result tree. Stop and report an unmet safety
or validity condition instead of producing a fabricated successful result.

## Interpretation boundary

The strongest defensible added claim, if supported by measurements, is that
evidence and feedback improved specified service/action outcomes in an isolated
packet emulator with a deterministic controller. It is not a trained-detector
evaluation, RAG/LLM benchmark, standards certification, real E2/A1 control, or
complete agentic O-RAN security validation.
