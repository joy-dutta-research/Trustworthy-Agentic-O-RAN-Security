# 5G-NIDD second-source protocol v0.1

Status: specified before inspecting comparative results, 2026-09-22. Outputs
are preliminary until independent co-author scenario review. This is an offline
record-conditioned policy-conformance experiment, not live O-RAN replay, IDS
training, or validation of mitigation effectiveness.

## Fixed source and unchanged comparator

Use the authors' public 5G-NIDD release, DOI
https://doi.org/10.23729/e80ac9df-d9fb-47e7-8d0d-01384a415361 .
The original Fairdata metadata identifies CC BY 4.0 and open access:
https://metax.fairdata.fi/v3/datasets/9d13ef28-2ca7-44b0-9950-225359afac65 .
The processed `Combined.zip` is 28,028,224 bytes with SHA-256
`07531b251f3f35be70bf1d3dcca2e27274bd1b267c5a057c0fcea18668b9293d`.
No original attack scripts are executed. No packets or actions are sent.

Freeze these existing files before any second-source evaluation:

| File | SHA-256 |
| --- | --- |
| configs/paper_policy.json | bf5915cd92557ca193d692273021342e5bfa495878a0d4500742662497e6921c |
| src/oran_trust_boundary/engine.py | 8876b45a8188d1d33eaeead12178c09ca431a064cdc481b7d0072b7a865f57cd |
| src/oran_trust_boundary/baselines.py | 6cd02ac76aab4d1d8551eab6c4a78d7ac1d4ab2fd54b6502f53c3e59fc0568f4 |

The runner additionally pins the existing contract, policy validator, approval
verifier, models, audit and strict-JSON modules. This provenance hardening was
added after a development run was rejected because concurrent source edits
changed its source-tree digest. No policy, sampling, packet-budget or expectation
changes were made after observing development outputs. Strict CSV-grammar
rejection and clearer exclusion/zero-denominator reporting were also added.
The protocol hash is checked before and after evaluation.

## Population, sampling and observed inputs

Profile all CSV records and all attack labels. Report missing values, malformed
rows, invalid/nonfinite duration or packet counts, duplicate rows, and exclusions.
Use unencoded flow features, not the authors' training notebook. Do not impute
missing measurements or substitute zero for missing data.

Select up to 25 unique records per exact label `Benign`, `ICMPFlood`, `SYNFlood`,
and `UDPFlood` using smallest SHA-256 ranks over parsed row content after
excluding unnamed export-index columns. This gives a fixed, class-balanced
coverage sample, not an estimate of the natural traffic distribution. Retain
source row ordinals and opaque record IDs. Rows without usable duration/packet
counts are excluded from selection and counted. Attack records require strictly
positive duration and packet rate. Other attack classes remain in the data audit
but are excluded from this predeclared common-flood comparison.

Observed packet rate is `TotPkts / Dur` (packets per second). It is a per-flow
average, not a measured cell load, SLA, or instantaneous attack intensity.
Do not use dataset labels to claim detector accuracy: the experiment assumes
oracle incident labels and separately probes false alarms.

## Three separate evaluations

1. **Controlled conformance:** each selected attack record supplies six cases:
   compliant, unauthorized role, protected service, out-of-range parameter,
   direct conflict, and missing high-risk approval. Each selected benign record
   supplies one non-disruptive operator-notification control. These are policy
   expectations, not dataset-provided safe-action ground truth.
2. **Record-conditioned candidate proposals:** an explicitly illustrative
   upstream rule requests a reduction of
   `max(1, ceil(100 * (1 - 1000 / packets_per_second)))` percent for flood records.
   The hypothetical 1000 packets/s target is fixed in advance, is not a standard
   or calibrated network capacity, and does not establish appropriate mitigation.
   Do not clamp this group's proposals to the gateway's 80 percent bound. This
   tests what happens when measured input values change a proposal. Controlled
   conformance bases use `min(80, requested_reduction)` to isolate each rule.
3. **Forced false-alarm probes:** propose a compliant 30 percent reduction for
   each selected benign record. Report its admission separately, never as a
   safe-action acceptance success. The frozen engine does not verify incident
   truth; admitting these proposals exposes that limitation.

UE identity, interface, authority, slice, approval, rollback and clock values are
explicitly simulated control-context fixtures. A flow IP is not evidence of a
UE identity or authorization. No radio metrics, E2/A1 traces or operational
identity mappings are invented. The source-to-control identity resolver remains
outside the experiment's scope.

## Reporting and reproducibility

Use the existing direct, contract-only, contract-plus-RBAC and full gateway
comparators. They are controlled ablations, not state-of-the-art IDS competitors.
Record all proposals, decisions, reasons, source hashes, policy/source hashes,
timing seed, runtime version and timing samples. Default: 25 timing repetitions,
5 warmups per case, timing-block seed 20260922. Initialization, download, parsing
and file I/O are excluded from decision latency. Use a fresh output directory;
do not overwrite an earlier run.

Keep the three groups separate and report numerators and denominators. Omit
inferential confidence intervals: flow records, base-case variants and timing
repetitions are not independent safety trials. Report class coverage and number
of source records, not an inflated count of independent incidents. Where the
combined file does not expose trustworthy session/base-station identifiers,
state that limitation rather than creating them.

Preserve NetsLab results unchanged. No relative latency claim between separate
historical runs is justified. The final journal claim is limited to governance
conformance and local computation overhead under two data-source contexts.
Source-to-control identity verification, incident verification, learned-agent
quality, and post-action network outcomes are untested.
