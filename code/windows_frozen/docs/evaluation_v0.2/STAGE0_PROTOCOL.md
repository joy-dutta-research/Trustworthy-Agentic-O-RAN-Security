# Stage 0: preserve the baseline and capture the study specification

Status: technical preparation for staged evaluation; no new comparative
experiments run by this document. Design version 0.2 refers to the evaluation,
not a new version of the original policy or gateway.

## Authorization and scope

On 2026-09-23 the user authorized beginning the staged plan and then explicitly
selected: keep the original policy unchanged and disclose the rollback-policy
limitation. Existing policy, source, prior results and portable v1 ZIP remain
unchanged. This does not authorize live traffic, operating-system administration,
an external API call, publication or upload.

Stage 0 creates a separately authored reference table, a machine-readable
study design, and a checksummed baseline inventory. It does not falsely claim
that future generators, workload distributions or the executable oracle are
already implemented, independently reviewed, or frozen.

## Artifacts

- `POLICY_DECISION_TABLE.md`: six-action matrix, fourteen rule groups, exact
  boundary semantics, witness requirements and known specification gaps.
- `configs/evaluation_v0.2/reference_policy_v0.1.json`: declarative companion,
  original policy digest, legacy semantics and claim limitations.
- `configs/evaluation_v0.2/study_design.json`: seed purposes, sample and run
  budgets, illustrative sensitivity settings and finite resource ceilings.
- `baseline_spec.json`: explicit reviewed allowlist for inventory, historical
  digest pins and provenance-only entries. It must not enumerate home folders,
  credentials, private reviewer crosswalks or unrelated downloads.
- `scripts/freeze_evaluation_baseline.py`: new-directory-only hash inventory
  and read-only verification. This is preservation tooling, not a benchmark.

## Preservation and provenance

Directly rehash the selected 5.4 MB NetsLab database, the 28 MB 5G-NIDD archive,
original policy/core files, named result directories, approved specification
files, and existing portable ZIP. Verify supplied historical hashes rather than
merely blessing today's bytes. Record size and SHA-256 with relative paths.

The approximately 24 GB parent NetsLab archive is NOT rehashed here. Its
extraction receipt attests the selected member; it does not contain a full
parent-archive SHA-256. The inventory must report that distinction, never call
the parent archive directly verified or assign it the member's digest.

Hash inventories detect changes; they are not immutable backups, digital
signatures or protection against someone replacing both files and manifest.
Preserve the originals in place; do not delete, move, commit or upload them.

New tooling or tests added after Stage 0 will legitimately change the complete
source inventory. Record that change as a new stage-specific freeze. Never
rewrite the old manifest or treat an expected added file as corruption of the
historical original policy. Original-result and core pins must still match.

## Completion criteria and next gate

Stage-0 technical preparation is complete when:

1. New specification/helper tests pass and the existing regression suite passes.
2. Historical core, selected dataset and bundle digests match.
3. The new inventory is generated into a fresh directory and immediately
   reverified, including tracked additions/missing/changed files.
4. User preservation choice and all identified limitations are recorded.
5. No result is labelled as a new robustness, timing or effectiveness finding.

Next: implement and test the independent declarative oracle and systematic
validity generator in Stage 1. Freeze their exact source, fixtures, coverage
model, mutation list and analysis before running comparative tests. Author
verification of the reference table is still required before publication;
preserving legacy behavior does not validate its operational adequacy.

## Resource and measurement discipline

The design records initial conservative limits: at least 10 GiB free disk,
at most 5 GiB new outputs/run, 2 GiB worker RSS and one hour per offline runner.
They are ceilings, not predictions. Large-run preflight must reject unsupported
resource monitoring. An exceeded limit produces an incomplete retained run,
not a passing or silently reduced experiment. A separate instrumentation-only
pilot may justify a versioned change before comparative measurement.

Reference dates are logical per-case dates for offline policy/timing tests.
Do not allow wall-clock time during long runs to change approval/TTL outcomes.
VM lifecycle expiry is a separate experiment. Data-selection seeds, generated-
control seeds, timing-order seeds and arrival-order seeds have different
meanings and cannot all be called independent dataset repetitions.

Run manifests must record missing/excluded cases and generator limitations.
No best-seed selection, deletion of failures, pooling of repeated timing calls
as independent incidents, or claim that a policy-compliant false alarm is safe.
