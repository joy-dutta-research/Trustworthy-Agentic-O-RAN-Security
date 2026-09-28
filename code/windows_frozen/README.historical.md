# Trustworthy O-RAN Action Gateway

For the portable isolated-VM handoff, begin with [START_HERE.md](START_HERE.md).
It provides home-machine setup, offline transfer, qualification, pilot and
all-session result-return instructions. Packaging is not evidence of packet
execution; the initial home study remains a deterministic-controller pilot.

This repository is a small, deterministic proof of concept for evaluating an
O-RAN mitigation proposal **before** it reaches an executor. It implements the
Trust Boundary described in *Trustworthy Agentic O-RAN Security: From Threat
Detection to Safe Action, Governance, and Standardization*.

The research question is:

> Can an independent Trust Boundary prevent unsafe but syntactically valid
> O-RAN actions without rejecting legitimate actions or adding prohibitive
> latency?

The gateway does not detect attacks and does not call an LLM. It consumes a
candidate action from any upstream planner, detector, rule engine, or human and
returns one of three decisions:

- `ALLOW`: the proposal satisfies the configured policies.
- `DENY`: the proposal violates a hard safety or authorization constraint.
- `ESCALATE`: a human or conflict resolver must decide.

## Safety boundary

The original gateway and its two dataset-context experiments remain **dry-run
only**. They have no O-RAN credentials, RIC connector or actuation endpoint.
The mock executor cannot send proposals to a network. A separate, opt-in Linux
namespace laboratory has now been added; it can generate bounded packets and
modify traffic control **inside its own isolated namespaces only**. See the
closed-loop section below. It must not be run against a production network.

## Evaluation design

Four systems receive exactly the same proposals:

1. `direct`: accepts every proposal.
2. `contract`: checks only the action contract.
3. `contract_rbac`: adds a registered principal, role/action authorization, and
   interface allowlist, providing a stronger operational baseline.
4. `trust_boundary`: checks the contract, authorization, interface scope,
   action/target and action/parameter semantics, protected services, parameter
   bounds, action conflicts, risk-based approval, rollback information, and
   expiry.

The caller supplies an authenticated principal as out-of-band evaluation
context (representing an mTLS/API-gateway identity); the proposal cannot
authenticate itself. Roles are resolved through the frozen principal registry.
Human approval
claims are accepted only when an out-of-band registry record is bound to the
same action and agent. The public registry is an offline benchmark fixture, not
a production credential system.

The initial conformance suite has 120 well-formed cases: 20 safe base actions
and five controlled variants of each base action. The variants exercise
unauthorized access, protected-service impact, out-of-range parameters, direct
action conflicts, and missing human approval. This is a **policy-conformance
test suite**, not a claim of 120 independently observed network events.

Ten bases use plausible UE mitigations for five exact subcategory labels in the
downloaded NetsLab database (`DDoS_ACK`, `DDoS_ICMP`, `DDoS_SYN`, `DDoS_UDP`,
and `Probe_PortScan`). The other ten use xApp and A1-policy scenarios traceable to the public
O-RAN/ETSI threat model. These sources are kept separate to avoid presenting an
xApp governance action as if it had been observed in the intrusion dataset.

The dataset adapter profiles all 19 subcategories and selects five attack strata
plus a benign negative control without sampling individual rows. It exports
only counts and aggregate signal means. Raw third-party data is deliberately
excluded from Git.

## Quick start

Python 3.11 or newer is required. The core experiment has no third-party Python
dependencies.

```bash
python scripts/generate_conformance_suite.py
python scripts/prepare_netslab_contexts.py
python -m unittest discover -s tests -v
python scripts/run_benchmark.py --repeats 100
```

These commands run without package installation or network access. Installing
the project in a virtual environment is optional when the command-line entry
point is preferred.

To create a blinded review sheet for a co-author:

```bash
python scripts/export_label_review.py \
  --output review/private/reviewer-a.csv \
  --mapping-output review/private/review_mapping.json \
  --create-blind-key
python scripts/export_label_review.py --output review/private/reviewer-b.csv
```

After two reviewers complete their copies:

```bash
python scripts/compare_label_reviews.py \
  review/private/reviewer-a.csv \
  review/private/reviewer-b.csv \
  --output review/private/agreement.json
```

The keyed ID mapping and completed sheets are ignored by Git and withheld from
reviewers until both reviews are complete. See `review/README.md`.

Generated outputs are written under `results/local/`. The release workflow will
copy reviewed raw decisions and summaries into a versioned results directory.

## Data placement

Place the downloaded NetsLab archive or extracted directory under `data/raw/`.
Do not rename its internal files. Run:

```bash
python scripts/inventory_netslab.py data/raw
```

The command is read-only and creates an inventory containing filenames, sizes,
candidate tabular schemas, and cryptographic checksums. It does not copy or
publish the third-party data.

For the published archive layout, extract only the small lower-layer database:

```bash
python scripts/extract_netslab_member.py /path/to/archive.zip
```

The extractor permits one exact member, enforces a 100 MB limit, validates the
archive path, writes atomically, and records a member checksum. It never extracts
packet captures or the upper-layer traffic corpus.

Inspect the database without exporting raw rows or UE identifiers:

```bash
python scripts/inspect_netslab_db.py
```

Then create the deterministic, de-identified context manifest. The command
requires the SHA-256 from the extraction receipt and fails on a different file:

```bash
python scripts/prepare_netslab_contexts.py
```

The current release contains no exact TCP-flood label, so the adapter does not
silently substitute ACK or another class. Its port-scan label also does not
establish UDP, so the replay uses the broader name `port_scan`.

## Reproducibility principles

- No OpenAI API key or commercial service is required.
- Policies and expected decisions are versioned.
- Input, policy, approval-registry, source-tree and output hashes are recorded.
- All proposals use synthetic identifiers; no IMSI or private topology is used.
- The final labels will be independently reviewed by at least two authors.
- Raw decisions are retained; aggregate numbers are generated from them.
- Timing blocks are randomized with a recorded seed; raw timing samples and
  Wilson 95% intervals are retained.
- The dataset version and SHA-256 checksums are recorded.
- Standards-based requirements are separated from illustrative operator policy.
- The Trust Boundary fails closed on malformed or unknown actions.
- Policy, approval, and suite loaders reject duplicate JSON keys and oversized
  security inputs.

## Scope limitation

Passing the gateway means only that a proposal conforms to the configured
pre-action policies. It does not prove end-to-end network safety, validate the
upstream detector, predict post-action KPI effects, or replace an operator's
change-control process.

See `THREAT_MODEL.md`, `docs/assurance_case.md`, and
`docs/reviewer_defense_checklist.md` before interpreting or publishing results.

## Second-source experiment: 5G-NIDD

The optional second-source test downloads the original, checksum-pinned
processed 5G-NIDD archive (about 28 MB), not packet captures. It requires network
access only for the download. No API key is needed:

```bash
python scripts/download_5gnidd.py
python scripts/run_5gnidd.py --output results/local/5gnidd_run1 --repeats 25
```

The runner reads the archived CSV without extracting or executing third-party
content, audits all records and selects a deterministic class-balanced sample.
It refuses to overwrite a prior run or evaluate changed comparator files.
See `docs/5gnidd_protocol.md` for the fixed sample, illustrative proposal rule,
input exclusions and the three separately reported evaluation groups.

This is record-conditioned policy-conformance testing with explicitly simulated
control targets, not O-RAN actuation or statistically independent field trials.
Forced false-alarm probes are reported separately: a compliant action on benign
traffic can pass the current gate because incident truth is not verified.

## Model-assisted blinded review

For the original 120-case suite, see `review/MODEL_REVIEW_GUIDE.md`. Model
reviewers receive the same policy and blinded case content with different
opaque IDs and order. Their outputs are consistency evidence, not replacement
human-expert validation or proof that illustrative operator thresholds are safe.
Private mappings and generated review packages are excluded from Git.

## New closed-loop experiment: implementation prepared, NOT RUN

The packet-level experiment complements the completed conformance tests. It
compares `no_action`, `fixed_rule`, `current_gate`, and `evidence_feedback`
under persistent overload, a brief benign burst, and an acknowledged-no-op
actuator fault. It measures real UDP request/echo traffic through a Linux
kernel bottleneck; it does not assign simulated KPI improvements.

**No packet-level mitigation results are available yet.** The development host
is Windows without a running Linux namespace environment. Unit tests use
mocked operating-system operations and do not establish kernel integration.
The implemented planner is explicitly a **deterministic reference controller**,
not a live LLM. No model API key is required for this reference-controller
pilot. Live agent planning and actual O-RAN interface integration remain
separate, unimplemented evaluations.

Read `docs/closed_loop_protocol.md` and `docs/CLOSED_LOOP_STATUS.md` first.
Inspect prerequisites without making changes:

```bash
python scripts/run_closed_loop.py --preflight
```

Only after the owner approves a disposable Linux VM/lab environment, and the
Linux isolation/policer smoke checks have been reviewed, explicitly opt in:

```bash
sudo python3 scripts/run_closed_loop.py --execute-isolated-lab --repetitions 1
```

This is a pilot, not a confirmatory paper result. It requires Python 3.11+ and
Linux `ip`, `tc` and `sysctl` plus namespace/netem/policing kernel support. The
read-only preflight checks availability, not kernel enforcement. No installer,
cloud access, external traffic, credential discovery, automatic privilege
escalation, or Docker/WSL startup is performed by the runner.

New outputs use unique directories under `results/local/`; existing results
and the frozen gateway/policy are never overwritten. Every method has bounded
traffic, finite action lifetime, scoped cleanup and explicit failure reporting.
Final scoring uses matched send cohorts with a 500-ms delivery deadline and
separately reports late replies and loss. A proposed LaTeX subsection is in
`docs/paper/closed_loop_experiment.tex`; it is marked **not yet executed** and
must not be presented as empirical evidence.

## Licence

The reference code is licensed under Apache-2.0. NetsLab-5GORAN-IDD is a
third-party dataset distributed under CC BY 4.0. The repository includes only a
de-identified aggregate manifest with attribution; it does not include raw data.
See `DATASET.md`.
