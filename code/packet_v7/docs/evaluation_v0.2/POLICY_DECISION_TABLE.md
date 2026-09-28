# Stage 0: declared policy decision table

Status: separately authored reference specification for the unchanged v0.1
policy. NOT a completed executable oracle, new experiment, or independent
human-expert validation. Author verification of this table remains necessary
before publication. Machine-readable companion:
`configs/evaluation_v0.2/reference_policy_v0.1.json`.

The user confirmed on 2026-09-23: keep the original policy for this evaluation
and report the rollback limitation. No corrective policy changes are authorized
by that decision. Preservation is not endorsement of operational adequacy.

## Decision combination

Invalid structural input is DENY. Otherwise evaluate all applicable policy
conditions: **DENY > ESCALATE > ALLOW**. A missing high-risk approval cannot
override a protected-service denial. An ALLOW means policy-permitted, not that
an incident is real, an intervention necessary, or a network outcome safe.

Expected outcomes will be computed by a separately implemented declarative
oracle in Stage 1, not by calling or duplicating production engine methods.
That oracle must distinguish written requirements from legacy-profile behavior
and retain disagreements. These documents do not make an oracle independent
of its authors or substitute for domain-author judgment.

## Action matrix

| Action | Interface / target | Authorized roles | Required parameter besides control_parameter | Minimum risk | Disruptive | Approval required by action |
| --- | --- | --- | --- | --- | --- | --- |
| rate_limit_ue | E2 / ue | responder, orchestrator, human_operator | reduction_percent: 1–80 inclusive | medium | yes | no |
| quarantine_ue | E2 / ue | responder, orchestrator, human_operator | duration_seconds: 1–300 inclusive | medium | yes | no |
| isolate_xapp | SMO / xapp | orchestrator, human_operator | duration_seconds: 1–600 inclusive | high | yes | yes |
| modify_a1_policy | A1 / policy | orchestrator, human_operator | policy_weight: 0–1 inclusive | high | yes | yes |
| rollback_policy | A1 / policy | orchestrator, human_operator | snapshot_id: key present; see limitation below | high | **no** | yes |
| notify_operator | SMO / operator | observer, detector, responder, orchestrator, human_operator | message: key present; see limitation below | low | no | no |

Here responder/orchestrator abbreviate security_responder/security_orchestrator.
High or critical risk requires approval even where the action column says no.
Each action requires exactly its two parameter keys and its fixed
control_parameter value; no other parameters may be silently accepted.

## Rules and independent witnesses

For each witness all unrelated conditions must pass. Legitimate modified
proposals need newly digest-bound approval fixtures. Time witnesses use a
fixed logical clock, not today's date.

| ID | Condition | Failure decision | Passing/boundary/failing witness |
| --- | --- | --- | --- |
| R01 | Frozen structural contract profile | DENY | correct shape / max allowed field length / missing or extra field |
| R02 | Out-of-band principal, claimed identity and registered role agree | DENY | matched responder / wrong claimed role / missing or forged principal |
| R03 | Role permits action | DENY | responder rate-limit / observer notification / observer rate-limit |
| R04 | Interface permits action | DENY | rate-limit on E2 / same action on A1 |
| R05 | Target type matches action | DENY | rate-limit ue / rate-limit policy target |
| R06 | Request age in [-30,600] seconds | DENY | ages 599,600,601; future ages -29,-30,-31; use sufficiently long TTL |
| R07 | No disruptive action on declared protected slice | DENY | best-effort rate-limit / public-safety rate-limit; rollback is out of scope |
| R08 | Exact parameter semantics and inclusive numeric bounds | DENY | reduction 79,80,81; numeric true is not 1; missing/extra key |
| R09 | Risk meets per-action minimum | DENY | medium rate-limit / low rate-limit |
| R10 | Bounded TTL and unexpired authorization | DENY | ttl 899,900,901; elapsed age ttl-1,ttl,ttl+1, without masking by freshness |
| R11 | Disruptive action declares available, nonblank rollback | DENY | present declaration / unavailable or blank procedure |
| R12 | Verifiable nonconflicting active state | ESCALATE | other target / same target-control / malformed active entry |
| R13 | Required approval is present, current and externally bound | ESCALATE | expiry after now / equal to now / revoked, absent or digest-mismatched |
| R14 | Winning severity and reasons are consistent | DENY before ESCALATE | protected-service violation plus missing approval must DENY |

The full bound matrix will include each minimum as well as each maximum, and
adjacent finite representable values for floating-point parameters. Generate
pairwise combinations and declared three-way combinations in Stage 1, with
coverage verified separately from case generation. These counts are not yet
claimed as achieved.

## Exact boundary and legacy-profile details

- Parameter limits are inclusive. Numeric action parameters accept finite
  integers/floats, not booleans. TTL requires an actual integer, not 900.0.
- Age exactly 600 seconds, future skew exactly 30 seconds, TTL exactly 900,
  and elapsed age exactly TTL pass those respective conditions.
- Approval expiry equal to the evaluation time is expired. Required approval
  must be approved and exactly bind action ID, agent ID, approver role, expiry
  string and the entire canonical proposal digest. Its authority is simulated.
- Unnecessary approval is still structurally parsed but is not checked for
  trust/expiry if neither action nor risk requires it.
- A structurally valid active action with the same action_id is ignored, even
  if its other content differs. Malformation is considered before that exemption.
- Conflict key: interface, target type, target ID, control_parameter. Parameter
  values need not differ. Cell/slice IDs and action name are not key components.
- Active-record timestamps/approval trust are not rechecked. Conflict scanning
  stops at the first conflicting or malformed record: the decision may remain
  ESCALATE while the specific reason changes with list order.
- snapshot_id and message have no extra value-type/nonempty/existence rules
  in the frozen per-action policy. Do not invent such a rule in the oracle.

## Structural-profile discrepancies to expose, not hide

The JSON schema is not equivalent to the Python parser. The latter rejects
whitespace-only required strings, imposes additional nesting/collection/string
and 4,096-byte parameter limits, requires true integer TTL, and accepts some
timezone-aware ISO timestamps beyond strict RFC3339 forms. JSON ingress also
has duplicate-key, size and non-finite-number rejection at its own boundary.

Stage 1 must distinguish schema-profile agreement from legacy parser-profile
conformance. No source/parser/schema change has been made. Any discrepancy
found becomes an explicit result or a separately approved new version, never
an expected label silently altered to match the implementation.

## Claims deliberately unavailable

No guarantee of incident truth, real target/slice mapping, snapshot existence,
working rollback, cumulative impact limits, distributed idempotency, indirect
conflict detection, external service authentication or tamper-proof logging.
Thresholds and interface/action mappings are illustrative operator fixtures,
not requirements mandated by O-RAN/ETSI.
