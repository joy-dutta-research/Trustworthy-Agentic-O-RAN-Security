# Threat model

## Purpose

This document states what the proof of concept protects, what it trusts, and
what remains outside its claims. It must be read with the experiment protocol.

The original dry-run gateway remains unchanged. The separate optional Linux
packet laboratory adds a new, explicitly privileged research boundary; see
`docs/closed_loop_protocol.md`. It trusts the dedicated VM/kernel, local worker
processes, operator-reviewed settings and local telemetry files. Target linkage
and hashes are not cryptographic authentication against a privileged local
attacker. It has no external destination, live LLM, or O-RAN connector. The new
reference controller is only an instrumentation component, not validated AI.
Namespace/traffic-control integration is untested until run on approved Linux.

## Protected assets

- Availability and policy compliance of O-RAN resources represented by a
  proposed action.
- Integrity of the pre-action decision and its reason codes.
- Separation between an untrusted planner and the dry-run executor.
- Reproducibility and provenance of the reported experiment.

## Trust boundaries

The candidate action, including its claimed agent identity, role, evidence
references, and approval fields, is untrusted. The authenticated principal is
supplied separately by the benchmark harness to model an authenticated
transport identity. The frozen policy file, principal registry, external approval
registry, active-action snapshot, benchmark code, and host clock are trusted
inputs for this offline experiment.

The engine therefore does not accept an asserted identity, role, or in-band
human approval on its own. It binds the proposal identity to the out-of-band
principal, verifies its role, and verifies approval against a separately loaded
registry record bound to the exact proposal.

## Considered adversarial behaviour

- Unknown, missing, excessive, cyclic, deeply nested, or non-finite inputs.
- An agent claiming a more privileged role.
- A proposal claiming another registered principal's identity.
- An action sent through an inappropriate interface.
- An action using the wrong target type, unexpected parameters, or a misleading
  control-parameter alias.
- A disruptive action targeting a protected slice.
- Parameters outside operator-approved bounds.
- A risk rating lower than the configured minimum for the action.
- Stale or future-dated requests.
- A forged, expired, or mismatched human approval.
- A concurrent action touching the same target and control parameter.
- Missing rollback information.
- Reuse of an already submitted action identifier at the dry-run executor.
- Substitution of a different proposal after an `ALLOW` decision.
- Malformed active-state data that could otherwise hide a conflict.
- Malicious or unexpectedly large dataset archive metadata.

## Security decisions

Hard violations produce `DENY`. Conditions needing an authority or conflict
resolver produce `ESCALATE`. If both occur, `DENY` takes precedence. Unknown
contracts and unknown actions fail closed.

## Explicit non-goals and residual risks

- The prototype never connects to a live RIC, SMO, CU, DU, UE, or executor.
- Principal and approval registries are offline fixtures. Production requires
  the caller to derive the principal from authenticated transport (not a request
  header), signed or integrity-protected approvals, rotation, revocation, and
  secure storage.
- The checksum on an audit record detects accidental changes; it is not a
  digital signature or immutable ledger.
- Conflict checking covers direct overlap of a target and control parameter. It
  does not claim to detect indirect KPI or implicit ML-policy conflicts.
- Policy correctness is not proven by code correctness. Operator rules require
  domain-owner review, change control, and independent testing.
- The conformance suite demonstrates enforcement of frozen policies; it does
  not estimate the prevalence of unsafe actions in operational networks.
- Dataset labels provide incident context and do not prove that a mitigation
  will improve post-action KPIs.
- Evidence references provide traceability but are not an incident-authentication
  protocol. Production must bind detector evidence, target, and freshness using
  an authenticated evidence service.
- The in-memory replay set is sufficient only for this dry run. A production
  executor requires durable, atomic idempotency storage across processes.
- A party able to replace the policy, code, approval registry, active-state
  feed, or system clock can affect decisions. Release hashes expose changes but
  do not prevent compromise.
