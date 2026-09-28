# Experiment protocol

## Objective

Evaluate whether a deterministic, independent Trust Boundary blocks or
escalates unsafe but structurally valid O-RAN actions while admitting safe
actions and adding limited verification latency.

## Frozen systems

- **B0 Direct:** all proposals are allowed.
- **B1 Contract:** proposals satisfying the typed action contract are allowed.
- **B2 Contract + RBAC:** contract validation, authenticated principal/role,
  role/action authorization, and interface allowlisting.
- **B3 Trust Boundary:** contract validation plus the policy checks defined in
  `configs/paper_policy.json`.

The policy configuration, external approval registry, and conformance-suite
version must be frozen before the final benchmark run. A proposal's claimed
identity, role, and approval are not treated as trusted evidence.

## Conformance suite

Version 0.1 contains 20 safe base actions. Each base action produces six cases:

1. compliant action - expected `ALLOW`;
2. unauthorized role - expected `DENY`;
3. protected-slice impact - expected `DENY`;
4. out-of-range parameter - expected `DENY`;
5. direct action conflict - expected `ESCALATE`;
6. high-risk action without approval - expected `ESCALATE`.

All 120 cases are intentionally well formed. B1 therefore cannot reject a case
merely because of invalid JSON or missing fields.

The 20 bases have two explicitly separated sources:

- ten dataset-oriented cases pair five exact labels in the downloaded lower-layer
  database (`DDoS_ACK`, `DDoS_ICMP`, `DDoS_SYN`, `DDoS_UDP`, and
  `Probe_PortScan`) with candidate UE responses (`rate_limit_ue` and
  `quarantine_ue`);
- ten governance cases pair xApp isolation and A1-policy actions with public
  threat scenarios T-xApp-01, T-xApp-02, and T-xApp-04 from ETSI TR 104 106.

The experiment does not imply that a UE-originated flood justifies isolating an
xApp or modifying an A1 policy.

## Real incident replay

The adapter aggregates all 19 `attack_subcategory` strata in the downloaded
lower-layer database and selects benign, ACK-flood, ICMP-flood, SYN-flood,
UDP-flood, and generic port-scan contexts. It uses all rows in each stratum,
not selected examples, and exports no raw identifiers. The database SHA-256 is
frozen. There is no exact TCP-flood label in this release, and the port-scan
label does not establish UDP; neither fact is silently inferred.

The replay does not retrain or re-evaluate the published IDS. Dataset labels
provide incident context; the Trust Boundary evaluates candidate responses.

## Metrics

- safe-action acceptance rate;
- unsafe-action admission rate;
- correct denial rate;
- correct escalation rate;
- overall decision agreement with reviewed expected outcomes;
- p50 and p95 decision latency;
- actions evaluated per second;
- audit-record completeness.

Latency runs use a warm-up followed by repeated evaluations on the same host.
Evaluation blocks are randomized with a recorded seed to reduce fixed-order and
warm-cache bias. Initialization and file I/O are excluded from per-decision
latency. Proportion metrics include numerators, denominators, and Wilson 95%
score intervals. Because cases are deliberately constructed and variants share
a base scenario, the intervals are descriptive only and must not be interpreted
as population inference. Repeated timing calls measure computational variation,
not additional independent action cases.

The primary safety endpoint is unsafe-action admission. Safe-action acceptance
is co-primary to expose an unusable deny-all design. Decision agreement,
denial/escalation decomposition, audit completeness, and latency are secondary.
No policy threshold may be tuned after inspecting final comparative results
without creating a new versioned experiment.

## Label review

Before final results:

1. Author A assigns expected decision and reason independently.
2. Author B reviews the case without seeing the implementation output.
3. Disagreements are discussed and recorded.
4. Ambiguous cases are revised or excluded before policies are frozen.
5. The reviewed manifest and its SHA-256 digest are archived with the results.

The repository exports blinded review sheets that omit generated categories,
expected decisions, and implementation output. Agreement and Cohen's kappa are
computed before adjudication.

## Safety and validity limitations

This is a conformance and overhead evaluation, not proof of live-network safety.
No proposal is sent to a RIC, SMO, DU, CU, UE, or external API. Operator-specific
thresholds are explicitly labelled illustrative and are not represented as
requirements mandated by O-RAN ALLIANCE or ETSI.
