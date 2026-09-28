# Self-contained scientific context for the second workstation

## Goal and scope

Paper: *Trustworthy Agentic O-RAN Security: From Threat Detection to Safe Action,
Governance, and Standardization*. The small experimental contribution evaluates
an explicit action trust boundary and a controlled evidence/feedback loop. It
does not benchmark a full deployed agentic O-RAN system. Do not describe this
as a measured extension of the CSCN RAG planner: the planner is not executed.

Orders 0-5 were completed on the original university Windows workstation.
Read `EVALUATION_v0.2_PAPER_TAKEAWAYS.md` and the preserved
`reference/university/final_verified/REPORT.md` for detailed original evidence.
The comparison capsule is byte-preserved summaries and provenance, not a copy
of all original raw outputs. Its manifest lists its exact coverage.

## What the completed evidence says

- Original v0.1 policy is unchanged. A separate declarative reference, source
  freeze, targeted coverage and fault-injection tests were used. The common
  suite has 777 cases; 14/14 deliberately targeted mutants and 25/25 scoped
  property witnesses were detected/satisfied. This is not exhaustive proof.
- NetsLab: 20 control-generation seeds, 20,000 constructed proposals. The full
  gateway admitted 0/16,000 policy-block-required and 4,000/4,000 permitted cases.
- 5G-NIDD: the original full source reconciliation covered 1,215,890 rows;
  733,693 eligible records all generated permitted natural proposals, so their
  blocking denominator is not applicable. Twenty controlled panels produced
  95,000 conformance cases: 0/75,000 required-block admissions and 20,000 permitted
  admissions. Those 95,000 cases reduce to 162 normalized configurations.
- All 5,000 forced benign mitigation probes were admitted. Permission to act
  does NOT establish necessity or benefit. Panels overlap; seeds are not
  independent datasets. The 12 admitted common-suite legacy limitation probes
  remain admitted by design, not renamed safe actions.
- Twelve one-factor sensitivity conditions were completed. Several never
  crossed a decision boundary; do not claim they independently prove robustness.
- Original performance: 18 partitions / 1,820 cells. Mean paired block-p95
  difference, full gateway minus bypass, was 0.113 ms (NetsLab) and 0.093 ms
  (5G-NIDD), for the small declared mixture and original host only. These are
  differences of block percentiles, not a p95 of per-request overhead.
- No-conflict cost grew to approximately 19 ms at 1,000 active actions.
  With 100 active actions and a single consumer, all 100 proposals/s completed;
  only about 67% at 1,000/s and 14-15% at 5,000/s completed in the full gateway.
  Losses were queue overflow. Two generator-limited cells were retained.

This supports **bounded policy-conformance validity, declared-input robustness,
and local computational feasibility with explicit scaling limits**. It does
not establish detection accuracy, correct model reasoning, mitigation efficacy,
universal safety, production capacity, or genuine E2/A1/radio interoperability.

## Fresh Orders 0-7 scope chosen for this workstation

The user's final preference is a complete fresh Orders 0-5 rerun as well as
Orders 6-7. This is stronger than replay alone because it checks input processing,
case generation and sensitivity, not just repeated gateway calls. It remains
reproducibility on the same datasets, not external-dataset generalization.

The main source ZIP includes original frozen derived inputs and compact reference
evidence. A **separate private data companion** includes the exact 5,402,624-byte
NetsLab extracted database and 28,028,224-byte 5G-NIDD archive, with sanitized
receipts and attribution. No 24 GB parent archive is needed. Verify both raw
hashes; regenerate the NetsLab aggregate without replacing the included aggregate.
The full campaign reexecutes the natural census and all twelve sensitivity
conditions, then compares regenerated case/workload identities with the originals.
The original parent-archive extraction itself is not repeated or claimed verified
from the full parent archive on the destination.

Windows Orders 0-5 are the matched-environment primary comparison. Differences
still reflect more than CPU model alone (OS build, Python, background load,
power/thermal state). Record these; do not claim a causal hardware speedup.

## What the additional stages add

**Order 6:** isolated Linux packet-level network emulation. Compare no action,
fixed rule, current gateway, and additional evidence/feedback. Measure actual
service delivery, harmful restriction, response delays and rollback recovery.
The existing 36-episode pilot is a starting harness, not final measured evidence.
The added harmful-action scenario is needed because an ineffective no-op alone
cannot demonstrate successful reversal of a harmful configuration.

**Order 7:** close the full regeneration/performance comparison on the second
Windows hardware, optionally replay the frozen cases as an extra integrity
check, and perform a clean-source/environment repeat of the final Linux protocol.
The Windows measurements reuse the new Orders 0-5 campaign, not a duplicate run.
The former tests hardware-transfer reproducibility; the latter tests clean
environment reproducibility on the same workstation. Neither independently
validates the scientific policy assumptions. Do not pool their measurements.

No raw archives are in the main source ZIP; the separate companion is explicitly
for the requested full rerun. Original reviewer outputs, private manuscripts and
credentials are omitted. The replay-only option works without the companion but
does not regenerate the census and must not be relabelled a full rerun. Author verification
of standards locators, operator thresholds/protected-service assumptions and
paper claims is still required. Model-assisted consistency reviews are not
independent human-expert validation.

## Immutable policy limitation

`configs/paper_policy.json` SHA-256:
`bf5915cd92557ca193d692273021342e5bfa495878a0d4500742662497e6921c`.
The user explicitly chose to keep the original policy for comparison.
`rollback_policy` is not categorized as disruptive; the protected-service and
rollback-declaration restrictions therefore do not cover it. Report this
limitation. Stage6 restores an owned Linux lab configuration through its
separately documented experimental controller; do not claim this corrects or
validates the original policy's rollback semantics.
