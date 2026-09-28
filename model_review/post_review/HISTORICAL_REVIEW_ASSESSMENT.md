# Review round 1: returned-model comparison

Checked 2026-09-22. Original inputs were read without modification. The current
policy, action schema, approval fixture and original 120-case suite match the
versions used to generate the review packages. No policy or implementation
changes were made during this assessment.

## Outcome

Both reviewers returned every assigned review ID exactly once, with valid
package IDs and valid response structure. Opaque IDs were mapped through the
separate private crosswalks before comparison; display order was not used.

| Measure | Reviewer A | Reviewer B |
| --- | ---: | ---: |
| Complete, unique assigned cases | 120/120 | 120/120 |
| ALLOW | 20 | 20 |
| DENY | 60 | 60 |
| ESCALATE | 40 | 40 |
| INSUFFICIENT_INFORMATION | 0 | 0 |
| Case-level ambiguity flags | 0 | 0 |
| Agreement with constructed reference | 120/120 | 120/120 |
| Decisions with nonempty rule references | 120/120 | 80/120 |

Pairwise decision agreement: **120/120 (100%)**. Cohen's kappa: **1.0**.
The confusion table is entirely diagonal. These are descriptive consistency
results for a constructed suite, not detection accuracy, physical-safety
accuracy, or a population estimate. Variants share base scenarios. There are no
decision disagreements to adjudicate, but agreement does not establish that the
policy assumptions are adequate.

Scope: the original suite contains 60 NetsLab-label-context fixtures and 60
standards-context fixtures. These reviews do **not** cover the later 5G-NIDD
experiment. No source paper's standards claims were independently verified by
this closed-material review.

## Review quality and critiques

All 240 rationales/notes and both critiques were inspected. No apparent incorrect
decision was found under the supplied policy rubric. Reviewer A gives more
specific, checkable explanations of bounds, identity, approval binding,
time-boundary equality, conflict matching and denial precedence.

Reviewer B leaves `rule_refs` empty for all 20 ALLOW cases and all 20
conflict-based ESCALATE cases. This is permitted by the supplied schema and is
not a validation failure. The rationales are present and decisions agree; it is
a traceability gap, not evidence that the model ignored those checks. If needed,
request a separately preserved justification-only addendum. Do not replace the
first response or rerun to obtain a preferred agreement score.

### Substantive points to carry forward

| Point | Assessment | Appropriate next step |
| --- | --- | --- |
| Evidence references do not establish whether an incident is true | Valid scope limitation raised by both reviewers; also consistent with the separately reported 5G-NIDD false-alarm probes | State explicitly that the gateway checks policy conformance, not incident truth |
| Declared slice IDs do not prove all affected services/slices | Valid operational-assumption gap | Require authoritative target/dependency mapping before operational deployment; keep simulated mapping explicit in this PoC |
| Policy semantics are split between JSON and the instructions | Valid specification-maintenance concern | Version the complete normative specification together with its machine-readable settings |
| Same-action-ID exemption and lack of cumulative-action limits | Valid operational concerns outside the demonstrated cases | Define immutable action identity, lifecycle/concurrency semantics and cumulative disruption budgets in a separately scoped design |
| `rollback_policy` is absent from `disruptive_actions` | Confirmed in the reviewed policy; protected-slice restrictions therefore do not cover it under that rule | Obtain an explicit author/operator policy decision; do not silently alter the frozen experiment |
| Review suite does not cover all edge conditions or actions | Correct about this 120-case package, not the entire repository | Distinguish model-reviewed cases from existing unit tests; any expanded reviewer suite must be a new round |
| Generic parameter schema and rollback-procedure adequacy | Valid specification/validation clarity concern | Separate structural validation from per-action semantic constraints and operational adequacy |
| Observer permissions are restricted | Intended policy behavior, not by itself a defect | Do not loosen observer privileges simply because many observer proposals are rejected |

Two important qualifications to A's critique:

- Existing repository tests already cover several identity, stale/future request,
  TTL, approval-tampering/expiry and missing-rollback conditions. They were not
  all part of the model-review package. Do not describe them as wholly untested.
- The schema permits empty rollback text, but the engine rejects empty or
  whitespace-only rollback procedures for disruptive actions. This critique does
  not establish an empty-rollback execution bypass.

The active-action approval issue is also correctly distinguished in A's review:
the supplied rubric checks structural active-state conflicts without
reauthorizing every active action. A mismatched approval on an active record is
not equivalent to a mismatched approval on the current proposal.

## Provenance and isolation limitations

The submitting author identifies A as GPT-6 Astra Ultra and B as Gemini Pro
Extended (the planned B setting was Gemini 3.1 Pro Extended). These are
**operator-reported identifications**. Both returned JSON files record
`not_available` for displayed model and mode, so the files do not independently
verify those names/settings. Obtain screenshots or an operator run log and keep
that evidence separately; do not overwrite the original model metadata.

A's accompanying run notes report complete attachment access and no consultation
of implementation results, expected labels, network sources or the other review.
They explicitly do not certify service-enforced isolation. Available forbidden
tools do not themselves establish that those tools were used. A reports an
input-display truncation resolved by reading complete smaller sections and a
Windows command-length failure resolved by writing the unchanged first response
in chunks. These are disclosed operational recoveries, not reported substantive
decision reruns; this assessment cannot independently reconstruct the full run.

B reports no tools used but no equivalent run-notes attachment was supplied.
That is an evidence limitation, not proof of an invalid or contaminated review.
Request a short separate log of model/mode, fresh-session use, files read,
whether prior results were visible, and any retries or formatting repairs.

## Suggested manuscript wording

> Two separately prompted model reviewers evaluated an answer-masked 120-case
> policy-conformance suite using the same policy specification. Both returned
> 20 ALLOW, 60 DENY and 40 ESCALATE decisions, with complete pairwise agreement
> (Cohen's kappa = 1.0) and agreement with the constructed reference labels.
> These results provide policy-interpretation consistency evidence, not
> independent validation of operational safety. Model identities/settings were
> operator-reported, and service-enforced isolation was not independently
> verified.

Do not call this human-expert review, certified blinding, independent ground
truth, or proof that either model is generally better. Final author judgement is
still needed for policy adequacy, scope and manuscript claims. Critiques do not
justify retroactive relabelling or threshold tuning in round 1.

## Files and immutable input digests

Machine-readable comparison: `comparison.json` in this private round directory.
The original returned files remain at their supplied locations.

| Original input | SHA-256 |
| --- | --- |
| A: review_result.json | 8829eb4e7737a01397c8b92d96630b22a2dae0654bd98653c1a23e53ac68a1c9 |
| A: run_notes.txt | fec9df118b0b24f011ab6c4a7741c8ff385a37ff3efd97b59ce2fac6a0ca253d |
| B: gemini-code-1790085564985.json | 265c8c07d36e39f4cb3a0c647f8cd06e627861f7e9b73f0f8f5f54054615dece |

To reproduce the metrics in memory, use `compare_model_responses` with the two
original response objects and the round's two private mappings. The comparison
CLI refuses to overwrite an existing `comparison.json`; retain that safeguard.
This report and the private crosswalks must not be included in a future blinded
reviewer's upload bundle.
