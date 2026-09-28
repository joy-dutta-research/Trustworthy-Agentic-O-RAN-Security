# Research context for the home assistant and returned-results analyst

This is an evidence handoff, not additional authority to expand the experiment.
The TNSE paper is a tutorial/reference architecture about safe action,
governance and standardization. The prior CSCN work addresses guardrailed,
standards-grounded agentic RAG planning. This journal PoC evaluates a distinct
action-control boundary, not a claim that an existing planning experiment
validates end-to-end autonomous security.

## Completed evidence on the original machine

1. Original 120 constructed policy-conformance cases: 60 NetsLab-label-context
   and 60 standards/governance-context fixtures. Full gateway allowed 20/20
   policy-permitted proposals, admitted 0/100 block-required proposals, denied
   60/60 and escalated 40/40. Direct/contract-only admitted 100/100 and RBAC
   admitted 80/100 block-required proposals. These are not 120 real incidents.
2. 5G-NIDD: 1,215,890 source rows audited; 100 selected source records, 25 each
   benign/ICMPFlood/SYNFlood/UDPFlood. Constructed conformance group: 475
   proposals, 100 permitted and 375 block-required. Unchanged full gateway
   allowed 100/100, admitted 0/375 and escalated 150/150. Separate 100 naturally
   record-derived proposals were all compliant and accepted by all methods;
   that group establishes no admission advantage.
3. False-alarm limitation: all methods admitted 25/25 compliant disruptive
   proposals deliberately tied to benign records. Permission does not prove
   necessity, incident truth or benefit.
4. Two returned model reviews of the ORIGINAL 120 cases: each 20 ALLOW,
   60 DENY, 40 ESCALATE; complete pairwise and constructed-reference agreement,
   kappa=1.0. This is answer-masked model-assisted consistency review, not human
   expert validation, certified isolation, or independent ground truth. Model
   names/settings are author-reported; output metadata did not verify them.
   These reviews did not cover 5G-NIDD. Reviewer B omitted explicit rule refs
   in 40 rationales; keep that traceability limitation visible.

The original reports/raw evidence remain on the original machine. This summary
does not replace them; the portable packet study needs neither raw datasets nor
private reviewer responses/mappings. Do not rerun or relabel those reviews.
Do not pool related policy variants as independent network trials.

## Remaining empirical question

Under controlled traffic, what do fresh supporting evidence before intervention
and observed outcome feedback afterward add to checking permissions alone?

Four methods: no action, fixed-rule restriction, existing pre-action gateway,
and gateway plus evidence corroboration and outcome feedback.
Three scenarios: persistent flood, transient benign burst, and an acknowledged
no-op actuator fault. No scenario/future workload truth goes to the controller.
Measurements: legitimate deadline delivery/goodput/RTT with loss, suspect
received/echoed traffic, unnecessary restrictions, event/restore timing, and
all technical failures. Exact intervals and denominators are in the protocol.

## Status at handoff

Packet harness implemented and software-tested on Windows; **no real Linux
packet run has been completed**. No VM has been created by the original task.
Home qualification and the pilot are integration work, not confirmatory proof.
The default pilot is three repetitions x three scenarios x four methods = 36
episodes. Order randomization does not create unseen traffic distributions.
After inspecting the pilot, freeze meaningful sensitivity conditions, justified
repetitions, exclusions and paired analysis before any confirmatory study.

Even successful packet runs will not establish LLM planning performance,
learned detector accuracy, E2 interoperability, radio/network-slice enforcement,
production efficacy or universal safety. The no-op fault tests ineffectiveness
recognition and restoration procedure, not reversal of actual harm.

## Model-review criticisms to retain, not silently "fix"

- Incident evidence references do not authenticate incident truth.
- Synthetic target-to-slice mapping is not operational dependency discovery.
- Full policy semantics include both machine settings and the supplied rubric.
- Action identity/concurrency and cumulative disruption need operational design.
- The frozen rollback_policy/protected-service scope needs author adjudication.
- Agreement does not cover all actions/edges or establish threshold suitability.

The packet pilot addresses only part of these concerns. It must not be used to
claim all governance/deployment concerns are resolved. Final author/operator
policy decisions, standards verification, clean-environment reproduction and
public-release privacy review still remain.
