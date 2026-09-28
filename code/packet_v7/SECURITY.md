# Security policy

## Supported use

The original gateway is a research prototype for offline, dry-run evaluation.
The separate optional closed-loop harness operates only inside isolated Linux
network namespaces on an owner-approved disposable lab host. Neither component
is approved for production network actuation.

## Prohibited repository content

Do not commit:

- API keys, passwords, private certificates, or approval secrets;
- IMSIs, subscriber identifiers, or production topology;
- proprietary O-RAN specifications or copied standards text;
- raw third-party datasets unless their licence explicitly permits it;
- executable payloads or live-network connection details.

## Safe defaults

- Unknown actions and malformed contracts are denied.
- Proposal identity is bound to an out-of-band authenticated principal; claimed
  roles are checked against a separate principal registry.
- High and critical-risk actions require an external approval reference.
- Proposal-supplied approvals are rejected unless a separate registry verifies
  their binding to the action, agent, approver role, and expiry.
- Disruptive actions require an explicit rollback procedure.
- Original dataset-context evaluations remain within the mock executor. The
  optional packet laboratory requires explicit CLI opt-in and Linux lab root
  privileges; it never connects to an O-RAN or external execution endpoint.
- Policy files are treated as reviewed configuration, not model-generated text.
- Duplicate action identifiers are rejected by the dry-run executor.
- The executor checks that the `ALLOW` audit digest belongs to the exact
  submitted proposal.
- Security-relevant JSON rejects duplicate keys, non-finite constants, and
  oversized input files.

## Optional packet laboratory

Review `docs/closed_loop_protocol.md` before using `scripts/run_closed_loop.py`.
The privileged backend may create and delete only its newly owned namespaces,
create their internal virtual links/routes, and alter their private traffic
control. Workers reject the initial/host network namespace. The destination
and source identities are fixed private laboratory addresses, not user-supplied
network targets. Packet size, rate, episode length and episode count are bounded.

Containment is not a substitute for a disposable VM. A process forcibly killed
outside Python cleanup, a kernel crash, or a privileged local adversary can
defeat cleanup assumptions. Retain the owned namespace identifiers and inspect
any reported residue; never flush host networking as recovery. There is no
claim of hostile-tenant isolation, cryptographic sensor authentication, or
production-ready root-privilege separation. Linux integration is pending.

## Reporting a vulnerability

Until a public repository contact is configured, report security concerns
privately to the corresponding author. Do not open a public issue containing a
working exploit, credential, or sensitive network information.
