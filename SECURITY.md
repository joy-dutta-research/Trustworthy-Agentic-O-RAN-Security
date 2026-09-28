# Safe use and reporting

## Default: read and analyse

Repository verification, result-view generation and saved-evidence analysis are local operations. They do not need a model API key, network credentials, a VM or administrator privileges.

## Windows experiments

Run new measurements from a fresh prepared workspace as an ordinary user. Keep source, settings and original evidence immutable. The Windows supervisor applies its documented process/resource guards. Stop and inspect a failed or interrupted attempt; preserve it rather than deleting it to obtain a cleaner result set.

## Packet experiments

The packet implementation can generate bounded traffic and alter Linux network namespaces/traffic control. Execute it only with explicit authorization in a disposable isolated Ubuntu VM. Remove external network adapters for the experiment. Do not attach the lab to production networks, host bridges, NAT, a live RIC, an O-RAN radio stack or public interfaces.

Qualification, explicit execution flags, bounded rates, limited action lifetime, namespace ownership, configuration readback and cleanup checks are part of the protocol. Do not disable these safeguards to make a run succeed. If cleanup is uncertain, preserve logs and stop the lab; never delete broad namespace/interface patterns.

Historical transfer/host-administration launchers are provenance, not unattended public instructions. Do not reuse old disk identifiers, absolute paths or credentials.

## Reporting an issue

Before a public security contact is approved, report findings privately to the corresponding authors through their established institutional contact. Do not post credentials, private machine paths, live network identifiers or sensitive raw logs in a public issue. A public security contact can be added with the approved repository metadata.

Keep security fixes separate from the frozen scientific baseline. Document which version was evaluated and which version contains a later repair, with tests showing the intended behavior.
