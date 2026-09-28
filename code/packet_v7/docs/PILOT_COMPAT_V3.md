# Pilot compatibility release v3

This is a separately versioned correction, not the delivered v2 source.
The original v2 archive, manifest and both failed guest attempts are preserved.
The received v2 manifest is included at reference/PILOT_V2_RECEIVED_MANIFEST.json.

Only the packet actuator readback adapter changes: use configuration-only tc
JSON and collect plain-text tc statistics separately. The exact actuator command,
traffic, rates, policy, core gateway, controller, seeds, acceptance tests and
36-episode pilot design remain unchanged. Malformed configuration and failed
commands still fail closed. No raw output is rewritten or filtered.

The original manifest-verified dataset audit is included to correct the v2
packaging omission. Five regression tests use preserved guest diagnostic output.
This release requires its own source verification, all tests and fresh measured
qualification before the pilot. It is PILOT ONLY, not final-study evidence.
The final study still requires a new version, full qualification and an approved
frozen protocol. Its kernel rate/target verification must be stronger than this
pilot's existing presence-only readback check.
