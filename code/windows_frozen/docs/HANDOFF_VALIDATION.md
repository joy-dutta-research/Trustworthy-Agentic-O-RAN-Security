# What was checked before delivery

Validation performed on the original Windows computer, September 2026:

- Offline software test suite, including source/return archive integrity,
  mandatory qualification evidence, VM isolation refusals, retention of
  unsuccessful runs, and bounded child-process interruption behavior.
- Offline suite under Python 3.12 and Python 3.14 on Windows.
- Extraction of the portable source ZIP into a separate fresh folder; manifest
  verification and offline tests without original raw datasets/private files.
- Generated source ZIP read-back and SHA256 sidecar verification.
- Source/return export allowlists; exclusions for raw data, private review
  mappings, credentials, VM media/disks and original host-specific results.
- All nine frozen original gateway/comparator file checksums unchanged.
- PowerShell syntax and read-only plan mode for VM/transfer helpers.
- Independent review of qualification evidence and interrupted-run recovery.

These checks do **not** establish:

- Actual Hyper-V creation, disk initialization/mounting or guest installation.
- Linux kernel/module support or a measured packet pilot.
- Precise achieved bottleneck rate, comparative service improvement, correct
  behavior after every possible power/process fault, or production safety.
- Live LLM planning, IDS accuracy, O-RAN radio or E2 interoperability.

The home assistant must verify first-use setup rather than infer it from unit
tests. Do not fabricate a success receipt, weaken failed guards, or substitute
an assistant's narrative for raw measurements. See the runbook and protocol.

The source and results archives use SHA256 for integrity. They are not signed
releases. The current account's intended model setting is not machine-verified
by these files, and no live model is part of the experimental controller.
