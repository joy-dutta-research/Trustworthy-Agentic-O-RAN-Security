# Publication-layer regression tests

Run `python -m unittest discover -s tests -v` from the repository root. These tests exercise safe preparation and evidence-checking helpers. They use temporary local fixtures, not a live network or VM.

The publication-scope fixtures check nested ZIPs for withheld document/image formats. Asset-catalogue fixtures check that all six archive identities match and that missing download links cannot be reported as a completed public evidence release. Integrity tests also check the manifest's location under `release/` and ensure that identically named files elsewhere are not skipped. Homepage tests require the main README and reject competing files that could hide it on GitHub, while allowing ordinary folder guides. These tests do not contact an external service.

The original scientific tests belong to the frozen implementations. Follow [the reproduction guide](../docs/03_reproduce.md) to prepare a fresh working copy and run them there. The model-review helper has additional tests at `model_review/test_analysis.py`.

Passing a software test establishes that the checked behavior matches the test; it is not detector validation, production O-RAN validation or evidence of statistical significance.
