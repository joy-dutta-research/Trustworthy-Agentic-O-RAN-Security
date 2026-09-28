# Release records and integrity checks

This folder records how the reproducibility package was assembled and checked. Most readers can start with [the main README](../README.md) or [the reproduction guide](../docs/03_reproduce.md); maintainers and reviewers can use these records to inspect the release itself.

| File | What it tells you |
|---|---|
| [VALIDATION.md](VALIDATION.md) | Checks actually completed, their outcomes and their limits, including source/evidence verification and companion-download checks |
| [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md) | Completed preparation work and the author decisions required for subsequent publication updates |
| [REPOSITORY_MANIFEST.json](REPOSITORY_MANIFEST.json) | Recorded file identities used by the repository verifier |
| [GIT_FILE_LIST.txt](GIT_FILE_LIST.txt) | The explicit source-file selection for Git, excluding the six large companion evidence ZIPs |

These are release records, not additional experimental results. A successful checksum check establishes byte identity; it does not establish scientific improvement or certify legal clearance. Historical verification counts describe the checked version. New documentation or layout changes require an updated manifest and fresh verification.

## Check a downloaded copy

From the **repository root**, not this folder, run:

```text
python tools/verify_repository.py --without-raw-assets
python tools/build_result_views.py --check
python tools/analyze_model_reviews.py --check
```

The first command explicitly identifies absent companion evidence. For the complete archive check, obtain all six matching assets using [the asset guide](../evidence/ASSET_GUIDE.md), retain their filenames, and run `python tools/verify_repository.py --deep-assets` from the repository root. The [asset catalogue](../evidence/RELEASE_ASSETS.json) records their download links, destinations and checksums.

Read [the reproduction guide](../docs/03_reproduce.md) before collecting any new measurements. File verification and offline reanalysis do not launch VMs, generate network traffic or contact a model. Keep all new experiment outputs separate from the preserved published observations.

## Preparing a later release

Review [the checklist](RELEASE_CHECKLIST.md), preserve the original scientific evidence, update the affected guidance and manifest, and rerun the checks. Follow [contribution guidance](../.github/CONTRIBUTING.md), [safe-use guidance](../.github/SECURITY.md) and [licensing](../licenses/README.md). A Git update, a change to repository visibility and acceptance of the paper are separate decisions.
