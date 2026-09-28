# From prepared source to approved publication

This checklist concerns publication, not whether the completed initial PoC needs to be relabelled or repeated. We prepare the source locally first, then publish only after author approval. A prepared source repository and a fully downloadable historical-evidence release are distinct milestones.

## Prepared source and reader guidance

- [x] Keep the current manuscript, publication figures and direct copies of paper tables outside the public tree. Preserve numerical evidence and repository-specific summaries for reproducibility.
- [x] Use Workstation 1 and Workstation 2 in the current guides, with hardware specifications and a mapping to unchanged historical data identifiers.
- [x] Explain the experiments in our research voice and retain all conditions, measurement boundaries and future research opportunities.
- [x] Document each of the six companion archives, its exact placement, size, checksum, role and applicable reproduction route.
- [x] Provide official dataset sources and exact input acquisition/import instructions for new Windows runs.
- [x] Keep original evidence immutable and distinguish new observations from reanalysis of our historical measurements.
- [x] Provide automated checks for source integrity, result views, publication-file exclusion and the six-asset catalogue.

The completed checks and their limits are recorded in [VALIDATION.md](VALIDATION.md). The asset catalogue now links the six companion archives in the verified Viewer-only Drive folder. Evidence availability is separate from GitHub visibility and paper acceptance.

## Author decisions before public release

- [ ] Confirm the final paper-to-evidence mapping privately, without adding the manuscript or publication displays to this repository.
- [x] Identify Joy Dutta as software maintainer and the repository as `joy-dutta/Trustworthy-Agentic-O-RAN-Security`; retain private repository visibility. Paper status remains under review. Software citation is not a replacement for the paper's co-author list.
- [ ] Approve the stated policy assumptions, standards locators and disclosed legacy rollback-policy exception.
- [ ] Review the public evidence selection and documented path redactions; retain the private originals unchanged.
- [x] Check the original providers' declared dataset licences and include creator/source credit, change descriptions and separate software/data terms. This is not institutional or legal clearance.
- [x] Run the repository, result-view and model-review checks from a clean export of the exact Git index, with no private dataset companion. Both preserved software suites also pass from newly prepared source workspaces.
- [ ] Verify official acquisition/import instructions independently of the original private data companion.
- [ ] Review recorded software-test results and separately authorize any new Windows performance or Linux packet run.
- [x] Upload the matching large evidence assets and hashes to the approved companion location, outside ordinary Git history; verify Viewer-only sharing.
- [x] Populate the six asset URLs and folder URL in `evidence/RELEASE_ASSETS.json`. The strict catalogue check passes; rebuild the manifest after the final documentation edits.
- [x] Download all seven companion files anonymously and match their sizes and SHA-256 values to the intended release. Clean source-checkout verification is recorded separately; catalogue validation alone does not establish remote availability.
- [x] Obtain Joy Dutta's explicit authorization on 28 September 2026 to finalize licensing and push this package to his named GitHub repository. This does not authorize changing repository visibility.
- [ ] Add the accepted paper link and citation when available; do not invent a DOI or acceptance date.

The repository's build/verification receipts record the checks actually performed. Unchecked author-review items are retained honestly; technical checks cannot certify institutional rights or substitute for final author review. They are not missing experimental results. The larger confirmatory study remains future work, not a release prerequisite for the completed initial PoC.

Dataset source links are sufficient for acquiring the experimental inputs, but not for downloading our earlier measurements. The latter require the six companion assets. Our [asset guide](../evidence/ASSET_GUIDE.md) also explains how to produce new observations when historical raw-evidence inspection is not needed.

## Preparing an approved Git index

`release/GIT_FILE_LIST.txt` is the explicit list of source-repository files. It excludes the six large raw/history evidence ZIPs; those belong to matching companion release assets. Review this list and verify the complete local artifact before staging. Run the commands below from the repository root, not from this folder.

The browsable frozen source preserves its historical `.gitignore`. That file ignores three shipped acquisition-metadata/documentation files under `code/windows_frozen/data/raw/`. Ordinary `git add .` would silently omit them. Use the reviewed exact allowlist when preparing a fresh repository:

```text
git init
git add -f --pathspec-from-file=release/GIT_FILE_LIST.txt
git diff --cached --stat
```

This stages local files only. It does not commit, configure a remote or push. A forced add is appropriate here only because the list is explicit and excludes raw third-party datasets, private working directories and large release assets. Do not replace it with `git add -f .`. Before publication, compare tracked file names with the allowlist and run the source-only verifier from a clean checkout together with the matching release assets for full verification.
