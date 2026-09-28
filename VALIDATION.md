# Artifact verification

Checked on **28 September 2026**. This record describes preparation of the publication artifact, not a new scientific experiment.

## Checks completed

| Check | Outcome and meaning |
|---|---|
| Scientific source snapshots | Original deliveries checked during initial preparation; public transport copies additionally omit manuscript templates while preserving scientific code/settings/input identities |
| Source inputs | Both exact dataset files and both historical acquisition receipts imported into a private validation workspace; full Windows campaign `--plan` reports inputs ready and does not execute the plan |
| Frozen Windows software tests | 392 tests run successfully, including 2 expected skips |
| Packet-v7 software tests on Windows | 383 tests run successfully, including 2 expected skips; not a Linux packet execution |
| Publication helper tests | Initial preparation passed 18 tests; the expanded release checks are recorded below |
| Supplied model-review analysis tests | 12 tests passed |
| Final results exports | All 66 Stage 0–7 view files reproduce in memory from the supplied summaries |
| Auxiliary model-review exports | All 5 derived files reproduce from the supplied original responses and comparison inputs |
| Packet raw-data analysis | All 72 episodes recalculated; 24 condition aggregates and 18 paired condition comparisons agree with the included audit |
| Public evidence archives | All 25,038 manifested source/evidence members streamed through their public SHA-256 checks; extra reader guides are declared and bound by the outer archive hashes |
| Folder guidance and current links | Every distributed authored folder has Markdown guidance; current reader-navigation links resolve |
| Git transfer check | A clean export of the staged source-only index passes the explicitly partial integrity check and both result-view checks; the six large companion ZIPs are correctly reported absent there |

At the initial preparation stage, the source-only export was not a clean clone from GitHub: no remote, commit or upload had been created at that point. It tested the exact selected Git file set and byte preservation without publishing the repository. Large evidence ZIPs remain companion downloads, not ordinary Git history.

## Verification boundaries

Original evidence, scientific policies, settings and recorded results were not overwritten. Private originals of the transport bundles and omitted manuscript templates remain outside this repository. Public transport manifests were regenerated for the declared template omission and nested packaging changes. No performance campaign, packet experiment, new model call, network attack or VM creation was performed during artifact preparation. The subsequent companion-evidence upload is recorded below. Software tests use controlled fixtures and mocks. Some tests intentionally exercise rejected requests, so expected parser/error text in their output is not a failed scientific run.

The Windows sandbox initially prevented access to Python-created temporary test directories. Repeating the bounded local test suites with ordinary filesystem access resolved that tooling restriction. This was an artifact-checking environment issue, not an experimental repair or change to scientific code.

GitHub-hosted workflow execution is separate from these local checks; consult [the repository's Actions page](https://github.com/joy-dutta/Trustworthy-Agentic-O-RAN-Security/actions) for its current run status. New Linux environment setup and new physical-host packet replication were not attempted during artifact preparation. The initial packet evidence still represents two clean VMs on one physical workstation, with three paired repetitions per condition per VM.

Targeted checks for personal machine paths and obvious credential patterns do not constitute exhaustive privacy or legal certification. Author review of licensing, disclosure and manuscript alignment remains a release requirement. File integrity and reproducible arithmetic support inspection; they do not by themselves prove scientific improvement.

## Updated publication-scope preparation

We excluded the current manuscript and publication displays, and removed the old protocol-writing templates from the browsable trees and public source transports. Exact originals remain in private author storage outside this repository. The public transport identities and the scientific byte comparisons are recorded in [the source omission record](evidence/source_snapshots/PUBLIC_SOURCE_OMISSIONS.json).

The updated preparation preserves 102 Windows, 104 packet and 95 nested-bootstrap scientific members. The frozen bundle verifiers accept the new public manifests: 213 Windows, 154 packet and 136 nested-bootstrap payload files. No changed packaging path intersects a frozen scientific source/configuration/test boundary.

The expanded publication-helper suite passes **31 tests**. Model-review analysis passes **12 tests**. All **66 Stage 0-7 derived files** and **five model-review derived files** match recomputation. All 54 result CSV/JSON files remain byte-identical to the preceding draft; reader-facing workstation labels changed only in documentation and its rendering code.

Freshly prepared public snapshots also pass the unchanged scientific software suites: **392 Windows tests** and **383 packet-v7 tests on Windows**, each including two expected skips. These are software checks with fixtures and mocks, not new measured campaigns or Linux packet executions.

The publication-format check examines both ordinary files and nested ZIPs. It finds no withheld manuscript, PDF, raster/vector figure, Word or slide-file formats in the prepared public tree. This is not a semantic plagiarism or privacy certification. Repository-specific numerical tables remain available; no publication-ready paper table is copied into the reader guides.

During initial preparation, all six companion-asset identities and destination instructions matched the manifest and SHA-256 sidecars, and the catalogue correctly reported `PREPARED_LINKS_PENDING`. The later upload and link completion supersede that availability status, not the scientific findings. Official dataset source references were checked without rerunning source-data experiments.

## Companion distribution and licence reconciliation, 28 September 2026

We uploaded six evidence archives and their README to the author-approved Drive folder. Read-only metadata checks confirmed every expected filename and byte count, and then confirmed the folder and all seven files had an `anyone: reader` permission. The catalogue contains their actual links; its `published` status refers to these companion assets, not repository visibility or paper acceptance.

Before upload, we expanded only the generated root README in each archive with self-contained dataset attribution and the existing software licence. All **25,038 scientific members** and all **29,026 non-root-README members** remained byte-identical. The [revision record](evidence/ARCHIVE_NOTICE_REVISION.json) records both archive identities. Original ZIPs remain in private author storage.

The software retains Apache-2.0. The initial GitHub template's MIT notice is preserved separately rather than silently applied to the evaluated software. Our own guides/results have an explicit, rights-limited CC BY 4.0 grant; third-party terms remain separate. These measures document the distribution basis without claiming blanket ownership or legal clearance. See [LICENSES.md](LICENSES.md) and [REUSE.md](REUSE.md).

The repository was private at the release-access check. Its connected account was Joy Dutta (`joy-dutta`) with push permission. Changing repository visibility is a separate author decision. Remote download-byte verification and GitHub execution are separate checks; do not infer either from file metadata or a local catalogue pass.

All seven companion files were then downloaded anonymously, without cookies, credentials or browser state. Every size and SHA-256 matched, covering **1,349,746,795 bytes** including the README. Five smaller files also matched through an authenticated connector; the two larger Windows archives exceeded that connector's 256 MiB limit and were successfully verified through the ordinary public Google download route. The [download-verification record](evidence/DOWNLOAD_VERIFICATION.json) preserves the file identities and method. No downloaded archive was executed.

The final **595-file Git selection** was exported into a new directory. Its source-only integrity check reported the six intentionally absent companion ZIPs and no failures. The strict published-link catalogue, publication-format guard, all 66 stage views and all five model-review outputs passed. The 31 publication-helper tests and 12 model-review analysis tests passed. New workspaces prepared solely from that export passed 392 Windows software tests and 383 packet-v7 software tests on Windows, each with two expected skips. No scientific campaign was rerun. This check exercises the same source selection that is committed, rather than relying on untracked private inputs.

## Repeat these artifact checks

Follow [the reproduction guide](docs/03_reproduce.md) and [tool descriptions](tools/README.md). Start with `python tools/verify_repository.py --without-raw-assets`; use `--deep-assets` when the complete evidence assets are present. Also run `python tools/check_publication_scope.py` and `python tools/check_release_assets.py`. Consult [the release checklist](RELEASE_CHECKLIST.md) before any future publication.
