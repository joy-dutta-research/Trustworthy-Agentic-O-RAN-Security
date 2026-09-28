# Return evidence contract

The outer project root is `oran-workstation-lab`. Keep the original delivered
ZIP and `WORKSTATION_MANIFEST.json`. Hashes detect corruption; they are not a
digital signature, privacy guarantee or proof of scientific validity.

## Required result layout

```text
results/
  local/
    full_campaign_runs/
      <runner-session>/    # new baseline, raw-input checks, regeneration, sensitivity
    stage6_runs/
      <unique-attempt>/
        STATUS.json
        REPORT.md
        protocol/          # fixed plan, seed/cell list, amendments
        source/            # exact final/development source, configs, hashes, tests
        environment/       # minimal host/guest/tool/topology information
        raw/               # independent packet observations, action/readback logs
        analysis/          # analysis code, tables, uncertainty, figures if used
        receipts/          # commands, completion/failure, integrity, cleanup
      campaign_summary/
        STATUS.json
        REPORT.md
    stage6_returns/        # original collected legacy pilot ZIPs + sidecars
    workstation_runs/
      <runner-session>/    # generated replay/performance plan, receipts, raw replay
      comparison_<date>/
        STATUS.json
        REPORT.md
        analysis.json
        manifest.json
  evaluation_v0.2/
    stage0_<new-id>/        # NEW transfer baselines only, not university runs
    s7_<session>_.../       # all pilot/final/failed/partial performance partitions
    full_<session>_.../     # all fresh Orders0-3/preparation partitions and pilots
```

Stage6 is developed on the destination; the above Stage6 files are requirements,
not pre-existing outputs. For each attempt, `STATUS.json` should give a schema
version, phase (`development`, `qualification`, `pilot`, `final`, `clean_repeat`),
unique ID, protocol/source hashes, environment ID, planned/completed/invalid
cells, status, unresolved issues and links to local relative evidence. Never
claim final completion from a pilot receipt. Record all attempts before any
analysis selection, and retain unfinished source versions as well as final code.

## Guest return and import

For the unchanged bootstrap pilot use its existing `portable_bundle.py return`
after owner privacy review. Collect its archive via the validated offline
transfer-disk workflow and copy the archive + checksum unchanged into the outer
`results/local/stage6_returns/` directory. The outer exporter verifies the legacy
ZIP's internal manifest; do not put arbitrary/unverifiable ZIPs in this folder.

For the separately versioned final harness, implement and test an equivalent
bounded guest exporter that includes **all** Stage6 attempts, protocol/source
versions, independent metrics and failures. Verify its manifest and path safety
before extracting into outer `stage6_runs/<attempt>/`. Preserve its original
return ZIP under that attempt's `receipts/`. No virtual disks or full OS images.
The 1-GiB transfer disk requires a size check; do not overwrite evidence to fit.

PNG/SVG figures are not in the outer export allowlist. Prefer machine-readable
CSV/JSON tables and plotting code; regenerate publication figures from returned
data. Do not silently omit required evidence because of an extension/size limit.

## Comparison report requirements

For the full rerun, first report raw-input hash checks, regenerated aggregate and
case/workload identities, census source/eligibility accounting, all twelve
sensitivity conditions and fresh coverage/property/mutation results. Do not call
an exact replay a new independent dataset experiment. Preserve any difference;
do not normalize or retune away unexpected discrepancies.

Summarize replay decision/reason/audit agreement, exact case coverage and source
identity. Use all 1,820 final performance cells; exclude 84 pilots by predeclared
role, not result. Use `scripts/summarize_workstation_reproduction.py` as documented
in the Stage7 guide to validate the complete compact-summary inventory and
produce the new-host analysis. It does not independently recompute every raw
request observation; retain the raw records and state this boundary. Any extra
raw-data audit must have its own recorded scope and results. Keep original-host
values in a separate column and explain host
differences; do not pool samples or call this an independent new dataset test.

For Stage6, report all methods/scenarios, paired uncertainty, missed or harmful
actions, censored recovery, failure/invalidity counts and clean-repeat consistency.
Keep aggregate status dimensions separate: experiment execution, evidence
integrity, scientific findings, and pending author approval. A negative scientific
result can be a successfully executed experiment.

## Export on Windows

Review logs for user paths, hostnames, email addresses, network identifiers,
tokens and unexpected private content. Do not collect environment variables,
browser profiles, credential stores, institution files or home directories.
The automated credential-pattern scan is only a limited safeguard. If a raw
log needs redaction, preserve its private original locally, create a documented
shareable derivative and explicit hash/redaction receipt; do not silently edit
an attested original and call its hash unchanged.

From the outer project root, with a trusted Python interpreter:

```powershell
python scripts/workstation_bundle.py return --output '..\ORAN_WORKSTATION_RESULTS_YYYYMMDD.zip' --reviewed-for-sharing
python scripts/workstation_bundle.py verify-zip '..\ORAN_WORKSTATION_RESULTS_YYYYMMDD.zip'
```

Choose a fresh dated filename. Export refuses overwrite, suspicious paths,
unsupported evidence files, recognized credential patterns, files over 2 GiB,
or a total uncompressed return above 16 GiB. If a bound is exceeded, retain
everything and design a reviewed, indexed multi-volume return; do not discard
raw results or silently raise limits. This release uses a 2-GiB archive-member
bound because the already observed full-census decision log alone is
1,067,137,148 bytes. It is a packaging bound, not a relaxation of experiment
memory/runtime/output guards. Stop writing experiment outputs before
export so hashes are stable.

The ZIP contains an index, observed receipts/statuses, file hashes, received
manifest, current source snapshot and source-change report. Frozen replay inputs
are rehashed and listed but not duplicated in the return ZIP. All `s7_*` and new
`stage0_*` and `full_*` directories are retained, including unindexed interrupted
attempts. Successful packaging alone never marks Orders 0-7 scientifically complete.

Send the resulting ZIP and adjacent SHA-256 file to the original task. Keep the
source package and full workstation results locally until receipt and analysis
are confirmed. No automatic GitHub publication or other upload is authorized.
