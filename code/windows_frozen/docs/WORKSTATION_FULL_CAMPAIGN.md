# Full Orders 0-7 on the destination workstation

This is a new full-source regeneration campaign, not a replacement of the
completed university results and not a new independent dataset. It is useful
for reproducibility and keeps all new timing measurements on one workstation.
The i9/64-GB host is not itself evidence of greater validity or safety.

## Raw inputs and prerequisites

The public code/replay package does not contain the original raw data. Install
the separately supplied private raw companion only through its verified importer
and only if you may use these dataset copies. No 24-GB parent NetsLab archive is
needed: the exact selected database and 5G-NIDD release are sufficient.

| Required relative path | Bytes | SHA-256 |
|---|---:|---|
| `data/raw/Lower_Layer_Data.db` | 5,402,624 | `d76fe7df11379223948e624d0f19bcd5caf744a2b6ce20d1ee2143644199ab64` |
| `data/raw/5g-nidd/Combined.zip` | 28,028,224 | `07531b251f3f35be70bf1d3dcca2e27274bd1b267c5a057c0fcea18668b9293d` |

Use a clean verified Windows extraction and a normal user, trusted Python 3.12,
at least 10 GiB free disk for the offline campaign, and the unchanged source.
No network access, model API or administrator privilege is needed for Orders
0-5. Complete the software tests first. Keep the Ubuntu VM stopped and do not
run concurrent scientific campaigns or background analysis while timing.

## Ordered execution

```powershell
python scripts/workstation_campaign.py --plan
python -m unittest discover -s tests
python scripts/workstation_campaign.py --execute
```

Planning is read-only. Missing raw inputs are listed; wrong hashes are refused.
Execution creates a fresh full-input Stage0 baseline and an indexed session in
`results/local/full_campaign_runs/`. The baseline pins the exact original
policy/core, both raw files, aggregate, historical audit, and frozen comparison
inputs. It is a new destination inventory, not the original university Stage0.

The command performs the following in this order:

1. Read the pinned NetsLab database without modifying it; regenerate the full
   45,244-row aggregate into the new session and compare parsed content and
   canonical digest with the shipped aggregate. Never overwrite the aggregate.
2. Run the 50-case validity instrumentation pilot, then all 777 common validity
   cases and all 20,000 NetsLab control-generation cases.
3. Run a 1,000-record instrumentation-only 5G-NIDD pilot, then the full archive
   reconciliation/census: 1,215,890 source rows, 733,693 eligible records and
   2,934,772 comparator evaluations. The pilot is not a completed source audit.
4. Generate and evaluate all 20 seeded 5G-NIDD panels: 95,000 conformance cases
   and 5,000 separately classified forced false-alarm probes. Compare all 42
   regenerated case files, containing 120,777 cases, byte-for-byte by SHA-256
   against the supplied original cases. A difference stops the campaign.
5. Run all 12 frozen one-factor sensitivity conditions: five NetsLab and seven
   5G-NIDD, with the original denominators and thresholds.
6. Prepare both performance workloads from the newly completed upstream
   experiments. Compare their actual JSONL bytes with the shipped performance
   inputs. Preparation timestamps, source paths and receipt hashes legitimately
   differ; those metadata are preserved, not required to match the old machine.

There are 19 supervised partitions: two excluded instrumentation pilots, 16
scientific validity/dataset/sensitivity partitions and one workload preparation.
The unchanged Windows Job supervisor applies the existing per-run process,
memory, time and disk guards. The small, exact-hash NetsLab aggregation is a
read-only preparation step; the large scientific runners are Job-supervised.
All original false-alarm and protected-service-policy limitations remain visible.

## Orders 4-5: perform one timing campaign

Inspect the new session's `COMPLETE.json`, `AGGREGATE_COMPARISON.json`,
`CASE_REGENERATION_COMPARISON.json` and `WORKLOAD_COMPARISON.json`. All must
complete/match and `performance_ready` must be true before timing. Do not tune
labels or regenerate a preferred subset to force agreement.

Then, with the host quiet and Ubuntu stopped, run once:

```powershell
python scripts/workstation_reproduce.py --execute --phase performance --quiet-host-confirmed
```

This reuses the byte-identical frozen workload files whose regeneration was
just verified, not a different case selection. It runs all 1,820 final cells
and 84 separately excluded instrumentation-pilot cells. It is simultaneously
the destination's Orders 4-5 and its cross-host performance reproduction;
do not run it twice merely to create separate favorable headline tables.
Comparisons use separate columns for university and workstation values, never
pooled timings. A hardware change is not an isolated causal CPU experiment.

## Orders 6-7

Follow `WORKSTATION_STAGE6_FINALIZATION.md` for isolated Ubuntu qualification,
the preserved pilot, separately versioned final packet study and clean repeat.
Do not overlap VM traffic experiments and Windows benchmarks. A same-workstation
clean VM repeat is not independent second-hardware packet validation.

The original full generation plus exact input comparison already establishes
the constructed-case regeneration check. `workstation_reproduce.py --execute
--phase replay` is a recommended additional integrity check, optional if the
full-campaign analyzer independently validates regenerated cases. It replays
those same cases, not extra independent scientific observations or a substitute
for source census.
Follow the companion analysis/return instructions to produce a combined indexed
report with all Orders 0-7 completion statuses and any remaining author checks.

## Failures, integrity and return

Every attempt has unique result names; there is no overwrite, automatic retry,
resume, or selection of faster/better runs. The parent session indexes each
supervised `full_<id>_*` directory under `results/evaluation_v0.2/`. Keep all
of those directories, all `s7_*` timing partitions, new `stage0_*` baselines,
and unindexed interrupted attempts. A final receipt is not sufficient by itself:
the receiving analysis must verify hashes, raw evidence and denominators.

A forced termination can leave `.active-campaign.lock`. Do not remove a lock
because a command is slow. Confirm the owned process tree has ended, preserve
the original lock privately outside the return collector, and record its exact
contents, SHA-256, path, ownership/process checks and owner-approved recovery in
fresh `.txt`/`.json` evidence inside the affected attempt. Only then remove the
exact abandoned lock with owner approval; never use a wildcard or remove a live
lock. Do not move a file still named `.lock` into exported evidence: that
extension is deliberately unsupported. Diagnose the retained failure before a
new attempt. Never delete failed outputs, broaden resource bounds silently or
change the original policy to obtain agreement.

The return bundle contains derived experiment evidence, not the raw companion.
Raw inputs stay private and local. Review any error trace for private paths
before sharing. Dataset-reproduction success still does not prove a learned
detector's accuracy, LLM planning, incident truth, mitigation effectiveness or
production O-RAN interoperability. Author verification remains required.
