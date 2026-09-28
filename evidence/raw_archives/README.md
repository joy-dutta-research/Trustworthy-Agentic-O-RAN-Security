# Saved scientific measurements

Place five companion ZIPs here for exact reanalysis. They are downloaded separately and excluded from ordinary Git history. A sixth, optional history asset belongs in `evidence/history/`. Follow the [complete asset guide](../ASSET_GUIDE.md) and [machine-readable catalogue](../RELEASE_ASSETS.json) for download links, destinations, hashes and new-run commands.

| Archive | Meaning |
|---|---|
| `university_windows_final.zip` | Workstation 1 Windows policy, dataset, sensitivity, timing, scaling and load results. |
| `workstation_windows_final.zip` | Workstation 2 results for the frozen Windows protocol. |
| `packet_primary.zip` | Primary VM qualification and 36 packet episodes on Workstation 2. |
| `packet_repeat.zip` | Clean-VM qualification and 36 repeated episodes on the same physical Workstation 2. |
| `campaign_provenance.zip` | Original baseline, preparation and campaign records, not an additional measured run. |

The historical `university` and `workstation` identifiers remain unchanged to preserve provenance. They map to Workstation 1 and Workstation 2, respectively. Keep the Windows hosts and the two packet runs separate in analysis.

Each ZIP includes a public member manifest and folder guidance. `requests.csv` contains individual processing observations. `arrivals.csv` and `completions.csv` support all-offered load analysis, including overflow. Packet JSONL retains the sent cohort and responses needed to recompute timely delivery and goodput. Settings and summaries explain each condition. Recorded raw observations and scientific values have not been rewritten.

These are our observed outcomes, not publicly downloadable NetsLab or 5G-NIDD source files. The [data guide](../../data/README.md) explains acquisition of those inputs for new runs. The [asset guide](../ASSET_GUIDE.md) explains why both routes are useful and not interchangeable. Public asset URLs are not available until the release is approved and uploaded.

Fields ending in `_ns` are nanoseconds and `_bytes` are bytes. Windows load is action proposals, not network packets. Packet delivery includes missing or late replies in the sent-cohort denominator; received-only RTT does not measure delivery reliability. Read [the metric definitions](../../docs/02_methods_and_metrics.md) before recomputing results.
