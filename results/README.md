# Results: read the experiment in order

Start with [00_overview](00_overview/README.md). Then follow the numbered folders below. We provide explanations, readable result summaries and machine-readable exports so each experimental finding can be traced to its evidence. The exports retain full numerical precision where the source provides it; the reading tables round for readability. These are repository result views, not copies of manuscript tables or figures.

| Folder | Main question |
|---|---|
| [00_overview](00_overview/README.md) | What does our completed PoC establish? |
| [01_policy_validity](01_policy_validity/README.md) | Does each comparator enforce the same declared policy? |
| [02_dataset_robustness](02_dataset_robustness/README.md) | How do the dataset-grounded, census and seeded-panel results relate? |
| [03_sensitivity](03_sensitivity/README.md) | What changes when the declared policy parameters change? |
| [04_processing_cost](04_processing_cost/README.md) | What local processing cost do the checks add? |
| [05_scaling_and_load](05_scaling_and_load/README.md) | How does cost/completion change with state and offered load? |
| [06_packet_feedback](06_packet_feedback/README.md) | What do mitigation, corroboration and outcome feedback contribute? |
| [07_reproducibility](07_reproducibility/README.md) | What repeated across physical hosts and clean VM installations? |
| [08_model_review](08_model_review/README.md) | How did the two model reviewers interpret our original policy cases? |

Folder numbers are a reading order. The model-review folder is supplementary, not an extra runtime Stage 8. The experiment stage mapping is in [the study overview](../docs/01_study_overview.md).

## Read a result at three levels

1. **Meaning:** the folder's Markdown explanation identifies the question, result and implication for the framework.
2. **Numbers:** Markdown tables provide a compact view; CSV/JSON files support filtering, plotting and precise reuse.
3. **Evidence:** source references point to our saved analysis objects or raw-evidence assets. The original measurements remain separate from derived exports.

Use denominators and units exactly as labelled. Do not pool computers or packet VMs, mix census records with constructed cases, treat packets as repetitions, or interpret model-policy agreement as runtime detection accuracy. All conditions, including the operating limits that guide the next development steps, are retained.

We use **Workstation 1** and **Workstation 2** throughout the reader-facing summaries. Historical CSV/JSON identifiers stay unchanged for reproducibility: `university` means Workstation 1; `workstation` means Workstation 2. Both packet VMs ran on Workstation 2.

## Refresh and verify

`python tools/build_result_views.py --check` checks the Stages 0–7 views against the included summary evidence. `python tools/analyze_model_reviews.py --check` checks the auxiliary model comparison from the preserved responses. See [the reproduction guide](../docs/03_reproduce.md) for the distinction between rebuilding views, reanalysing raw evidence and performing new measurements.
