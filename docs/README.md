# Understand the study and choose a reproduction route

These guides connect our research questions to the code, measurements and practical steps. Read them in order for the complete story, or start with the question you need to answer.

| Guide | What it helps you do |
|---|---|
| [01_study_overview.md](01_study_overview.md) | Understand the practical problem, the framework connection and the completed Stages 0–7 |
| [02_methods_and_metrics.md](02_methods_and_metrics.md) | Identify the compared methods, measurement boundaries, units and denominators |
| [03_reproduce.md](03_reproduce.md) | Verify the package, reanalyse saved observations or collect a new result set |
| [04_provenance_and_scope.md](04_provenance_and_scope.md) | Trace the source versions, inputs, seeds, workstations and VMs |
| [05_research_directions.md](05_research_directions.md) | See how the findings inform the next engineering and evaluation steps |

## Go directly to the task you need

- **Read the takeaways:** open the [results overview](../results/00_overview/README.md), then use the methods guide to interpret each metric.
- **Check files and saved exports:** follow [read-only verification](03_reproduce.md#1-read-and-verify-the-local-artifact). No dataset download or VM is needed for the source-only checks.
- **Recalculate packet outcomes:** follow [saved-packet reanalysis](03_reproduce.md#2-reanalyse-the-saved-packet-observations) after obtaining the two packet archives from [the asset guide](../evidence/ASSET_GUIDE.md).
- **Collect new Windows measurements:** obtain the [two original dataset inputs](../data/README.md), [prepare a fresh workspace](03_reproduce.md#3-prepare-a-fresh-scientific-workspace), then follow [Stages 0–5](03_reproduce.md#4-windows-stages-05).
- **Collect new packet measurements:** read [the safety guidance](../.github/SECURITY.md), then follow [Stage 6](03_reproduce.md#5-packet-stage-6-in-an-authorized-disposable-ubuntu-vm) and [the clean-VM repeat](03_reproduce.md#6-clean-environment-stage-7). These require an explicitly authorized isolated lab.
- **Inspect the model-assisted comparison:** follow [the review guide](../model_review/README.md). The supplied responses can be compared offline without an API key.

The current guides are the starting point for readers. Older instructions in frozen code snapshots explain how the original work developed; their historical paths and launchers are not commands to execute automatically. Keep new outputs separate from the published evidence and retain all measured conditions.

For integrity records and release administration, use [release/](../release/README.md). For reuse terms, use [licenses/](../licenses/README.md). Return to [the main README](../README.md) for the complete repository map.
