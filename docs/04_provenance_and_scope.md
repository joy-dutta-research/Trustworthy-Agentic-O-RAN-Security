# Versions, provenance and scope

## The scientific versions

The Windows experiments used frozen source, policy, input preparation and seeds. The packet experiments used the separately repaired **v7** implementation. Keeping these versions separate makes the evaluation traceable: later packet transport repairs are not silently presented as part of the earlier Windows baseline.

The public source snapshots preserve the original scientific code, settings, tests and input fixtures. We omit one legacy manuscript-writing template from each source family and the nested bootstrap. Archive and transport-manifest hashes consequently change; [the omission record](../evidence/source_snapshots/PUBLIC_SOURCE_OMISSIONS.json) records the exact original-to-public mapping and unchanged scientific identities. Original experimental records retain their historical hashes. Browsable code adds reader documentation. The preparation helper extracts a fresh, manifest-verified public workspace for execution, keeping those documentation overlays separate.

## Experimental computers and environments

We name the two physical computers Workstation 1 and Workstation 2 in our current guides. The specifications below describe the hardware relevant to these CPU-based experiments, rather than unrelated display, camera or peripheral features.

| Environment | Hardware and software | Experimental role |
|---|---|---|
| Workstation 1 | Dell Pro 14 Premium PA14250; Intel Core Ultra 7 268V, shown as 2.20 GHz; 32 GB RAM; Windows 11; Python 3.12.14 | Original Windows Stages 0–5 measurements and comparison reference |
| Workstation 2 | HP Omen 16; Intel Core i9-13900HX, 24 cores; 64 GB DDR5 RAM; 1 TB SSD; Windows 11 Pro; Python 3.12.14 | Reproduction of Windows Stages 0–5 and host for the packet VMs |
| Packet VM 1 and clean-VM repeat | Separately installed Ubuntu 24.04 environments on Workstation 2; each with 4 vCPUs, 4 GiB RAM and Python 3.12.3 | Two separate 36-episode packet runs, covering initial Stage 6 and the clean-environment part of Stage 7 |

The Workstation 1 hardware details are supported by our Windows system-information screenshot; the Workstation 2 product configuration is author-supplied. Runtime manifests preserve the recorded software environments. We used CPU execution, not GPU acceleration. The listed 2.20 GHz is a system-information value, not a measured sustained experimental clock.

For traceability, we do not rename historical files or condition identifiers. **`university` identifies Workstation 1; `workstation` identifies Workstation 2.** VM labels identify separate guest installations on Workstation 2, not further physical computers. Hardware, background activity and scheduling can all affect timings, so the cross-host comparison does not isolate a CPU-model effect.

## Data provenance

NetsLab-5GORAN-IDD and 5G-NIDD are third-party research datasets. This repository identifies their official acquisition routes, exact selected input hashes and transformations. It does not present constructed approval or action-policy fixtures as original dataset labels. The packet scenarios are separately controlled laboratory workloads, not a packet replay proving radio-stack behavior on those datasets.

Derived public evidence may replace personal filesystem paths with documented aliases. Scientific numeric values, condition identifiers, seeds and relevant settings must remain unchanged. The evidence manifests distinguish original private hashes from the hashes of public derivatives. A changed metadata hash following documented redaction is not a changed experimental outcome.

## What has been verified

The prior private audit checked the complete handoff's manifested members, source/input identities, all 72 packet episodes and all 18 paired packet contrasts. It additionally reaggregated 24 selected raw Windows cells. Later inventory checks confirmed both Windows raw measurement sets and the files consumed by the original final synthesis.

This repository adds release-layout, documentation, asset-integrity and derived-view checks. It does not rename a checksum check as scientific validation or claim that every original Windows statistic has received an independent raw reanalysis. The packet reanalysis helper makes its arithmetic checks inspectable and repeatable from the supplied public evidence.

## Completed evaluation boundary

Completed: initial PoC Stages 0–7, including frozen Windows reproduction on a second physical host and a 36-episode packet experiment repeated in a separately installed clean VM.

The two packet VMs share Workstation 2. Each scenario/method/VM has three paired episode repetitions. The study describes the tested conditions; it does not supply population-level significance or field deployment evidence. The larger confirmatory packet study remains deferred.

No live/evaluated LLM, trained-detector accuracy benchmark, production O-RAN control interface, real radio-stack integration or continuous-learning agent is part of the runtime experiment. The supplied model reviews are an auxiliary policy-consistency exercise. These boundaries keep the evidence aligned with the paper's architectural argument and identify the next evaluation steps.

## Historical attempts

Earlier packet attempts and repairs explain how the successful protocol was qualified. The immediate UDP timeout errors were recorded, but their underlying cause was not conclusively reproduced. Controlled stable-neighbor handling was then used consistently across all successful comparators. History is retained separately from final results, so readers can inspect it without confusing incomplete attempts with final episodes.

Historical status text may say a stage was pending when a file was created. Current completion is established by the final scope and measured-run records, not by silently editing those earlier documents.
