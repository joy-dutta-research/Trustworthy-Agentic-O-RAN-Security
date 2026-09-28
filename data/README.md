# Dataset inputs and acquisition

We use two public datasets as sources of intrusion context, then evaluate explicitly constructed action-policy cases. Our compact results and frozen replay fixtures can be inspected without downloading either dataset. Full source-data regeneration requires the two exact inputs below. We document their acquisition here rather than redistribute raw third-party files.

| Input | Bytes | SHA-256 |
|---|---:|---|
| NetsLab `Lower_Layer_Data.db` | 5,402,624 | `d76fe7df11379223948e624d0f19bcd5caf744a2b6ce20d1ee2143644199ab64` |
| Original 5G-NIDD `Combined.zip` | 28,028,224 | `07531b251f3f35be70bf1d3dcca2e27274bd1b267c5a057c0fcea18668b9293d` |

These inputs are not the six companion measurement ZIPs. For those files, their publication status and the alternative new-run routes, use [the evidence asset guide](../evidence/ASSET_GUIDE.md).

## NetsLab-5GORAN-IDD

Begin with the [official NetsLab dataset page](https://netslab.ucd.ie/netslab-datasets/netslab-5goran-idd/). It links the [Kaggle distribution](https://www.kaggle.com/datasets/netslabdemo/netslab-5g-oran-idd) and [dataset DOI](https://doi.org/10.34740/kaggle/ds/7416931). We checked those source references against the creator's page on September 28, 2026. Follow the provider's access and licence requirements; a Kaggle sign-in may be needed for download.

Obtain `Lower_Layer_Data.db`, either directly from the provider's file listing if available or as a member of the dataset ZIP. Only this 5,402,624-byte SQLite database is required by our experiment. We used its `lower_layer_data` table with 45,244 records. Higher-layer databases are not required. The full downloaded parent ZIP is unnecessary after the exact database has been extracted and verified.

## 5G-NIDD

Begin with the [authors' repository](https://github.com/yushan1986/5g-nidd), which identifies the original public [dataset DOI](https://doi.org/10.23729/e80ac9df-d9fb-47e7-8d0d-01384a415361). Its [Fairdata landing page](https://etsin.fairdata.fi/dataset/9d13ef28-2ca7-44b0-9950-225359afac65) provides the source files. We checked the repository's DOI attribution on September 28, 2026. Public service availability is separate from this attribution check.

Obtain the pinned 28,028,224-byte `Combined.zip`, which contains the processed `Combined.csv`. Keep it zipped for our runner. No PCAP files, third-party Kaggle repost, classification notebook or attack script is required. A newly repackaged CSV is not an exact substitute for the original ZIP, even if its filename looks similar.

## Optional acquisition helpers

You may download and extract the files manually, then use their paths in the import command below. If you prefer our bounded acquisition helpers, first prepare a separate acquisition-only workspace from the repository root:

```text
python tools/prepare_workspace.py --kind windows --destination work/acquisition
```

To extract the exact NetsLab member from a downloaded parent ZIP:

```text
python work/acquisition/scripts/extract_netslab_member.py "PATH_TO_DOWNLOADED_NetsLab_ARCHIVE.zip" --member Lower_Layer_Data.db
```

It reads only that size-bounded member and writes `work/acquisition/data/raw/Lower_Layer_Data.db` with an extraction receipt. Do not use `--overwrite`. If the provider changes the member name or nesting, inspect the official archive listing and record the change before proceeding; do not guess a substitute.

To request the original 5G-NIDD ZIP from Fairdata:

```text
python work/acquisition/scripts/download_5gnidd.py --output-dir work/acquisition/data/raw/5g-nidd
```

This writes `work/acquisition/data/raw/5g-nidd/Combined.zip` and a sanitized acquisition receipt. The helper verifies the pinned metadata, size and SHA-256 and does not retain temporary download tokens. It downloads data only, not executable attack code. Public service changes may require an updated acquisition-only helper. If download or identity checks fail, stop and inspect the cause rather than bypass the checks or silently replace the scientific input.

The acquisition-only workspace is for downloading/extracting inputs, not executing the frozen experiment: its new acquisition receipts differ from historical metadata. The next command creates a separate clean scientific workspace, imports the exact files, preserves the frozen historical metadata and records the new import in its own receipt.

## Import into a new experiment workspace

After obtaining both files, run from the repository root, replacing the two input paths with their actual locations:

```text
python tools/prepare_workspace.py --kind windows --destination work/windows_full --netslab-db "PATH_TO_Lower_Layer_Data.db" --nidd-zip "PATH_TO_Combined.zip"
```

If you used both acquisition helpers, the fully specified command is:

```text
python tools/prepare_workspace.py --kind windows --destination work/windows_full --netslab-db work/acquisition/data/raw/Lower_Layer_Data.db --nidd-zip work/acquisition/data/raw/5g-nidd/Combined.zip
```

Run only one of these equivalent import commands for that destination. The helper refuses incorrect hashes, symlink/junction destinations and existing output directories. It copies the inputs to the paths expected by the frozen code:

| Imported file | Exact location in the new workspace |
|---|---|
| NetsLab database | `work/windows_full/data/raw/Lower_Layer_Data.db` |
| 5G-NIDD processed archive | `work/windows_full/data/raw/5g-nidd/Combined.zip` |
| New preparation/import receipt | `work/windows_full.preparation.json` |

Do not place raw inputs in `code/windows_frozen/`, `results/` or a saved measurement archive. `work/` is ignored by Git so new raw data and results remain local. No model API key is required for these experiments.

Continue with [Windows Stages 0-5](../docs/03_reproduce.md) and inspect all completion/input-comparison receipts before timing. The complete campaign uses the whole pinned lower-layer database and the declared 5G-NIDD eligible census and seeded panels; the preserved configuration determines which constructed cases are evaluated. We do not select new favorable subsets during reproduction.

See the original [dataset attribution notice](../code/windows_frozen/DATASET.md) for creators, source references, recorded licence terms and transformations. The source-code Apache licence is separate from dataset terms. Derived aggregates/case inputs retain their documented attribution requirements.

## What the data establish

For redistribution of the derived contexts in the evidence archives, see [the standalone third-party notice](THIRD_PARTY_NOTICES.md). It credits both datasets and explains the retained fields and transformations. Original dataset files are omitted, but derived records still require appropriate attribution.

NetsLab contributes O-RAN intrusion context; 5G-NIDD is a related 5G intrusion dataset rather than an O-RAN safe-action dataset. Neither supplies approval evidence, ground-truth permitted responses or post-mitigation outcomes. We make those control contexts explicit in constructed fixtures. This separation lets readers examine policy enforcement without mistaking assumed operator rules for dataset labels.

The packet study uses controlled laboratory traffic generated by the included packet-v7 code. It needs neither source dataset and is not a replay of either dataset through a real radio stack. Its raw packet-event outputs are our own measured evidence, supplied through the companion assets or produced by a new isolated-VM run.
