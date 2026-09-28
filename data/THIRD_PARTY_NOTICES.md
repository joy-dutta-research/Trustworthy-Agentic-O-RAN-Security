# Third-party dataset attribution for the evidence release

Our six evidence archives combine new experimental records with some dataset-derived content. We do not claim ownership of the source datasets. The original database, original combined CSV/ZIP, packet captures, third-party papers and standards documents are not mirrored in these archives.

## Dataset-derived material in the archives

- `university_windows_final.zip` and `workstation_windows_final.zip` contain 5G-NIDD-derived contexts alongside our decisions and measurements. In particular, census records retain a source-row reference, attack label, duration, packet count and a calculated packet rate. These are adapted extracts, not wholly new observations. Seeded case files also retain selected observed context.
- `campaign_provenance.zip` contains NetsLab-derived aggregate contexts, including class counts and selected signal summaries, alongside our campaign records and constructed workloads.
- The three packet archives contain controlled laboratory traffic records and development evidence. They are not captures redistributed from NetsLab or 5G-NIDD.

These extracts are not complete copies of the original datasets; they remain dataset-derived material with attribution obligations.

## NetsLab-5GORAN-IDD

Source: **NetsLab-5G Open RAN Intrusion Detection Dataset**, created by Network Softwarization and Security Labs (NetsLab), University College Dublin: **Alan Civciss, Vidura Ravihansa, Farah Abed Zadeh, Chamara Sandeepa and Madhusanka Liyanage**.

- [Creator's dataset page](https://netslab.ucd.ie/netslab-datasets/netslab-5goran-idd/)
- [Official Kaggle distribution](https://www.kaggle.com/datasets/netslabdemo/netslab-5g-oran-idd)
- [Dataset DOI: 10.34740/kaggle/ds/7416931](https://doi.org/10.34740/kaggle/ds/7416931)
- Licence: [Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/)

The data card requests citation of A. Civciss, V. Ravihansa, F. Abed Zadeh, C. Sandeepa and M. Liyanage, “Silent Signals, Loud Threats: Using dApps for Radio Signal Intelligence-based Intrusion Detection in 5G O-RAN,” IEEE GLOBECOM, 2025.

We adapted the lower-layer measurements into class-level counts and selected signal summaries for action-policy contexts. The aggregate export omits raw records, timestamps, UE identifiers, RNTIs and cell identifiers. Action proposals, operator permissions and approval evidence are constructed by our experiment, not supplied by the dataset.

The official Kaggle metadata was checked on 28 September 2026 and explicitly identifies CC BY 4.0. Our frozen input identity is recorded separately; a licence check is not a new dataset download or a change of dataset version.

## 5G-NIDD

Source: **5G-NIDD: A Comprehensive Network Intrusion Detection Dataset Generated over 5G Wireless Network**, provided by **Yushan Siriwardhana, University of Oulu**.

Descriptor attribution: **Yushan Siriwardhana, Sehan Samarakoon, Pawani Porambage, Madhusanka Liyanage, Sang-Yoon Chang, Jinoh Kim, Jonghyun Kim and Mika Ylianttila**.

- [Authors' repository](https://github.com/yushan1986/5g-nidd)
- [Original dataset DOI: 10.23729/e80ac9df-d9fb-47e7-8d0d-01384a415361](https://doi.org/10.23729/e80ac9df-d9fb-47e7-8d0d-01384a415361)
- [Original Fairdata landing page](https://etsin.fairdata.fi/dataset/9d13ef28-2ca7-44b0-9950-225359afac65)
- [Descriptor: 5G Wireless Network Intrusion Detection Dataset (5G-NIDD), IEEE Data Descriptions, 2025](https://doi.org/10.1109/IEEEDATA.2025.3592888)
- Licence: [Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/)

We select eligible source records, retain limited label/duration/packet-count fields and source-row references, and calculate packet-rate summaries. The evaluated census covers the declared eligible records; it is not only a handful of examples. Our proposed actions, identities for simulated control, permissions, approvals and policy decisions are separate constructed or computed additions. They are not original 5G-NIDD response labels.

The original Fairdata metadata was checked on 28 September 2026 and explicitly identifies CC BY 4.0. Its listed `Combined.zip` size and SHA-256 match our recorded input. The original raw processed archive is acquired separately from its provider.

## Licence boundaries and preservation

The above third-party material remains subject to its original CC BY 4.0 terms. Preserve creator credit, source and licence links, supplied notices and this description of changes when redistributing covered material. We do not apply the software's Apache-2.0 licence in place of the dataset licence, impose additional restrictions on the dataset creators' licensed rights, or imply that they endorse this study.

The datasets are provided without warranties under their original licences. The full terms, including the disclaimer and rights not covered, are available in the [CC BY 4.0 legal code](https://creativecommons.org/licenses/by/4.0/legalcode.en). A copyright licence does not by itself resolve privacy, institutional-approval or other third-party-rights questions.

Our included software/helper snapshots retain the project's Apache-2.0 software licence. Author-created documentation and research contributions are distinct from the third-party material; this notice does not invent a new blanket licence for them or grant rights to the withheld manuscript or publication artwork.

The scientific evidence members and numerical measurements are unchanged. The public ZIPs include expanded root README files carrying these notices and the existing software licence; their updated archive checksums identify this documentation-only packaging revision. Original pre-notice ZIPs remain in private author storage, and the original-to-public identities are recorded separately. `PUBLIC_MANIFEST.json` within each archive also identifies the previously recorded transformations, including declared personal-path substitutions. Retain the README and relevant notices when sharing dataset-derived portions.
