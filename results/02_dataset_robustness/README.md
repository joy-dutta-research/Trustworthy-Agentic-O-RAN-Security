# Stage 2: dataset coverage and seeded robustness

Our dataset-grounded tests extend the policy result beyond the common validity suite. The full Trust Boundary admitted 0/16,000 block-required NetsLab proposals and 0/75,000 block-required 5G-NIDD conformance proposals, while admitting every reference-permitted proposal in those groups. These policy and dataset summaries matched between Workstation 1 and Workstation 2.

NetsLab supplies exhaustive aggregate context from 45,244 lower-layer rows, combined with standards-context bases. Twenty control-generation seeds produce 20,000 constructed proposals and 19,945 semantic configurations. `netslab_stratified_results` retains every reported action and seed stratum.

5G-NIDD starts with 1,215,890 source rows. Its eligible natural census contains 733,693 unique records, but only 33 meaningful proposal configurations; all natural proposals are reference-ALLOW and every method admits them. Twenty seeds and nested per-label sizes of 25/100/250 support the separate panel analysis. The 95,000 conformance occurrences contain 162 normalized configurations. Overlapping panels and generated variants must not be counted as independent real incidents.

The **5,000 deliberately forced benign-mitigation probes were admitted by every method**. This gives the feedback experiment a clear motivation: an action can comply with policy yet be unnecessary. It is not a detector false-positive-rate estimate. The gate enforces authorization and constraints; corroboration addresses intervention necessity in Stage 6.

`netslab_method_comparison` contains the four overall method rows. `nidd_group_results` separates the natural census, conformance and false-alarm populations, with original numerator/denominator/rate objects. Ratios use 0–1 units. `sampling_and_eligibility.json` preserves source counts, exclusions, seeds and overlap information. A `0/0` entry below means the group contains no such cases, not a zero failure rate.

| Population | Method | Cases | Block-required admitted / total | Permitted admitted / total |
|---|---|---|---|---|
| NetsLab controls | Direct | 20000 | 16000/16000 | 4000/4000 |
| NetsLab controls | Contract | 20000 | 16000/16000 | 4000/4000 |
| NetsLab controls | Contract + RBAC | 20000 | 9606/16000 | 4000/4000 |
| NetsLab controls | Full Trust Boundary | 20000 | 0/16000 | 4000/4000 |
| 5G-NIDD record_proposals | Direct | 733693 | 0/0 | 733693/733693 |
| 5G-NIDD record_proposals | Contract | 733693 | 0/0 | 733693/733693 |
| 5G-NIDD record_proposals | Contract + RBAC | 733693 | 0/0 | 733693/733693 |
| 5G-NIDD record_proposals | Full Trust Boundary | 733693 | 0/0 | 733693/733693 |
| 5G-NIDD conformance | Direct | 95000 | 75000/75000 | 20000/20000 |
| 5G-NIDD conformance | Contract | 95000 | 75000/75000 | 20000/20000 |
| 5G-NIDD conformance | Contract + RBAC | 95000 | 60000/75000 | 20000/20000 |
| 5G-NIDD conformance | Full Trust Boundary | 95000 | 0/75000 | 20000/20000 |
| 5G-NIDD false_alarm_probes | Direct | 5000 | 0/0 | n/a; see benign probes below |
| 5G-NIDD false_alarm_probes | Contract | 5000 | 0/0 | n/a; see benign probes below |
| 5G-NIDD false_alarm_probes | Contract + RBAC | 5000 | 0/0 | n/a; see benign probes below |
| 5G-NIDD false_alarm_probes | Full Trust Boundary | 5000 | 0/0 | n/a; see benign probes below |

[Column meanings and units](DATA_DICTIONARY.md)

[Results guide](../README.md) · [Previous stage](../01_policy_validity/README.md) · [Next stage](../03_sensitivity/README.md)
