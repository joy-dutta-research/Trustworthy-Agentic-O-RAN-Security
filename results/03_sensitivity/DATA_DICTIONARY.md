# Column meanings and units

`condition` identifies one fixed policy/mapping variant. `cases` is the number of case occurrences used to compare that condition with the primary setting. `expected_decision_changed_from_primary`, `expected_reasons_changed_from_primary`, and `proposal_changed_from_primary` are counts on those same fixed inputs; they are not percentages. A zero change does not mean the setting is universally insensitive.

`all_method_results` uses the same nested numerator/denominator/rate definitions as Stage 2. `population` identifies the sensitivity condition; `group` keeps natural records, conformance and false-alarm probes separate. Every method is retained, even when a condition has no decision changes.

CSV and JSON contain the same data. JSON preserves nested structure; CSV flattens object keys with dots and encodes lists explicitly as JSON strings. Empty CSV cells correspond to missing/not-applicable JSON values, not measured zeros. Booleans are true/false. `source` fields are repository-relative evidence filenames followed by JSON Pointers; array indexes are zero-based. Source pointers locate the saved input value, not another independent experiment.

[Back to this stage](README.md)
