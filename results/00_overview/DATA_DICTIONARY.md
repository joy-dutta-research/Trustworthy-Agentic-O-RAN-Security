# Column meanings and units

`stage_map` has one row per stage: `question` is the evaluation question, `evidence` describes the completed test, and `meaning` states the supported conclusion. `source_identities` records SHA-256 and byte length of the two evidence JSON inputs actually read by this exporter. `export_checks` describes export consistency only; PASS is not a new scientific result.

CSV and JSON contain the same data. JSON preserves nested structure; CSV flattens object keys with dots and encodes lists explicitly as JSON strings. Empty CSV cells correspond to missing/not-applicable JSON values, not measured zeros. Booleans are true/false. `source` fields are repository-relative evidence filenames followed by JSON Pointers; array indexes are zero-based. Source pointers locate the saved input value, not another independent experiment.

[Back to this stage](README.md)
