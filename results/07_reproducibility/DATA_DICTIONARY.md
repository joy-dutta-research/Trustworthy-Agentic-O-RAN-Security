# Column meanings and units

`equal_across_windows_hosts` compares complete saved fixed-summary objects, not only rounded headlines. Case identity rows retain `group`, `seed`, `count`, `expected_sha256`, `actual_sha256`, and `match`; null seed denotes a file not keyed to a dataset-sampling seed. All 42 case-file identities are retained.

The regeneration summary distinguishes exact case/workload bytes from parsed aggregate equality. Packet source/return hashes identify historical archives whose source data support the views. A file hash is not a digital signature, privacy certification, or proof that an experiment's scientific claim is true. This exporter reads aggregate evidence; consult the repository's raw-evidence guide for packet logs and full raw Windows measurements.

CSV and JSON contain the same data. JSON preserves nested structure; CSV flattens object keys with dots and encodes lists explicitly as JSON strings. Empty CSV cells correspond to missing/not-applicable JSON values, not measured zeros. Booleans are true/false. `source` fields are repository-relative evidence filenames followed by JSON Pointers; array indexes are zero-based. Source pointers locate the saved input value, not another independent experiment.

[Back to this stage](README.md)
