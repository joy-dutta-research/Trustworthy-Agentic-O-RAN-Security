# Preserved first responses

| File | What it contains |
| --- | --- |
| [reviewer_a.json](reviewer_a.json) | Reviewer A's 120 decisions, concise explanations, rule references, uncertainty flags, metadata and 10 policy-critique entries |
| [reviewer_a_run_notes.txt](reviewer_a_run_notes.txt) | A's original account of attachment access, isolation limits and formatting recovery |
| [reviewer_b.json](reviewer_b.json) | Reviewer B's 120 decisions, explanations, rule references, uncertainty flags, metadata and 3 policy-critique entries |

We preserve byte-for-byte copies of the returned artifacts. A public filename change is not a substantive edit. Original and copied hashes are in [the manifest](../SOURCE_MANIFEST.json). We did not call either model again or repair a response to improve its agreement score during repository preparation.

A reported an initial input-display truncation resolved by reading smaller complete sections, and a command-length error resolved by writing the same first serialized response in chunks. The notes report no substantive decision rerun. They also state that service-enforced isolation could not be certified. B's response lists no tools used; no equivalent run-notes attachment is available. Those differences are recorded rather than inferred away.

Both responses contain `not_available` for displayed model and mode. See [our separate identification record](../MODEL_IDENTIFICATION.json); we have not overwritten the original metadata with the reported model names.

To read their findings side by side, use [case_comparison.csv](../../results/08_model_review/case_comparison.csv). All original critiques appear in [policy_critiques.csv](../../results/08_model_review/policy_critiques.csv), with discussion in the accompanying interpretation. These are model-generated critiques of the supplied material, not automatically established defects in the whole implementation.
