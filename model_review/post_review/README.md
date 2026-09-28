# Crosswalks released after the review

This folder makes the completed comparison reproducible. **It reveals the answers and must never be included in an answer-masked reviewer upload.**

| File | How to use it |
| --- | --- |
| `reviewer_a_mapping.json` | Map A's opaque review IDs to the shared case IDs and constructed reference decisions |
| `reviewer_b_mapping.json` | Map B's different opaque IDs to those same cases |
| `original_comparison.json` | Preserved numerical comparison made on 22 September 2026 |
| `HISTORICAL_REVIEW_ASSESSMENT.md` | Preserved contemporary interpretation of the original responses and critiques |

We keep every case assignment and reference label in both public mappings. We removed the retired key used to create opaque identifiers because it is not needed to reproduce the comparison. Original file hashes and the transformation are documented in [the source manifest](../SOURCE_MANIFEST.json).

Fields under `original_identity_sha256` are provenance identities recorded by the original generator. Some are hashes of canonical JSON objects rather than the pretty-printed upload bytes. Do not compare those values directly to an upload file's byte hash. Use `SOURCE_MANIFEST.json` to verify the supplied public file bytes.

The historical assessment is not a newly completed human-adjudication record. It helps explain the policy critiques, including distinctions between the 120 reviewed cases and the implementation's wider tests. Author/operator approval of policy adequacy remains a separate responsibility.

The [public analysis script](../../tools/analyze_model_reviews.py) reconstructs the new reader tables directly from the returned responses and these mappings. It does not substitute the historical aggregate as a new observation.
