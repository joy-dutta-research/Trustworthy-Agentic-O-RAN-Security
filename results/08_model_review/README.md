# Auxiliary model-review results

We include this completed answer-masked review to check whether the written policy can be interpreted consistently by two separately prompted models. The `08` prefix keeps it after the Stage 0–7 results in the reading order; **it is not an additional experimental stage** and we did not deploy the models inside the packet controller.

Start with [SUMMARY.md](SUMMARY.md) for the numerical outcome, then [INTERPRETATION.md](INTERPRETATION.md) for how it complements our implementation and packet tests.

| File | What one row or field means |
| --- | --- |
| [summary.csv](summary.csv) | One reviewer; counts of decisions, reference matches, ambiguity flags and rule-reference coverage |
| [summary.json](summary.json) | The same counts plus the full confusion matrix, source-context counts, metadata and descriptive agreement statistics |
| [case_comparison.csv](case_comparison.csv) | One shared constructed case; reference decision, both original decisions, explanations, notes, rule citations and agreement flags |
| [policy_critiques.csv](policy_critiques.csv) | One original policy-critique entry; reviewer and original order are retained |

CSV files use a single header row and UTF-8 text. Counts are integers; JSON agreement values are fractions (1.0 means 100%). Boolean columns indicate an observed flag or exact label equality, not a confidence score. `rule_refs_json` preserves an array inside a CSV field. An empty array means no explicit citation was returned; it does not erase the reviewer's rationale.

The reference labels are constructed labels under the stated policy, not independent operational ground truth. `INSUFFICIENT_INFORMATION` is reviewer abstention, whereas `ESCALATE` is a policy decision to defer an action for conflict handling or approval. These must not be combined.

## Recompute without calling a model

From the repository root, use Python 3.11 or later, as recommended for the other repository helpers:

```text
python tools/analyze_model_reviews.py --check
```

The read-only check verifies source hashes, package IDs, unique case coverage, crosswalk completeness and saved-result equality. No API key, internet access or gateway execution is required. To regenerate the five derived files, run the same command without `--check`; the original responses and mappings remain unchanged.

The input trail begins at [model_review/README.md](../../model_review/README.md). The material supports the paper's discussion of explicit policy, verification and auditable reasoning. The accepted-paper citation will be added after acceptance; the manuscript is currently under review.
