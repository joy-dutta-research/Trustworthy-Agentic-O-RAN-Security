# Model-assisted policy review

In this companion study, we ask a focused question: **can separately prompted reviewers interpret the written policy consistently?** We examine the policy as a written specification, complementing the software tests of enforcement and the packet tests of intervention consequences.

This is part of our supporting material for *Trustworthy Agentic O-RAN Security: From Threat Detection to Safe Action, Governance, and Standardization*, currently under review. We will add the accepted-paper citation when available. The package is maintained in [our repository](https://github.com/joy-dutta/Trustworthy-Agentic-O-RAN-Security); repository access follows its current sharing settings.

## Read this part in order

1. Read the [results and their meaning](../results/08_model_review/README.md).
2. Inspect the [original reviewer inputs](inputs/README.md): equivalent case content, different opaque IDs and ordering, the same policy and decision rubric.
3. Inspect the [preserved first responses](responses/README.md), including explanations, uncertainties and critiques.
4. Use the [post-review crosswalks](post_review/README.md) to align the different IDs and check the reference comparison.
5. Recompute the saved tables with `python tools/analyze_model_reviews.py --check` from the repository root. This is read-only and calls no model. Omit `--check` to regenerate only the five derived result files.

For additional parser/coverage regression checks, run `python -B model_review/test_analysis.py`. These tests include duplicate, missing and unknown cases, invalid labels, wrong packages and malformed uncertainty flags. They test the analysis utility, not a model's scientific validity.

## What was reviewed

Each reviewer assessed the original **120 constructed policy-conformance cases**: 60 NetsLab-label-context fixtures and 60 standards-context fixtures. Related variants share base scenarios. This is not a review of the later 5G-NIDD panels, the expanded 777-case validity suite, or all packet episodes.

We identify Reviewer A as **GPT-6 Astra Ultra** and Reviewer B as **Gemini 3.1 Pro Extended**, based on the model selections we reported. The original record described B more briefly as **Gemini Pro, Extended**. Both returned files say the displayed model and mode were `not_available`. The [identification record](MODEL_IDENTIFICATION.json) preserves that distinction. These are author-reported names, not independently verified version identifiers or a model leaderboard comparison.

Both returned all 120 decisions. Their decisions agree with each other and with the constructed reference labels: 20 ALLOW, 60 DENY and 40 ESCALATE decisions from each reviewer. Both supplied explanations; explicit rule citations accompanied 120 decisions from A and 80 from B. We retain this traceability difference alongside the agreement. Their critiques also offer useful design directions, including evidence relevance, target-to-slice mapping and clear policy semantics. The [interpretation](../results/08_model_review/INTERPRETATION.md) explains what the agreement supports and how the critiques inform future work.

## How this supports the paper

This material supports the **Trust Boundary**, **Safe Action Verification**, and **Audit** aspects of our framework: a policy decision can be related to an explicit rule, a supplied case, a returned explanation and a reproducible comparison. The practical contribution is consistency in explaining whether a proposed action is permitted, forbidden or awaiting approval. We use it as an auxiliary consistency check, **not independent human-expert validation or an evaluated runtime LLM controller**. It does not establish whether a real alert was correct or an intervention helped; the controlled packet tests address intervention consequences. No API key is needed to inspect or recompute this review.

The input packages were designed to hide expected answers. A's notes describe attachment-only review and disclose that service-enforced isolation was not observable. Equivalent isolation notes were not supplied for B. Accordingly, use “answer-masked model-assisted consistency review,” not “certified independent blinded validation.”

## Preservation and publication

We preserve the original response files and supplied input files byte-for-byte. Only the released crosswalks were transformed: we omitted the retired identifier-generation key and added a post-review disclosure. We did not change case IDs, decisions or critiques. [SOURCE_MANIFEST.json](SOURCE_MANIFEST.json) records original and public SHA-256 values and transformations.

The complete original prompts are retained as research provenance, not instructions to run automatically. All reference labels and mappings below `post_review/` are disclosed **after** the completed round. Never give that folder, the results, or either response to a new reviewer as supposedly answer-masked input. Any future review should be separately versioned; exact model outputs are not guaranteed to repeat.
