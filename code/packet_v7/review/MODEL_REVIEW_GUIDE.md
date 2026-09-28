# How to run the two blinded model reviews

These packages review the original 120-case policy-conformance suite, not the
5G-NIDD experiment. The cases are constructed research scenarios, not 120
independently observed incidents. No API key or full raw intrusion dataset is
needed for this manual review.

## Which package goes where

| Destination chosen by the author | Upload only |
| --- | --- |
| GPT-6 Astra, Ultra setting if offered in your interface | model_review_round1/reviewer_a.zip |
| Gemini 3.1 Pro, Extended setting if offered in your interface | model_review_round1/reviewer_b.zip |

These names/settings record the author's requested choices. Check the actual
model and mode displayed by each service; do not silently substitute a different
model. The models receive equivalent case content and the same rubric, with
separate opaque IDs and shuffled order. We retain the private crosswalk locally.

## Steps to follow for each model

1. Start a new, isolated conversation with no previous paper/code discussion.
   Where available, disable memory/project instructions and web browsing. Do not
   use this existing development conversation as the reviewer conversation.
2. Upload only that model's ZIP. If ZIP attachments cannot be read, extract it
   locally and upload the files inside the corresponding reviewer folder. Do not
   upload the whole repository, manuscript, original case generator, results,
   the other model's package, or anything under `review/private`.
3. Paste the contents of that package's `PASTE_PROMPT.txt` as your instruction.
   The model must read the complete cases, policy, trusted approval evidence,
   contract and output specification. Ask it to report an unreadable/truncated
   attachment, not infer missing cases or expected answers.
4. Record the actual model/mode visible in the interface, date, tools used and
   unavailable generation settings. A screenshot of the displayed model setting
   is useful author evidence; do not include private account details.
   Supply those displayed model/mode names in your initial prompt if the model
   cannot observe them. Review its metadata for accuracy before returning it,
   keeping any author correction separate from the unchanged original output.
5. Save the model's original response and downloadable JSON unchanged. If it
   cannot create a downloadable file, save its complete JSON response as a UTF-8
   `.json` file. Keep refusal, truncation and formatting failures too.
6. Return both JSON files to this project/chat, identifying which model produced
   each. Do not show model A's answer to model B or vice versa.

Complete the first response from both models before requesting corrections.
If a response is incomplete, preserve it and request only the missing IDs or a
formatting repair, without sharing the hidden labels or suggesting decisions.
Keep the original and repaired responses separately and record the intervention.
Do not rerun repeatedly until a preferred agreement score appears.

## What each reviewer is asked to return

- Exactly one record for every opaque review ID.
- `ALLOW`, `DENY`, `ESCALATE`, or an explicit information-insufficient abstention.
- The applicable policy rules and a short, checkable explanation.
- Ambiguities and a separate critique of the policy assumptions.
- Run metadata. Do not fabricate unavailable temperature, seed, version or mode.

An operational `ESCALATE` decision is different from the reviewer not having
enough information. No hidden chain-of-thought is requested; concise factual
justifications are sufficient. The detailed output format is inside each ZIP.

## What the comparison can establish

We will validate package IDs, completeness, duplicates and labels, then map the
two different sets of opaque IDs back to the same cases. Report decision
coverage, abstentions, confusion table, raw agreement, Cohen's kappa where
defined, disagreements and rationale/ambiguity flags. Agreement with the
constructed reference is explicitly *reference agreement*, not independently
established accuracy. A constant-label comparison can make kappa undefined;
do not replace that with a perfect score.

Two models can share training information, blind spots and systematic errors.
Separate sessions do not make them statistically independent or prove
correctness. The same model family also contributed to implementation, so
within-family correlated judgement is a potential limitation. High agreement
does not establish that thresholds are appropriate for a real operator.

Appropriate paper wording: "Two separately prompted model reviewers evaluated
blinded cases against the fixed policy specification. Their agreement and
disagreements were reported as model-assisted consistency evidence."

Do not describe this as two independent human experts, operational certification,
or validated safe-action ground truth. Final author adjudication should cover
all disagreements/ambiguities and a preselected sample of agreements.

## What still requires the authors

Model review can help find inconsistencies, but it cannot supply:

1. Operator approval of the illustrative thresholds/protected-service assumptions.
2. Author identities, ORCIDs, repository ownership or publication permission.
3. An actual clean-clone reproduction on a second machine.
4. Accountable verification of each standards citation and the final manuscript.

Blinded case decisions and open-ended policy critique are deliberately separate:
first assess consistency with the declared rules, then question whether those
rules are sufficient or realistic. Do not silently rewrite the policy during
review.

Evaluation methodology reference: [OpenAI evaluation best practices](https://developers.openai.com/api/docs/guides/evaluation-best-practices),
which recommends calibrating model graders with human judgement and documenting
biases. This guide does not assert that either selected model is universally the
best reviewer.
