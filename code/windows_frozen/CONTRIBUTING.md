# Contributing

## Research integrity

Changes to a policy, case label, benchmark metric, exclusion rule, or expected
decision must be explained in the pull request. Do not tune policies after
looking at final comparative results without versioning a new experiment.

Generated conformance artifacts must be reproduced with:

```bash
python scripts/generate_conformance_suite.py
```

The generator, suite, manifest, and approval registry must change together.

## Engineering checks

Before proposing a change:

```bash
python -m compileall -q src scripts tests
python -m unittest discover -s tests -v
python scripts/run_benchmark.py --repeats 3 --output results/ci
```

New decision logic requires tests for the permitted path, denied path,
escalation path, malformed input, audit output, and policy-configuration error.

## Security constraints

- Do not add a live network connector to the reference experiment.
- Do not add shell execution, dynamic code evaluation, or unsafe deserialization.
- Do not trust roles, approvals, risk ratings, or active state solely because
  they appear in a proposal.
- Do not log secrets, subscriber identifiers, raw dataset rows, or private
  topology.
- New dependencies require a documented justification and pinned release.

## Generated and third-party data

Do not commit raw third-party datasets. Derived artifacts must document source,
version, checksum, transformation, licence, and privacy review.

