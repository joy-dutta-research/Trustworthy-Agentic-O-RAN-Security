# Contributing to this research artifact

Start with [the study overview](docs/01_study_overview.md) and [the reproduction guide](docs/03_reproduce.md). The goal is to make the measured PoC easier to inspect and extend while preserving what was actually evaluated.

- Keep new results in a new run directory and identify the source/input/configuration versions.
- Preserve original measurements. Derive public/redacted outputs separately and record the transformation.
- Do not edit a result value to fit the interpretation or omit an unfavourable condition.
- Keep changes to publication tools separate from changes to frozen scientific implementations.
- Add tests for parsing, units, denominators, boundaries and failure behavior. Read-only CI must not launch privileged packet experiments.
- Explain the question addressed by an extension and distinguish observed outcomes from expected improvements.

Before a public-visibility release, the authors review the paper-to-result mapping, licensing/privacy, citation metadata and evidence integrity. Changes and new experimental runs require their own review. Joy Dutta authorized depositing this reproducibility package in the named private GitHub repository; that authorization does not make future uploads, merges, visibility changes or privileged experiments automatic.

Identify the terms and provenance of any new contribution. Our software uses Apache-2.0, while our original guides/results and third-party data follow the separate scopes in [LICENSES.md](LICENSES.md). Do not contribute material unless you are authorized to share it under the applicable terms.
