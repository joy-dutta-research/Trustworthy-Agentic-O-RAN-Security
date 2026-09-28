# Safety, contributions and automated checks

This folder contains the repository's working rules, kept together so the main page can focus on the research and reproducibility routes. This guide is deliberately named `GUIDE.md`: GitHub gives a README in this folder priority over the research README at the repository root.

| Read | Purpose |
|---|---|
| [SECURITY.md](SECURITY.md) | Safe analysis, isolated packet experiments and responsible reporting |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to propose improvements without changing the recorded scientific baseline |
| [workflows/README.md](workflows/README.md) | What the automated Windows and Ubuntu checks do |

The workflow runs software and artifact checks on pushes and pull requests. It has read-only repository permissions, does not run packet experiments and does not publish anything. Its [latest run status](https://github.com/joy-dutta/Trustworthy-Agentic-O-RAN-Security/actions) is separate from the recorded experiments.

Return to [the main reading guide](../README.md) to choose a reproducibility task.
