# GitInject

**A framework for evaluating prompt injection in real AI-powered CI/CD workflows.**

[![NeurIPS 2026 accepted](https://img.shields.io/badge/NeurIPS_2026-Accepted-6842C2)](https://neurips.cc/Conferences/2026/CallForEvaluationsDatasets)
[![arXiv](https://img.shields.io/badge/arXiv-2606.09935-B31B1B?logo=arxiv&logoColor=white)](https://arxiv.org/abs/2606.09935)
[![PyPI](https://img.shields.io/pypi/v/gitinject)](https://pypi.org/project/gitinject/)
[![Python 3.13+](https://img.shields.io/badge/Python-3.13%2B-3776AB?logo=python&logoColor=white)](https://github.com/ceferisbarov/GitInject/blob/master/pyproject.toml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-22863A)](https://github.com/ceferisbarov/GitInject/blob/master/LICENSE)

📚 [Documentation](https://ceferisbarov.github.io/GitInject/) · 📄 [Paper](https://arxiv.org/abs/2606.09935) · 🧪 [Reproduce paper attacks](https://ceferisbarov.github.io/GitInject/guides/running-benchmarks/#reproduce-the-bundled-paper-attacks) · 🤝 [Contributing](https://github.com/ceferisbarov/GitInject/blob/master/CONTRIBUTING.md)

🎉 **Accepted to the NeurIPS 2026 Evaluations & Datasets Track!**

Our paper, [*GitInject: Real-World Prompt Injection Attacks in AI-Powered CI/CD Pipelines*](https://arxiv.org/abs/2606.09935), introduces the framework and studies attacks against AI-powered GitHub workflows.

GitInject provisions repositories, installs agent workflows, triggers scenario inputs, and evaluates the resulting repository state and agent output. Use it to reproduce attacks, compare workflow defenses, and build custom experiments.

- **Live workflow evaluation:** run utility tasks and prompt injection scenarios in real GitHub Actions workflows.
- **Independent measurements:** track task completion, security breaches, and verified agent invocation. Verdicts can be `true`, `false`, or unknown; execution and evaluation errors are reported separately. A security breach means the attack succeeded.
- **Inspectable results:** each GitHub attempt records copied inputs, execution phases, evidence, and results.
- **Attack discovery:** the scanner generates and ranks attack hypotheses, then validates candidates through the same live run engine.

A [GitLab runner](https://ceferisbarov.github.io/GitInject/guides/gitlab/) is also available with a narrower execution and evidence contract. See [metrics and evidence](https://ceferisbarov.github.io/GitInject/concepts/evaluation/) for how verdicts are determined.

> GitInject creates public repositories, installs credentials, triggers real workflows, and deletes repositories during cleanup. Use a dedicated testing account.

## Get started

Install Python 3.13+, [uv](https://docs.astral.sh/uv/), and the [GitHub CLI](https://cli.github.com/). Install GitInject from [PyPI](https://pypi.org/project/gitinject/) as a standalone CLI:

```bash
uv tool install gitinject
gitinject list workflows
gitinject list scenarios
gitinject run-suite --workflow-labels codex --scenario-type benign --dry-run
```

The workflows, scenarios, and fixtures are bundled, so no checkout is needed. Run commands from your experiment directory; evidence is saved to `runs/` and reports to `reports/`. If `gitinject` is not found after installation, run `uv tool update-shell` and restart your shell.

The dry run lists compatible pairs without creating repositories or calling models. Configure your GitHub identity and workflow/judge credentials using the [installation guide](https://ceferisbarov.github.io/GitInject/getting-started/installation/), then run a first benign trial:

```bash
gitinject run --workflow codex-pr-review --scenario vulnerable_code_review
```

This pair needs `OPENAI_API_KEY` for Codex and `GEMINI_API_KEY` for semantic evaluation, plus local GitHub authentication. See the [quickstart](https://ceferisbarov.github.io/GitInject/getting-started/quickstart/) for interpreting results.

For the Python API, use `uv add gitinject` in your project and import from `gitinject`, for example `from gitinject.runner import BenchmarkRunner`. For development or paper reproduction with the checked-in dependency lockfile, see [checkout installation](https://ceferisbarov.github.io/GitInject/getting-started/installation/#develop-or-reproduce-from-a-checkout).

## Guides and reference

- [Run benchmarks, suites, and bundled paper attacks](https://ceferisbarov.github.io/GitInject/guides/running-benchmarks/)
- [Author Python scenarios](https://ceferisbarov.github.io/GitInject/guides/scenarios/) and [research experiments](https://ceferisbarov.github.io/GitInject/guides/research/)
- [Add workflows](https://ceferisbarov.github.io/GitInject/guides/workflows/)
- [Generate and optimize attacks](https://ceferisbarov.github.io/GitInject/guides/attacks/)
- [Scan workflows](https://ceferisbarov.github.io/GitInject/guides/scanner/)
- [Inspect and reproduce results](https://ceferisbarov.github.io/GitInject/guides/results/)
- [CLI reference](https://ceferisbarov.github.io/GitInject/reference/cli/) and [Python API](https://ceferisbarov.github.io/GitInject/api/)

For local documentation previews, strict builds, and GitHub Pages deployment, see [documentation development](https://ceferisbarov.github.io/GitInject/development/documentation/).

## Repository layout

| Path | Purpose |
| --- | --- |
| `src/gitinject/` | CLI, runners, scenarios, evaluators, and attempt records. |
| `src/gitinject/workflows/` | Target workflow assets and metadata. |
| `src/gitinject/scenarios/` | Python utility and attack scenarios with fixtures. |
| `src/gitinject/scanner/` | Hypothesis generation, ranking, recipes, validation, diagnostics, and reports. |
| `docs/` | Published guides and reference. |
| `tests/` | Unit and live integration tests. |
| `research/` | Research notes and scanner warm-start material. |

## Citation

```bibtex
@article{isbarov2026gitinject,
      title={{GitInject: Real-World Prompt Injection Attacks in AI-Powered CI/CD Pipelines}}, 
      author={Jafar Isbarov and Umid Suleymanov and Ilia Shumailov and Murat Kantarcioglu},
      year={2026},
      eprint={2606.09935},
      archivePrefix={arXiv},
      primaryClass={cs.CR},
      url={https://arxiv.org/abs/2606.09935}, 
}
```

Contact Jafar Isbarov at `isbarov at vt dot edu`.
