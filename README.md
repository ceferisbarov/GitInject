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

**Use v0.1.0 for replication of the original paper.** The current experiment API replaces workflow/scenario pairs with explicit targets, attack instances, threat models, privileged provisioning, and fixed evaluation contracts. Original commands now live under `gitinject legacy`; that engine and its scanner do not provide the new controller-isolation guarantees. No GitLab adapter yet meets the new contracts.

GitInject runs fresh trials using two dedicated GitHub machine accounts: defense provisions the target, while attack interacts through its own credentials and GitHub permissions. Static, offline, and online adaptive controllers use a reusable session API. Each trial records actions, observations, workflow invocation, independent utility/security results, and reproducible evidence.

## Get started

Install Python 3.13+, [uv](https://docs.astral.sh/uv/), and the [GitHub CLI](https://cli.github.com/), then work from this checkout:

```bash
uv sync --locked
uv run gitinject experiment list examples/experiments
uv run gitinject experiment dry-run examples/experiments/issue-injection.json
```

Configure `GITHUB_TOKEN` for defense, `ATTACKER_GITHUB_TOKEN` for a distinct attack account, and `OPENAI_API_KEY` for the example agent. All resources accessible to these dedicated credentials are in the experiment scope. Attack credentials never fall back to defense. Adaptive controllers additionally require Linux x86_64 and working Bubblewrap isolation.

```bash
uv run gitinject experiment run examples/experiments/benign.json
uv run gitinject experiment run examples/experiments/adaptive.json
uv run gitinject experiment replay runs/ATTEMPT --mode inspect
```

These commands create public repositories, run real workflows, and clean up attributed repository identities. Planning and dry runs do not mutate GitHub or call models. Evidence is saved to `runs/`. See the [experiment guide](docs/guides/experiments.md) for account scope, worker guarantees, result meanings, transport coverage, replay limits, and examples.

The Python API is `from gitinject.experiments import ExperimentSession, ExperimentSpec`. Generated attack code uses the isolated worker protocol; the host Python session API is for a trusted research orchestrator.

## Guides and reference

- [Targets, attacks, adaptive sessions, and replay](docs/guides/experiments.md)
- [v0.1.0 benchmarks, suites, and bundled paper attacks](https://ceferisbarov.github.io/GitInject/guides/running-benchmarks/)
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
| `src/gitinject/experiments/` | Versioned contracts, actor gateway, isolated worker, sessions, evaluation, and replay. |
| `examples/experiments/` | New benign, issue, fork-PR, online, and offline experiment fixtures. |
| `src/gitinject/` | CLI, legacy runners, evaluators, and shared attempt records. |
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
