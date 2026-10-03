# GitInject

**A framework for evaluating prompt injection in real AI-powered CI/CD workflows.**

[Documentation](https://ceferisbarov.github.io/GitInject/) · [Paper](https://arxiv.org/abs/2606.09935) · [Contributing](CONTRIBUTING.md) · [Apache 2.0](LICENSE)

GitInject provisions repositories, installs agent workflows, triggers scenario inputs, and evaluates the resulting repository state and agent output. The GitHub runner records copied inputs, execution phases, evidence, and results for each attempt.

It measures utility, security breaches, and verified agent invocation independently. Verdicts can be `true`, `false`, or unknown; execution/evaluation errors are reported separately. The scanner generates and ranks attack hypotheses and validates candidates through the same live run engine. A GitLab runner is also available with a narrower execution contract.

> GitInject creates public repositories, installs credentials, triggers real workflows, and deletes repositories during cleanup. Use a dedicated testing account.

## Get started

Install Python 3.13+, [uv](https://docs.astral.sh/uv/), and the [GitHub CLI](https://cli.github.com/), then run from the repository root:

```bash
uv sync --locked
uv run python -m src.benchmark.cli list workflows
uv run python -m src.benchmark.cli list scenarios
uv run python -m src.benchmark.cli run-suite --workflow-labels codex --scenario-type benign --dry-run
```

Configure your GitHub identity and workflow/judge credentials using the [installation guide](docs/getting-started/installation.md). Then execute a first trial:

```bash
uv run python -m src.benchmark.cli run --workflow codex-pr-review --scenario vulnerable_code_review
```

This pair needs `OPENAI_API_KEY` for Codex and `GEMINI_API_KEY` for semantic evaluation, plus local GitHub authentication. See the [quickstart](docs/getting-started/quickstart.md) for interpreting results.

## Guides and reference

- [Run benchmarks, suites, and bundled paper attacks](docs/guides/running-benchmarks.md)
- [Author Python scenarios](docs/guides/scenarios.md) and [research experiments](docs/guides/research.md)
- [Add workflows](docs/guides/workflows.md)
- [Generate and optimize attacks](docs/guides/attacks.md)
- [Scan workflows](docs/guides/scanner.md)
- [Inspect and reproduce results](docs/guides/results.md)
- [CLI reference](https://ceferisbarov.github.io/GitInject/reference/cli/) and [Python API](https://ceferisbarov.github.io/GitInject/api/)

Build or preview the documentation locally:

```bash
uv sync --locked --group docs
uv run --group docs mkdocs serve
```

The strict build and GitHub Pages deployment instructions are in [documentation development](docs/development/documentation.md).

## Repository layout

| Path | Purpose |
| --- | --- |
| `src/benchmark/` | CLI, runners, scenarios, evaluators, and attempt records. |
| `src/benchmark/workflows/` | Target workflow assets and metadata. |
| `src/benchmark/scenarios/` | Python utility and attack scenarios with fixtures. |
| `src/benchmark/scanner/` | Hypothesis generation, ranking, recipes, validation, diagnostics, and reports. |
| `docs/` | Published guides and reference. |
| `tests/` | Unit and live integration tests. |
| `research/` | Research notes and scanner warm-start material. |
| `plans/` | Historical designs and future work, outside the published documentation. |

## Citation

```bibtex
@article{isbarov2026gitinject,
  title   = {GitInject: Real-World Prompt Injection Attacks in AI-Powered CI/CD Pipelines},
  author  = {Isbarov, Jafar and Suleymanov, Umid and Shumailov, Ilia and Kantarcioglu, Murat},
  journal = {arXiv preprint arXiv:2606.09935},
  year    = {2026},
  url     = {https://arxiv.org/abs/2606.09935}
}
```

Contact Jafar Isbarov at `isbarov at vt dot edu`.
