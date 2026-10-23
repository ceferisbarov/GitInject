# GitInject

> Use **v0.1.0 for replication of the original paper**. The new GitHub [experiment engine](guides/experiments.md) uses targets, attack instances, two accounts, and isolated sessions. Original execution commands are under `gitinject legacy`; legacy runners/scanner/GitLab do not meet the new isolation contract.

**Evaluate prompt injection in real AI-powered CI/CD workflows.**

GitInject provisions repositories, installs an agent workflow, creates a scenario's input, and observes the resulting workflow run and repository state. It measures whether the agent completes its task, whether the attack succeeds, and whether an agent invocation can be verified.

Use it to compare workflow configurations, reproduce the bundled attacks, build custom experiments, or generate hypotheses with the vulnerability scanner.

## Install and explore

With Python **3.13+**, [uv](https://docs.astral.sh/uv/), and the [GitHub CLI](https://cli.github.com/) installed:

```bash
uv tool install gitinject
gitinject list workflows
gitinject list scenarios
gitinject run-suite --workflow-labels codex --scenario-type benign --dry-run
```

GitInject is available on [PyPI](https://pypi.org/project/gitinject/) with workflows, scenarios, and fixtures bundled. Run commands from your experiment directory; evidence is saved to `runs/` and reports to `reports/`. The dry run lists compatible pairs without creating repositories or calling models.

Follow [installation and configuration](getting-started/installation.md) to set up credentials, then [run your first benchmark](getting-started/quickstart.md). For the Python API, install into your project with `uv add gitinject`.

## Start here

| Goal | Read |
| --- | --- |
| Set up your environment | [Installation and configuration](getting-started/installation.md) |
| Execute one experiment | [First benchmark](getting-started/quickstart.md) |
| Understand the measurement contract | [Metrics and evidence](concepts/evaluation.md) |
| Write an attack or utility task | [Author Python scenarios](guides/scenarios.md) |
| Automate a research loop | [Research experiments](guides/research.md) |
| Explore interfaces | [CLI reference](reference/cli.md) and [Python API](api/index.md) |

## What runs where

The local Python process orchestrates the experiment. GitHub Actions executes the target agent. Provider APIs supply agent models, semantic judges, and optional attack generation. These are live executions with actual repository permissions and workflow costs.

The GitHub runner records each attempt under `runs/<attempt_id>/`, including copied inputs, their hashes, an execution journal, evidence, and results. A [GitLab runner](guides/gitlab.md) also exists, with a narrower lifecycle and evidence contract.

!!! warning "Use a dedicated testing account"
    GitInject creates public repositories, installs credentials, triggers workflows, and deletes repositories during cleanup. Use accounts and credentials dedicated to experiments.

## Research

GitInject accompanies *GitInject: Real-World Prompt Injection Attacks in AI-Powered CI/CD Pipelines*. The [paper reproduction guide](guides/running-benchmarks.md#reproduce-the-bundled-paper-attacks) lists the shipped attack/workflow pairs. Consult the [workflow](reference/workflows.md) and [scenario](reference/scenarios.md) catalogs for the current checkout.

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

The source is available on [GitHub](https://github.com/ceferisbarov/GitInject) under Apache 2.0. For project inquiries, contact Jafar Isbarov at `isbarov at vt dot edu`.
