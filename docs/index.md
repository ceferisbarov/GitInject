# GitInject

**Evaluate prompt injection in real AI-powered CI/CD workflows.**

GitInject provisions repositories, installs an agent workflow, creates a scenario's input, and observes the resulting workflow run and repository state. It measures whether the agent completes its task, whether the attack succeeds, and whether an agent invocation can be verified.

Use it to compare workflow configurations, reproduce the bundled attacks, build custom experiments, or generate hypotheses with the vulnerability scanner.

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
  title   = {GitInject: Real-World Prompt Injection Attacks in AI-Powered CI/CD Pipelines},
  author  = {Isbarov, Jafar and Suleymanov, Umid and Shumailov, Ilia and Kantarcioglu, Murat},
  journal = {arXiv preprint arXiv:2606.09935},
  year    = {2026},
  url     = {https://arxiv.org/abs/2606.09935}
}
```

The source is available on [GitHub](https://github.com/ceferisbarov/GitInject) under Apache 2.0. For project inquiries, contact Jafar Isbarov at `isbarov at vt dot edu`.
