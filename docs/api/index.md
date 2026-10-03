# Python API

GitInject's Python interfaces live under `src.benchmark`. Work from the repository root, with its dependencies installed through uv. This reference renders current signatures and source directly from the checkout; the linked guides explain how the interfaces fit together.

| Interface | Purpose |
| --- | --- |
| [Runner and analyzer](runner.md) | Execute live trials, optimize attacks, and calculate verdicts. |
| [Scenarios and discovery](scenarios.md) | Define lifecycle hooks, fixtures, event inputs, and evaluators. |
| [Runtime context and records](runtime.md) | Access actors, parameters, artifacts, lineage, and ownership. |
| [Evaluators and evidence](evaluation.md) | Establish boolean outcomes from attributed evidence. |
| [Attacks](attacks.md) | Supply static/adaptive payloads. |
| [GitHub and provisioning](github.md) | REST/GraphQL, repository operations, installation, cleanup. |
| [Scanner pipeline](scanner.md) | Generate, rank, validate, diagnose, and report hypotheses. |
| [Scanner types](scanner-types.md) | Serialize recipes, validation outcomes, memory, and costs. |
| [Model calls and usage](llm.md) | Route model calls and capture token usage. |
| [Types](types.md) | Event, provider, category, and scenario enums. |
| [GitLab](gitlab.md) | GitLab project and MR execution. |

Primary extension points are `AbstractScenario`, `Evaluator`, and `AbstractAttack`. Research controllers typically call `BenchmarkRunner.run()` and consume its returned dictionary and durable attempt files. Helper methods beginning with `_` are internal and omitted from the API navigation.

The CLI is documented [separately](../reference/cli.md). `simulator.py` contains local event-payload helpers and is not the live execution interface. The current runners trigger real services.
