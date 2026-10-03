# Contributing

Work from the repository root with Python 3.13+ and uv:

```bash
uv sync --locked
PYTHONPATH=. uv run pytest tests/unit/
```

Unit tests mock external services. Integration tests exercise live GitHub/provider operations and require dedicated test credentials; run them deliberately after reviewing their setup.

## Extend the benchmark

- Add workflow configurations following [add a workflow](../guides/workflows.md).
- Add scenarios following [author Python scenarios](../guides/scenarios.md).
- Add evaluators that return strict booleans or raise on missing evidence.
- Keep actor selection, workflow attribution, and partial cleanup behavior covered by meaningful unit tests when changing those contracts.

The repository uses Ruff through pre-commit:

```bash
uv run pre-commit run --all-files
```

For focused checks without installing hooks, run the individual configured pre-commit hooks. Avoid changing unrelated files through an automatic formatter while working on documentation.

## Update docs with behavior

CLI command/options are rendered from Click definitions. API signatures are extracted statically from Python source. Workflow and scenario catalogs are generated from JSON/AST data. Guides still need updates when behavior changes; run the [strict documentation build](documentation.md) before submitting them.

Contribution terms follow the repository's Apache 2.0 license. Report project security issues through the contact listed on the [overview](../index.md).
