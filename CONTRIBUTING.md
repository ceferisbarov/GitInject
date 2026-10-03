# Contributing to GitInject

Contribution instructions are maintained in the [documentation](https://ceferisbarov.github.io/GitInject/development/contributing/), with the [source guide](docs/development/contributing.md) available in this checkout.

```bash
uv sync --locked
PYTHONPATH=. uv run pytest tests/unit/
```

For extensions, read [scenario authoring](docs/guides/scenarios.md), [workflow authoring](docs/guides/workflows.md), and the [Python API](docs/api/index.md). For documentation changes, run the [strict site build](docs/development/documentation.md).

Contributions are licensed under the repository's Apache 2.0 license. Use the contact in [README.md](README.md) to report project security issues.
