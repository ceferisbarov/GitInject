# Package releases

GitInject is distributed as `gitinject`, with the same name for the command and Python import package. The release version is maintained in `pyproject.toml`.

## Local release checks

```bash
uv sync --locked
uv run pytest tests/unit/
uv build
uvx --from twine twine check --strict dist/*
```

`uv build` builds the source distribution, then builds the wheel from it. The wheel includes workflow YAML and metadata, scenario definitions and fixtures (including hidden CI files), and scanner research notes. Development dependencies are excluded from its runtime requirements.

Test the wheel in a separate project outside the checkout:

```bash
uv init --bare --python 3.13 /tmp/gitinject-consumer
cd /tmp/gitinject-consumer
uv add /absolute/path/to/GitInject/dist/gitinject-0.1.0-py3-none-any.whl
uv run gitinject list workflows
uv run gitinject list scenarios
uv run gitinject run-suite --workflow-labels codex --scenario-type benign --dry-run
uv run python /absolute/path/to/GitInject/scripts/check_distribution.py --require-installed
```

The distribution check compares every bundled file to its source, loads all scenarios and their fixtures, checks Python imports and both runner discovery paths, and verifies that output is written to the experiment workspace. It does not create repositories or call models.

The [Package workflow](https://github.com/ceferisbarov/GitInject/blob/master/.github/workflows/package.yml) runs unit tests on Python 3.13 and 3.14, builds distributions, validates metadata, and tests both `uv add` and `uv tool install`.

## First publication

The maintainer must configure a [pending PyPI Trusted Publisher](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/) before publishing the first release. Use these values:

| Field | Value |
| --- | --- |
| PyPI project name | `gitinject` |
| GitHub owner | `ceferisbarov` |
| Repository | `GitInject` |
| Workflow filename | `release.yml` |
| Environment | `pypi` |

Create the GitHub environment `pypi`. Merge the packaging changes, confirm the Package workflow passes, then create a GitHub release with tag `v0.1.0`. The release workflow checks that the tag matches `pyproject.toml`, runs package verification, and publishes the checked artifacts using OIDC. No long-lived PyPI API token is needed.

After publication, verify `uv add gitinject` in a clean project against PyPI.

## Subsequent releases

Update the version in `pyproject.toml`, refresh `uv.lock` with `uv lock`, run the release checks, and publish a matching `v<version>` GitHub release. PyPI releases are immutable; corrections require a new version. Remove old local distributions before a new build so that metadata checks and uploads use only the intended version.
