# Installation and configuration

The project requires Python **3.13 or newer**, [uv](https://docs.astral.sh/uv/), and the [GitHub CLI](https://cli.github.com/). The CLI is used for operations such as installing Actions secrets and fetching logs, even when API authentication uses an environment variable.

## Install the CLI

Install the released package from [PyPI](https://pypi.org/project/gitinject/) into an isolated tool environment:

```bash
uv tool install gitinject
gitinject --help
gitinject list workflows
```

Workflows, scenarios, fixtures, and scanner research notes are bundled. No source checkout or project setup is needed. The examples in the quickstart and guides use `gitinject` directly.

If the command is not found, run `uv tool update-shell` and restart your shell. To upgrade an installed CLI, run `uv tool upgrade gitinject`. If your default Python is older than 3.13, install with `uv tool install --python 3.13 gitinject`.

## Install the Python API into a project

For scripts, notebooks, or research controllers that import GitInject, add it to your project's dependencies:

```bash
uv add gitinject
uv run gitinject --help
uv run gitinject list workflows
```

The distribution and Python import package are both named `gitinject`. Extensions can import `gitinject.runner`, `gitinject.scenario_base`, and the other modules documented in the [Python API](../api/index.md). You can also invoke the CLI with `uv run python -m gitinject`.

`uv add` installs GitInject into your project environment; a tool installation does not make its Python modules available to your project's scripts. Use `uv run gitinject` for the project-installed CLI. A virtual-environment installation with `python -m pip install gitinject` works as well.

## Install from Git

To install directly from Git:

```bash
uv tool install git+https://github.com/ceferisbarov/GitInject.git
# Or add it to a Python project:
uv add gitinject --git https://github.com/ceferisbarov/GitInject.git
```

## Develop or reproduce from a checkout

Use a checkout and the dependency lockfile for development and paper reproduction:

```bash
git clone https://github.com/ceferisbarov/GitInject.git
cd GitInject
uv sync --locked
uv run gitinject --help
```

Run checkout commands from the repository root, using `uv run gitinject` in place of `gitinject` to use the checkout's code and locked dependencies.

## Experiment workspace

Installed commands can run outside the checkout. The current directory is the experiment workspace: run evidence goes into `runs/`, and reports and scanner memory go into `reports/`. Bundled package assets are read-only inputs.

To provide a custom dataset, create `workflows/` or `scenarios/` in the workspace. Each directory replaces the corresponding bundled catalog. In a checkout, `src/gitinject/workflows/` and `src/gitinject/scenarios/` are also discovered; legacy workspace directories under `src/benchmark/` remain supported. Scanner warm-start notes use `research/scenarios/` in the workspace when present, otherwise the bundled corpus.

## GitHub identities

The owner client uses `GITHUB_TOKEN`, falling back to `gh auth token`. Credentials must permit repository creation, file/workflow updates, Actions configuration, secrets/variables, and deletion. For classic tokens, repository/workflow access and the `delete_repo` scope are relevant; account or organization policies may impose further restrictions.

```bash
gh auth login
gh auth status
```

For token-based experiments, export `GITHUB_TOKEN` in your shell. An optional second account uses `ATTACKER_GITHUB_TOKEN`. Scenarios declaring `required_actors = ("owner", "attacker")` fail before provisioning if that second identity is unavailable. Attacker-fork scenarios need it. [Actors and custom API calls](../guides/research.md) explains the distinction.

Neither the CLI nor the runner automatically loads `.env` or `references/run.sh`. Export variables yourself, or source your private experiment configuration. The paper helper sources `references/run.sh` when present.

## Workflow and model credentials

Configure the provider selected by the workflow, plus the judge used by the scenario. Workflow metadata and YAML may require additional names.

| Use | Environment variables |
| --- | --- |
| Claude workflows; Anthropic scanner models | `ANTHROPIC_API_KEY` |
| Codex workflows; OpenAI judges; AutoInject and offline victim calls | `OPENAI_API_KEY` |
| Gemini workflows | `GEMINI_API_KEY`, `GEMINI_MODEL`, `GEMINI_DEBUG` |
| Default semantic evaluator | `GEMINI_API_KEY` |
| Copilot workflows | `COPILOT_GITHUB_TOKEN` |
| OpenRouter calls through `call_llm` | `OPENROUTER_API_KEY` |
| AWS-backed workflows classified as Amazon Q | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` |
| GitLab experiments | `GITLAB_TOKEN`, plus the workflow's provider credentials |

The current GitHub provider preflight requires all three Gemini variables to be nonempty. Set `GEMINI_MODEL` to your chosen model and, for example, `GEMINI_DEBUG=false`. Claude workflows may also need the Claude GitHub App configured for the test account, depending on the installed action.

`required_secrets` and `required_vars` in workflow metadata are checked before provisioning. Names discovered from `secrets.*` and `vars.*` in workflow YAML are installed when their environment values are available; discovery alone does not make missing names a preflight error. Scenario-provided secrets are also installed. See [workflow metadata](../reference/workflow-metadata.md).

## Optional experiment settings

| Variable | Default / purpose |
| --- | --- |
| `GITHUB_REPO_PREFIX` | Repository prefix for CLI runs; defaults to `benchmark-run`, or `benchmark-scan` for scanning. An `owner/prefix` selects an explicit owner. |
| `GITHUB_MAX_CALLS_PER_MINUTE` | `20`; controls pacing of selected GitHub helper operations. Use a positive number. |
| `ATTACK_ATTACKER_MODEL` | AutoInject generator model; set an OpenAI-endpoint-valid identifier explicitly. |
| `ATTACK_VICTIM_MODEL` | `gpt-4o-mini`; offline victim default and victim name used by AutoInject. |

The [attack guide](../guides/attacks.md#current-model-routing) describes current routing limits. These settings do not impose a global cost budget or concurrency limit.

!!! note "Local credentials and repository credentials"
    The owner's local `GITHUB_TOKEN` is distinct from the automatic `GITHUB_TOKEN` used by a workflow run. Input snapshots, repository variables, scenario artifacts, and logs may contain sensitive experiment data. Secret configuration in the manifest records names rather than values.

## Documentation tools

```bash
uv sync --locked --group docs
uv run --group docs mkdocs serve
```

For a documentation-only environment, use `uv sync --locked --only-group docs` followed by `uv run --no-sync mkdocs serve`. No GitHub or provider credentials are needed to build the site.
