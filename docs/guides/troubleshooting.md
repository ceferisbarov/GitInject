# Troubleshooting

## Missing authentication

The owner client requires `GITHUB_TOKEN` or a successful `gh auth token`. Verify your local account with `gh auth status`. Scenarios requiring an attacker also need `ATTACKER_GITHUB_TOKEN`; that identity is never substituted with the owner when requested through `RunContext`.

Listing and suite dry-runs do not need authenticated runners. Offline preflight currently constructs one, so it still needs local GitHub authentication even though it creates no repository.

## Missing workflow credentials

Check the error against the workflow provider, `required_secrets`, `required_vars`, and scenario-required secrets. Gemini provider preflight requires nonempty `GEMINI_API_KEY`, `GEMINI_MODEL`, and `GEMINI_DEBUG`. A semantic evaluator may need a judge credential even if the target agent uses another provider.

The runner does not load `.env` automatically. Export variables into the process environment.

## No compatible pairs

Compare category and event from `list scenarios` with workflow metadata from `list workflows`. Label filters match any exact label in each comma-separated list. The scenario's `get_event()` must return its expected event without needing live runtime state during discovery.

## No workflow run or ambiguous attribution

Inspect the trigger receipt and GitHub Actions UI. Common causes include a workflow that does not accept the event, fork approval requirements, failing preflight conditions, or a PR with no changes. A setup operation may produce a separate run; final observation requires a uniquely matching run after the trial boundary.

For custom triggers, return the correct event and optionally a known workflow run ID. The supplied ID must still satisfy attribution checks.

## Utility or security is unknown

Read `analysis.evaluation_errors`. An unconfigured evaluator, missing observation, judge/API failure, unverified invocation, or unexpected output account can produce `null`. Add exact `agent_steps` names for wrappers and `agent_logins` for additional agent accounts. Verify the step actually ran before interpreting a negative verdict as resistance.

Raw logs and attacker-authored comments do not satisfy attributed response checks. Token-shaped output without the expected token is insufficient to verify checkout token exfiltration.

## Fork or provisioning failure

Check repository creation permissions, Actions settings, workflow file access, and secrets configuration. Template forks may collide with an existing fork in the account's fork network. Overlapping scenario/workflow asset paths are rejected explicitly.

Provisioning raises on incomplete setup and retains ownership for cleanup. Inspect `cleanup_errors` and resource journal entries for failed deletion.

## Offline model errors

AutoInject and offline victim requests currently call OpenAI directly. Set endpoint-valid `ATTACK_ATTACKER_MODEL` and `--victim-model` values; OpenRouter-style names in CLI help do not enable routing. The selected scenario must provide injection slots and an offline evaluator.

## Documentation build errors

Run the strict build from the repository root:

```bash
uv sync --locked --only-group docs
uv run --no-sync mkdocs build --strict
```

The build uses static Python API extraction and AST-based catalogs, plus Click command metadata. It does not instantiate runners or load scenario modules. A missing page, symbol, or internal link should be fixed before publishing. See [documentation development](../development/documentation.md).
