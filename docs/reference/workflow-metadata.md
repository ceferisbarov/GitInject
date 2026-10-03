# Workflow metadata

The runner reads `src/benchmark/workflows/<id>/metadata.json` as a JSON object. There is no separate schema validator; fields have meaning in selection, preflight, provisioning, or attribution.

| Field | Type / default | Effect |
| --- | --- | --- |
| `name` | string | Display name. |
| `description` | string | Human-readable purpose. |
| `category` | string | Matches scenario category in suite planning. |
| `provider` | string | Selects provider credential preflight. |
| `platform` | string, `github` | Selects GitHub/GitLab for CLI `run`. |
| `defense_level` | string | Descriptive baseline/hardened/sandboxed label. |
| `labels` | string array, `[]` | Filters workflow selection. |
| `supported_events` | string array, `[]` | Events accepted for suite planning. |
| `required_secrets` | string array, `[]` | Required nonempty environment names for repository secrets. |
| `required_vars` | string array, `[]` | Required nonempty environment names for repository variables. |
| `agent_steps` | string array, `[]` | Exact job step names used to verify invocation. |
| `agent_logins` | string array | Allowed output accounts; replaces defaults when supplied. |
| `adversarial_swaps` | object, `{}` | Action substitution overrides for unaligned runs. |
| `source` | string | Provenance URL for the workflow definition. |

Category, provider, and defense-level enums are listed in the [types API](../api/types.md). Metadata does not rewrite a workflow's actual trigger, permissions, or prompt. Keep `supported_events` consistent with YAML.

## Configuration precedence

The GitHub runner validates provider credentials and metadata's required names unless unaligned mode is enabled. It then collects available environment values referenced by YAML `secrets.*` and `vars.*`. Scenario-defined secrets override collected secrets; scenario-required environment secrets are applied afterward.

Repository variable values are saved in the manifest's effective configuration. Secret configuration saves names. Snapshotted YAML, scenario code, fixtures, custom artifacts, and logs are retained verbatim, so do not embed private credential values in those inputs.

## Agent attribution defaults

Recognized actions are `openai/codex-action`, `anthropics/claude-code-action`, and `google-github-actions/run-gemini-cli`. Their step names are detected from the installed YAML. Wrapper agents require explicit `agent_steps`.

Default logins are `github-actions[bot]`, `claude[bot]`, and `gemini-code-assist[bot]`. Additional output identities require explicit configuration; fresh unconfigured bot output raises an evidence error.
