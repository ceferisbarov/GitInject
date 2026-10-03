# Workflows, scenarios, and attacks

## Workflow

A workflow is the agent configuration being tested: action references, permissions, triggers, prompts, tools, and credentials. It lives in `src/benchmark/workflows/<id>/`, with `metadata.json` and repository assets under `contents/`.

For GitHub, the workflow YAML belongs under `contents/.github/workflows/`. Other assets, such as instructions or scripts, are copied to their corresponding repository paths. GitLab workflows use `contents/.gitlab-ci.yml`.

Metadata supplies the provider, category, labels, supported events, and optional evidence attribution settings. It is descriptive configuration; the workflow YAML determines what actually executes. See [add a workflow](../guides/workflows.md).

## Scenario

A scenario defines the input task, repository setup, trigger, observation, and evaluation. Benign scenarios measure legitimate tasks; malicious scenarios specify an attack objective. Both can evaluate utility and security.

Python is the general authoring interface. A scenario directory contains exactly one `scenario.py` and optional `contents/` fixtures. The module defines one concrete `AbstractScenario` subclass. Scanner recipes use `recipe.json` as a convenience frontend to the same GitHub run engine. A directory cannot contain both definitions.

Scenario IDs are directory names and must be unique across discovery. A run also accepts a local scenario directory or definition file path. Category and event declarations make scenarios available to suite planning.

## Attack strategy

An attack strategy supplies a payload for a scenario's declared injection slots. It does not replace the scenario's setup or evaluator. `static` returns a supplied string or file; `autoinject` generates payloads and learns from scored trials.

Without `--attack`, the runner uses the payload already defined by the scenario. With an attack strategy, the scenario must supply a non-null attack goal and at least one template containing `{{INJECTION}}`.

## Compatibility and scope

Categories and labels help select experiments. `run --scenario all` matches category, supported event, and platform. `run-suite` currently matches category and event and executes through the GitHub runner; use `run` for GitLab pairs. An explicit single run does not perform suite compatibility filtering, so choose a workflow that handles the scenario's event.

GitInject's live executions expose real permissions and integration behavior. They also depend on account settings, action revisions, model availability, and service behavior; saved local inputs cannot freeze those external dependencies.
