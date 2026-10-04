# Add a workflow

Create `workflows/<id>/` in your experiment directory, or `src/gitinject/workflows/<id>/` when contributing to a source checkout:

```text
my-reviewer/
├── metadata.json
└── contents/
    └── .github/
        └── workflows/
            └── review.yml
```

Other repository assets may also live under `contents/`. The provisioner installs them on the default branch and removes existing workflow definitions from a template fork before syncing the selected workflow.

A workspace `workflows/` directory replaces the bundled workflow catalog. Include each workflow you want to use in that directory; see [experiment workspaces](../getting-started/installation.md#experiment-workspace).

## Define metadata

```json
{
  "name": "My reviewer",
  "description": "Reviews pull requests with the target agent.",
  "category": "code-review",
  "provider": "openai-codex",
  "platform": "github",
  "defense_level": "baseline",
  "labels": ["pr", "review", "experimental"],
  "supported_events": ["pull_request"],
  "required_secrets": ["OPENAI_API_KEY"],
  "agent_steps": ["Review pull request"],
  "agent_logins": ["github-actions[bot]"]
}
```

Use the actual provider, event, step names, and output accounts of your workflow. See the [metadata reference](../reference/workflow-metadata.md) and [type enums](../api/types.md) for the contract.

## Install the real workflow

Keep the target action's documented YAML in `contents/.github/workflows/review.yml`. Configure the required permissions, checkout behavior, provider secrets, and prompts for your experiment. The runner reads actual YAML triggers for workflow attribution; metadata's `supported_events` controls suite planning.

Known Codex, Claude, and Gemini actions are recognized as agent steps automatically. If an agent executes through a shell script, wrapper, or another action, add its exact YAML step name to `agent_steps`.

Specify `agent_logins` for output accounts beyond the defaults. The field replaces the default list, so include every account expected to produce agent evidence. Human owner and attacker inputs are excluded regardless.

## Verify discovery and pairing

```bash
gitinject list workflows
gitinject run-suite \
  --workflow-labels experimental --dry-run
```

Then execute one suitable scenario after configuring credentials. Inspect job evidence to verify the agent step was detected and inspect attributed comments to confirm output accounts.

The provisioner also accepts legacy root-level YAML when `contents/` is absent, but new workflows should use the directory layout above.
