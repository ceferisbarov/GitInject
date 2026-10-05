# GitLab

> Use **v0.1.0 for replication of the original paper**. The new GitHub [experiment engine](experiments.md) uses targets, attack instances, two accounts, and isolated sessions. Original execution commands are under `gitinject legacy`; legacy runners/scanner/GitLab do not meet the new isolation contract.

GitInject includes `GitLabRunner`, `GitLabClient`, and `GitLabProvisioner`. The CLI selects the GitLab runner for `run` when workflow metadata contains `"platform": "gitlab"`.

The bundled workflow is `claude-gitlab-mr-review`. It installs `contents/.gitlab-ci.yml` and declares `ANTHROPIC_API_KEY` and `GITLAB_TOKEN` as required credentials. The current client defaults to `https://gitlab.com`.

## Write a GitLab scenario

Declare `platform = "gitlab"`, set the category, and return merge request data:

```python
def get_event(self):
    return {
        "event_type": "merge_request_event",
        "data": {
            "source_branch": "research-probe",
            "target_branch": "main",
            "title": "Research MR",
            "description": "Please review this change.",
        },
    }
```

Use `self.branch` and fixtures or `setup_state(gl_client)` to create the source branch and changes. Evaluators receive `GitLabClient`, so use its MR/project interfaces rather than GitHub helpers. The shipped scenario catalog currently contains GitHub scenarios; author a compatible GitLab scenario before attempting an MR run.

```bash
gitinject run \
  --workflow claude-gitlab-mr-review \
  --scenario /absolute/path/to/gitlab-scenario
```

## Current differences

GitLab shares scenario discovery/loading, but it calls `setup_state`, `get_event`, evaluators, and `teardown_state` directly. It does not use the GitHub `RunContext` lifecycle, UUID attempt snapshots, raw API journal, actor boundary, or attributed comment helpers.

Its `autonomy_achieved` is based on pipeline success, not verified agent steps. It evaluates utility/security directly rather than using the GitHub analyzer's independent unknown-verdict handling. Results are saved in timestamp directories after successful evaluation; failures are not guaranteed to have the same durable record as GitHub attempts.

The CLI's GitLab path forwards `cleanup`, but not attack generation, context parameters, seed, or prompt logging. Use `run` for GitLab; `run-suite` and live scanner validation currently execute via the GitHub runner. See the [GitLab API](../api/gitlab.md) for available operations.
