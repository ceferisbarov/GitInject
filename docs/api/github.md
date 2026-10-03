# GitHub and provisioning

`GitHubClient` exposes authenticated REST/GraphQL, the PyGitHub client (`gh`), the bound `repository`, and higher-level helpers. Many mutation helpers return `(success, error)` and must be checked by callers. Raw `request()` returns a `requests.Response` and raises on HTTP errors.

`request` enforces the authenticated API host, rejects authorization overrides, defaults to a 60-second timeout and disabled redirects, and journals metadata when a recorder is attached. Mutations are not automatically retried. `graphql` raises on GraphQL errors; call the raw endpoint to inspect partial responses.

Framework ownership is recorded immediately after create/fork. `delete_owned_repo` checks immutable ownership; `delete_repo` is the general explicit deletion operation used by bulk cleanup. `get_pr_details` and `get_issue_details` return structured artifacts for evidence filtering.

::: src.benchmark.utils.gh_client.GitHubClient
    options:
      members: [__init__, request, graphql, get_authenticated_user_login, repository, get_repo_info, get_default_branch, create_repo, fork_repo, wait_until_ready, delete_owned_repo, delete_repo, get_branch_info, create_branch, get_file_sha, put_file, delete_file, get_pr_details, get_issue_details, list_files, set_secret, set_variable, enable_actions, set_fork_pr_approval_policy, enable_issues, list_repos, get_workflow_runs, batch_sync, run_gh]

## Provisioning

`RepoProvisioner.provision()` creates a fresh public repository or template fork, installs workflow and scenario files, and configures Actions/issues/secrets/variables. It raises `ProvisioningError` on incomplete setup or conflicting paths. `teardown()` deletes only a repository owned by this provisioner and retains ownership on failure.

::: src.benchmark.utils.provisioner.ProvisioningError

::: src.benchmark.utils.provisioner.RepoProvisioner
    options:
      members: [__init__, provision, teardown]

## Attacker forks

These helpers support legacy scenarios using attacker forks. Setup requires `ATTACKER_GITHUB_TOKEN`, creates an independently owned fork, and installs scenario fixture files on `scenario.branch`. The fork client is attached to the scenario before later setup operations so teardown can clean up partial setup. Fixtures must be local file paths. The scenario must call the teardown helper from its cleanup hook.

::: src.benchmark.utils.scenario_resources
    options:
      members: [setup_attacker_fork, teardown_attacker_fork]
