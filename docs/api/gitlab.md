# GitLab

These interfaces operate on GitLab projects and merge requests. They do not implement the GitHub `RunContext`, artifact attribution, or journal contract. Read the [GitLab guide](../guides/gitlab.md) before sharing measurement assumptions across runners.

`GitLabRunner.run()` creates a project, provisions assets/variables, calls legacy scenario setup, creates an MR, waits for its pipeline, evaluates directly, saves results, and tears down when requested. Its public arguments are workflow, scenario, and cleanup.

::: src.benchmark.gl_runner.GitLabRunner
    options:
      members: [__init__, run]

`GitLabClient` requires a token argument or `GITLAB_TOKEN`; the URL defaults to `https://gitlab.com`. Its project is bound after creation. MR notes are plain strings rather than the GitHub structured artifact representation.

::: src.benchmark.utils.gl_client.GitLabClient
    options:
      members: [__init__, create_project, delete_project, push_files, create_branch, create_merge_request, get_mr_notes, get_mr_pipelines, wait_for_pipeline, set_variable, get_project_url, get_default_branch]

::: src.benchmark.utils.gl_provisioner.GitLabProvisioner
    options:
      members: [__init__, provision, teardown]
