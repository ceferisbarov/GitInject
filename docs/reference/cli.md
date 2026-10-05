# CLI reference

> Use **v0.1.0 for replication of the original paper**. The new GitHub [experiment engine](../guides/experiments.md) uses targets, attack instances, two accounts, and isolated sessions. Original execution commands are under `gitinject legacy`; legacy runners/scanner/GitLab do not meet the new isolation contract.

After [installing the CLI](../getting-started/installation.md#install-the-cli), run commands from your experiment directory:

```bash
gitinject --help
gitinject run --help
```

The options below are generated from the actual Click command definitions at build time. Behavioral details and implementation limits are covered in [running benchmarks](../guides/running-benchmarks.md), [attacks](../guides/attacks.md), [scanner](../guides/scanner.md), and [GitLab](../guides/gitlab.md).

Some commands report an execution error as text/result data without a nonzero shell exit status. Inspect `metadata.json` and its `error`/`evaluation_errors` fields when automating experiments.

For a project installation or source checkout, use `uv run gitinject` in place of `gitinject` to select that environment's version.

::: mkdocs-click
    :module: gitinject.cli
    :command: cli
    :prog_name: gitinject
    :depth: 1
