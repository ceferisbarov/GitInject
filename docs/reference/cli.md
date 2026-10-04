# CLI reference

Run every command from the repository root:

```bash
uv run gitinject --help
uv run gitinject run --help
```

The options below are generated from the actual Click command definitions at build time. Behavioral details and implementation limits are covered in [running benchmarks](../guides/running-benchmarks.md), [attacks](../guides/attacks.md), [scanner](../guides/scanner.md), and [GitLab](../guides/gitlab.md).

Some commands report an execution error as text/result data without a nonzero shell exit status. Inspect `metadata.json` and its `error`/`evaluation_errors` fields when automating experiments.

::: mkdocs-click
    :module: gitinject.cli
    :command: cli
    :prog_name: uv run gitinject
    :depth: 1
