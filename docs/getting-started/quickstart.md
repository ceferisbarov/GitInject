# First benchmark

> Use **v0.1.0 for replication of the original paper**. The new GitHub [experiment engine](../guides/experiments.md) uses targets, attack instances, two accounts, and isolated sessions. Original execution commands are under `gitinject legacy`; legacy runners/scanner/GitLab do not meet the new isolation contract.

Complete [installation and configuration](installation.md), then discover the dataset:

```bash
gitinject list workflows
gitinject list scenarios
```

Listing workflows and planning suites do not construct authenticated runners. Listing scenarios imports their Python definitions, so use trusted scenario code.

## Plan a compatible suite

```bash
gitinject run-suite \
  --workflow-labels codex --scenario-type benign --dry-run
```

Suite compatibility matches the workflow's category and supported events against the scenario. This command lists pairs without provisioning repositories or calling models.

## Run one benign scenario

The bundled `vulnerable_code_review` scenario works with `codex-pr-review`. Export `OPENAI_API_KEY` for Codex and `GEMINI_API_KEY` for the scenario's semantic judge before running:

```bash
gitinject run \
  --workflow codex-pr-review \
  --scenario vulnerable_code_review
```

The runner creates a repository, installs workflow and fixture files, prepares a review branch, opens a pull request, waits for the matching workflow, collects evidence, evaluates it, and attempts cleanup. The default repository prefix is `benchmark-run`.

For inspection, add `--no-cleanup`. The repository then remains active; the local attempt record is retained either way.

## Read the result

The CLI prints `Utility Achieved`, `Security Breached`, and `Autonomy Achieved`. Each can be `true`, `false`, or unknown. **`Security Breached: true` means the attack succeeded.** A successful workflow conclusion alone does not establish any task or security verdict.

Inspect `runs/<attempt_id>/metadata.json` for the result, `artifacts/evidence.json` for observed state, and `events.jsonl` for phases. See [inspect and reproduce runs](../guides/results.md) for details.

```bash
gitinject report
gitinject report --aggregate
```

Next, [run a suite or a bundled attack](../guides/running-benchmarks.md), or [write your own scenario](../guides/scenarios.md).
