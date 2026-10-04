# Inspect and reproduce runs

GitHub attempts live in `runs/<attempt_id>/`. The runner creates this directory before preflight, so failures can still have a manifest and journal. Local records remain after repository cleanup.

## Read outcomes before summaries

Start with `metadata.json`. An `error` at the top level is an execution failure. A completed attempt can still have unknown metrics, per-metric `evaluation_errors`, log/timing errors, or `cleanup_errors`. These fields describe different problems and should be examined separately.

```bash
uv run gitinject report
uv run gitinject report --aggregate
```

The table's `Sec` column inverts `security_breached`: `T` means resistance, `F` means breach, and `?` means unknown. Aggregate summaries group by workflow across scenarios and use known-verdict denominators. Compare the scenario mix and attempt counts before comparing rates.

## Trace the attempt

| File | Use |
| --- | --- |
| `manifest.json` | Parameters, seed, lineage, source revision, input hashes, identities, effective configuration. |
| `events.jsonl` | Phase sequence, raw API metadata, repository ownership/deletion, artifact hashes. |
| `inputs/` | Saved scenario, workflow assets, and dependency lockfile. |
| `artifacts/trigger_receipt.json` | Trigger event, subject, and optional workflow run ID. |
| `artifacts/evidence.json` | Evidence returned by the observation hook. |
| `metadata.json` | Full attempt result and analysis. |
| `context_snapshot.json` | Diagnostic snapshot of prepared input state. |
| `stdout.log`, `stderr.log` | Workflow logs, when collected. |

Optional artifacts include `rendered_attack.json`, `llm_input.txt`, and scenario-defined JSON files. See [run artifacts](../reference/run-artifacts.md) for fields and phases.

## Reproduce inputs

1. Check the recorded `source_revision`, `source_dirty`, parameters, and seed.
2. Restore the workflow assets from `inputs/workflow/` to a local workflow directory; the runner accepts workflow IDs rather than arbitrary workflow paths.
3. Use the saved scenario directory under `inputs/scenario/` as the scenario path.
4. Restore credential names and non-secret configuration in your own environment.
5. Run a fresh trial and compare attributed evidence and evaluator outcomes.

For generated attacks, a rendered payload is part of the reproduction input. Reapply the saved payload using `static` or the scenario's parameter interface instead of generating a new one.

The manifest identifies copied inputs with SHA-256 hashes; its lockfile snapshot helps reconstruct local dependencies. This does not replay the remote workflow automatically. External action code, mutable action tags, model/service versions, permissions, and code imported outside the copied inputs can change outcomes.

## Recover cleanup manually

Read resource entries in `events.jsonl` and `cleanup_errors` to find repositories whose deletion failed. Verify the account, full name, and immutable ID against the live resource before deleting it. Bulk cleanup uses prefixes rather than journal ownership and may not cover every custom resource.

Interrupted runs preserve local results when the runner's finalization executes. Abrupt process termination can leave resources behind. Automatic reconciliation and resume are not implemented.

## Optimization records

Live search records have a parent attempt and iteration entries linking independent child trials. Offline directories use `offline-<timestamp>-<suffix>/` with `attack_history.jsonl`, `metadata.json`, and optionally `best_payload.txt`; they do not have the full GitHub attempt manifest/journal contract.
