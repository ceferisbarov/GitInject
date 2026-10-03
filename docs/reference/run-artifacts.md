# Run artifacts

This contract applies to GitHub `BenchmarkRunner.run()` attempts. Scanner candidates use it for their live trials. GitLab and offline optimization have separate, smaller record formats.

```text
runs/<attempt_id>/
├── manifest.json
├── events.jsonl
├── inputs/
│   ├── scenario/
│   ├── workflow/
│   └── dependencies/uv.lock
├── artifacts/
│   ├── trigger_receipt.json
│   ├── evidence.json
│   └── rendered_attack.json       # when an attack strategy is used
├── context_snapshot.json
├── llm_input.txt                  # with prompt logging
├── metadata.json
├── stdout.log
└── stderr.log
```

Files for later phases may be absent when execution fails early.

## Manifest, schema version 1

| Field | Content |
| --- | --- |
| `schema_version` | Currently `1`. |
| `attempt_id`, `timestamp` | UUID hex identifier and UTC creation time. |
| `spec` | Workflow/scenario identifiers, parameters, seed, parent attempt, attack, cleanup, unaligned mode. |
| `inputs` | Saved input paths grouped by label with SHA-256 hashes. |
| `source_revision`, `source_dirty` | Local Git revision and dirty state when available. |
| `actors` | Role-to-authenticated-login mapping from preflight. |
| `configuration` | Secret names, variable values, substitutions, required actors, template, branch, workflow metadata, security evaluator source. |

The runner loads/provisions saved scenario and workflow inputs, rather than continuing to use their original directories. The manifest does not serialize secret configuration values or the Python implementation of a caller-provided evaluator.

## Journal

Each line in `events.jsonl` contains a UTC `timestamp`, a `kind`, and kind-specific fields. Events are appended and flushed durably.

| Kind | Selected fields |
| --- | --- |
| `phase` | `phase`: created, loading, preflight, provisioning, preparing, triggering, waiting, observing, evaluating, cleaning, completed, failed, interrupted. |
| `resource` | Actor, repository name, immutable `id`, state (`created` or `deleted`). |
| `api_request` | Actor, local request ID, uppercase method, URL path. |
| `api_response` | Actor, local request ID, HTTP status, GitHub request ID where available. |
| `artifact` | Relative path and SHA-256 hash of saved JSON. |
| `iteration` | Search iteration, score, child attempt ID, workflow run ID, error. |

Raw API journaling excludes authorization headers, bodies, and query parameters. It covers `GitHubClient.request` and GraphQL calls through that method, not all SDK or CLI helper operations.

## Result metadata

Core fields include `workflow`, `scenario`, `repo`, `timestamp`, `attempt_id`, `runs_dir`, and `run_result`. A successful observation/evaluation additionally supplies `run_id`, `analysis`, `gh_state`, `billable_minutes`, and `evidence_boundary`.

`run_result` includes workflow status/conclusion, logs, exit code, `agent_invoked`, and job/step evidence. `analysis` has tri-state metric values, independent evaluation errors, and judge details where available. Execution failures set top-level `error`; cleanup failures append `cleanup_errors` without replacing measured outcomes.

See [metrics and evidence](../concepts/evaluation.md) for verdict rules and [inspect and reproduce runs](../guides/results.md) for a reading workflow.
