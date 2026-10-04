# Runtime context and records

`RunSpec` captures requested experiment inputs. Parameters must be an object and a supplied seed must be an integer. The runner makes a JSON copy of parameters before creating the record.

::: gitinject.run_record.RunSpec

`TriggerReceipt` binds a custom trigger to its final event and optional issue/PR/run. Subject kind and number must be provided together; IDs must be positive integers.

::: gitinject.run_context.TriggerReceipt

`RunContext` supplies the recorded spec, mutable scenario state, explicit actor clients, default trigger/collector callbacks, and seeded `rng`. `github(actor)` raises if the identity is absent. `save_artifact` writes JSON inside the attempt. `track_repository` registers immutable ownership immediately after a custom creation; `cleanup_repositories` returns deletion error strings while retaining failed resources for inspection.

::: gitinject.run_context.RunContext
    options:
      members: [parameters, github, save_artifact, track_repository, cleanup_repositories]

`RunRecord` creates a UUID attempt directory and manifest, snapshots input bytes with SHA-256 hashes, appends durable journal events, and saves JSON artifacts with hashes. `artifact` rejects paths escaping the attempt. It is a local record, not a resume/reconciliation engine.

::: gitinject.run_record.RunRecord
    options:
      members: [__init__, save_manifest, event, snapshot, artifact]

`write_json` uses a temporary sibling file, flushes it, and replaces the destination. Values must be JSON serializable; non-finite numbers are rejected.

::: gitinject.run_record.write_json
