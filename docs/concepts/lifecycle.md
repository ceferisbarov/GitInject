# Execution lifecycle

The GitHub runner assigns each attempt a UUID and creates its record before loading scenario inputs. The journal stores durable phase transitions.

```text
created → loading → preflight → provisioning → preparing
        → triggering → waiting → observing → evaluating
        → cleaning → completed / failed / interrupted
```

`cleaning` is omitted with `cleanup=False`. Partial attempts retain the phases they reached.

| Phase | Behavior |
| --- | --- |
| Loading | Copy scenario and workflow assets plus `uv.lock`; load the saved scenario definition. |
| Preflight | Check required actors, resolve authenticated logins, configure workflow attribution, and validate credentials. |
| Provisioning | Create or fork a repository; configure Actions, issues, secrets, and variables; install assets. |
| Preparing | Call `scenario.prepare(context)`; save the input context snapshot. |
| Triggering | Establish the trial boundary, then call `scenario.trigger(context)` and save its receipt. |
| Waiting | Select a uniquely attributable workflow run and wait for completion. |
| Observing | Fetch logs and job evidence; call `scenario.observe(context, run_result)` and save evidence. |
| Evaluating | Evaluate utility and security independently; derive autonomy from agent step evidence. |
| Cleaning | Call scenario cleanup, provisioner teardown, and cleanup of registered repositories. |
| Terminal phase | Save results and record completion, execution failure, or interruption. |

## Scenario hooks

The default hooks adapt existing scenarios:

| Hook | Default |
| --- | --- |
| `prepare(context)` | `setup_state(context.github("owner"))` |
| `trigger(context)` | `context.default_trigger()` using `get_event()` |
| `observe(context, run_result)` | `context.collect_target()` for the recorded issue or PR |
| `cleanup(context)` | `teardown_state(context.github("owner"))` |

Custom Python scenarios can override any hook. Put operations intended to invoke the victim in `trigger`, after the framework establishes the trial boundary. Setup can itself cause workflow activity; such runs are excluded from the final trial's attribution.

## Ownership and cleanup

The provisioner owns only repositories it creates or forks. The client records their immutable IDs immediately after creation. Cleanup verifies repository identity before deletion and preserves errors in `cleanup_errors`.

For a repository created through a custom raw API call, register it immediately with `context.track_repository(actor, full_name, repository_id)`. Repository existence alone does not establish ownership. Custom cleanup should tolerate partially completed preparation, because it is called after preparation has started even if that hook fails.

`--no-cleanup` skips scenario cleanup and repository teardown. It is useful for inspecting a run, but leaves the resources active. Local records support manual inspection and reproduction; automatic resume, reconciliation, queues, and concurrency scheduling are not implemented.
