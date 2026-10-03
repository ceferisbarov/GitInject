# Default event triggers

`AbstractScenario.get_event()` returns a dictionary with `event_type` and `data`, plus optional `actor`. The default lifecycle trigger uses these fields. Custom Python triggers can perform other operations through the API and return a `TriggerReceipt`.

| `event_type` | `data` fields | Default action |
| --- | --- | --- |
| `issues` | `title`, `body` | Create an issue. |
| `pull_request`, `pull_request_target` | `title`, `body`, `head`, `base` | Open a PR; YAML determines which GitHub event triggers the workflow. |
| `issue_comment` | `number`, `body` | Comment on the target issue/PR. |
| `pull_request_review` | `number`, `body` | Submit a PR review with event `COMMENT`. |
| `workflow_dispatch` | `workflow`, `inputs` | Dispatch the selected workflow on the default branch. |

For comments/reviews, specify a target number. The legacy fallback chooses the most recently created open PR when no number is given. For PRs, create a changed head branch first; defaulting head to the default branch does not produce a meaningful PR.

`actor="owner"` forces owner event creation; `actor="attacker"` requires a separate attacker client. With no actor, non-PR events use the event client, while a same-repository PR head without `:` uses the owner. An explicit actor or fork-style head permits the event client for PR creation.

`pull_request_review_comment` is present in the event enum but is unsupported by the default trigger because inline review comments need commit/path/line information. `push` is also an enum member without a default trigger implementation. Implement these through a custom `trigger(context)` if needed.

The runner treats `pull_request` and `pull_request_target` as equivalent candidates during run matching. It still checks that the selected installed workflow actually accepts the observed event.

## Trigger receipt

`TriggerReceipt(event_type=None, subject_kind=None, subject_number=None, workflow_run_id=None)` is an immutable record. Subject kind is `"pr"` or `"issue"`; kind and number must be supplied together. GitHub IDs must be positive integers.

The runner copies the subject number to scenario runtime state, saves the receipt as an artifact, and uses event/run ID for final workflow attribution. A supplied run ID cannot bypass trial attribution checks.
