# Runner and analyzer

`BenchmarkRunner` resolves local credentials during construction; GitHub identity reads begin in the recorded preflight. Inject `gh_client` and `event_gh_client` for controlled clients. Construction assigns a repository name; use a fresh runner for each independent experiment.

## Run arguments

| Argument | Meaning |
| --- | --- |
| `workflow_id` | Directory ID under `src/benchmark/workflows/`. |
| `scenario_id` | Dataset ID, local scenario directory, or definition file path. |
| `attack_id`, `attack_payload` | Named strategy and optional static input. |
| `attack` | An explicit `AbstractAttack`; takes precedence over strategy construction. |
| `cleanup` | Run cleanup and repository deletion; defaults to true. |
| `log_llm_input` | Print/save a reconstructed diagnostic prompt. |
| `parameters` | JSON-serializable object supplied to `RunContext`. |
| `seed` | Optional integer seed for `context.rng`. |
| `parent_attempt_id` | Recorded experiment lineage. |
| `security_evaluator` | Replace the scenario's security evaluator with a caller check. |

`run()` returns result metadata, including `attempt_id` and `runs_dir`. Ordinary execution exceptions become a top-level `error`; evaluator errors become per-metric unknown values. Keyboard interrupts/system exits are recorded and re-raised. Cleanup failures are retained independently. See the [artifact contract](../reference/run-artifacts.md).

`optimize()` performs independent live trials linked to a search record. `offline_optimize()` calls a plain OpenAI chat victim and uses a scenario preflight check. Read [attack optimization](../guides/attacks.md) before interpreting either ASR.

::: src.benchmark.runner.BenchmarkRunner
    options:
      members: [__init__, run, optimize, offline_optimize]

`BenchmarkAnalyzer.analyze()` runs utility/security evaluators independently, enforcing strict boolean and verified invocation rules. Its dictionary contains tri-state verdicts, `evaluation_errors`, and `details` with available judge results. See [metrics and evidence](../concepts/evaluation.md).

::: src.benchmark.analyzer.BenchmarkAnalyzer
    options:
      members: [__init__, analyze]
