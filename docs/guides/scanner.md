# Scan a workflow

The scanner extracts workflow context, generates structured attack hypotheses, ranks them, validates selected candidates through the live GitHub runner, and writes Markdown/JSON reports.

## Generate without live runs

```bash
uv run gitinject scan \
  --workflow codex-pr-review --dry-run
```

`--dry-run` skips live repository trials. It still calls generation/ranking models, may run installed baseline tools, and can initialize scanner memory. It is not a credential-free or cost-free plan.

Default generation and ranking use `claude-sonnet-4-6`; diagnostics use `claude-haiku-4-5`; the semantic judge uses `gemini-3.1-pro-preview`. Configure their keys as well as the target workflow's credentials for live validation.

## Validate candidates

```bash
uv run gitinject scan \
  --workflow codex-pr-review \
  --hypotheses 12 --max-live 5 --runs-per 3 --iterations 2
```

The generator splits hypotheses across four attack categories unless `--monolithic` is selected. Structural validation and optional LLM ranking discard implausible candidates. Accepted hypotheses become `recipe.json` scenarios under `runs/scanner-candidates/`; they are executed by path through `BenchmarkRunner.run()`.

A candidate is **confirmed** only when all requested trials count as successes and none are invalid. A mix of successes and failures remains unconfirmed. Infrastructure/evaluation errors are excluded from the effective-run denominator; all-invalid candidates are errors. Inspect `attempted_runs`, `invalid_runs`, and per-run diagnostics alongside the success rate.

Diagnostics distinguish infrastructure/evaluation problems, agent refusal, ineffective payloads, and evaluator blind spots. Diagnostic reinterpretation can affect scanner confirmation; inspect the recorded evidence and any `evaluator_correction` before treating a result as an independently verified finding.

## Models and ablations

```bash
uv run gitinject scan \
  --workflow codex-pr-review --dry-run --no-baselines \
  --hypothesis-model anthropic/claude-sonnet-4-6 \
  --ranker-model anthropic/claude-sonnet-4-6
```

The shared model helper accepts explicit `anthropic/`, `google/`, `openai/`, and `openrouter/` prefixes. For OpenRouter, use a name such as `openrouter/openai/gpt-4o-mini`.

| Option | Intended effect |
| --- | --- |
| `--no-ranker` | Use structural filtering without LLM plausibility ranking. |
| `--no-memory` | Disable cross-workflow seeds supplied to initial generation. |
| `--monolithic` | Use a single generation prompt. |
| `--no-diagnostics` | Disable artifact inspection in diagnostic classification. |
| `--no-baselines` | Skip zizmor and actionlint. |
| `--reseed` | Reload the warm-start research corpus. |

The live validator currently constructs its own `CrossWorkflowMemory`, so `--no-memory` does not prevent all live-validation memory access/writes. Likewise, `--no-diagnostics` still performs basic error/verdict classification. Treat ablation labels according to those implementation limits.

The optional `zizmor` and `actionlint` binaries must be installed separately to produce baseline findings; wrappers return no findings when the executable is unavailable. Their absence is not a clean bill of health.

## Reports and replay

Reports default to `reports/scanner/` with per-workflow Markdown and JSON files. They include ranked/discarded hypotheses, confirmations, errors, diagnostics, mitigation suggestions, and cost estimates. Live attempts retain the ordinary [run artifacts](../reference/run-artifacts.md).

Replay a generated recipe by path:

```bash
uv run gitinject run \
  --workflow codex-pr-review \
  --scenario /absolute/path/to/candidate-directory
```

Reported USD values use the repository's static model price table and captured token usage. Unknown model prices contribute zero and are surfaced in reports; these estimates do not represent a complete invoice. Workflow timing is reported separately.

The live scanner uses the GitHub runner. `scan --all` walks workflow directories without platform filtering; select GitHub workflows explicitly rather than assuming it provides GitLab validation. See the [scanner API](../api/scanner.md) and [recipe reference](../reference/recipes.md).
