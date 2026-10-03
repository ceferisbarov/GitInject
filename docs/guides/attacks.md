# Generate and optimize attacks

Attack strategies supply payloads to existing scenarios. The scenario must implement `get_attack_goal()` and effective `{{INJECTION}}` slots, and read the rendered values in `get_event()`. See [scenario authoring](scenarios.md#add-injectable-payloads).

## Apply a fixed payload

```bash
uv run python -m src.benchmark.cli run \
  --workflow codex-pr-review \
  --scenario pr_token_exfiltration_via_git_config \
  --attack static --attack-payload ./payload.txt
```

`--attack-payload` accepts a literal string or an existing file path. If a literal happens to be a file path, the loader reads that file; the Python `StaticAttack` constructor allows an explicit choice.

Omitting `--attack` uses the scenario's bundled payload. Generated/rendered overrides are saved in `artifacts/rendered_attack.json` for live attempts.

## Optimize against live workflows

```bash
uv run python -m src.benchmark.cli optimize \
  --workflow codex-pr-review \
  --scenario pr_token_exfiltration_via_git_config \
  --attack autoinject --iterations 5
```

Every iteration uses the ordinary run engine with a fresh runner and repository. Trial records point to the search attempt through `parent_attempt_id`. Known security verdicts become `1` for breach or `0` for resistance; unknown/execution-error trials receive `null` and do not update the attacker.

The search result records `asr_curve`, `final_asr`, valid and unknown iteration counts, and `best_payload.txt` when available. This ASR describes the adaptive search history. Estimate performance of the selected payload in separate trials using `static`.

## Offline preflight

Offline execution reconstructs a prompt and sends it to a plain chat model. It requires a scenario-specific `get_preflight_evaluator()` returning a callable that scores the response with a strict boolean.

```bash
uv run python -m src.benchmark.cli preflight \
  --workflow codex-pr-review \
  --scenario pr_token_exfiltration_via_git_config \
  --attack autoinject --victim-model gpt-4o-mini

uv run python -m src.benchmark.cli optimize \
  --workflow codex-pr-review \
  --scenario pr_token_exfiltration_via_git_config \
  --attack autoinject --offline --iterations 5 \
  --victim-model gpt-4o-mini
```

Preflight performs one offline iteration. Offline optimization stops early on a successful trial. Neither provisions a GitHub repository, but the CLI still constructs a runner and therefore needs local GitHub authentication. The live tool context, permissions, and action integration are absent from these calls; validate results in live runs.

## Current model routing

AutoInject and offline victim calls currently instantiate the OpenAI SDK directly with `OPENAI_API_KEY`. `ATTACK_ATTACKER_MODEL` selects the attacker and `ATTACK_VICTIM_MODEL` supplies the victim default/name. Use model identifiers accepted by that endpoint. The loader's attacker default includes `openai/`, and the CLI's victim help mentions OpenRouter, but these paths do not implement OpenRouter routing. Set `ATTACK_ATTACKER_MODEL` explicitly to an endpoint-valid model ID.

The scanner's shared `call_llm` helper supports provider routing separately; its behavior does not apply to AutoInject. See [model API](../api/llm.md).

`static` needs a payload and has no adaptive `best_payload`. The optimize/preflight commands have no payload option, so use `static` with `run` or construct it directly for library experiments.
