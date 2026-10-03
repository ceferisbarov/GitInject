# Scanner pipeline

The CLI composes extraction, generation, ranking, live validation, diagnostics, memory, baseline tools, and reports. For operational defaults and limitations, see [scan a workflow](../guides/scanner.md).

## Extraction and generation

`extract` reconstructs available workflow prompt context and detects provider, tool restrictions, checkout credential behavior, and a trigger. This is a reconstruction from assets, not a capture of live model traffic.

::: src.benchmark.scanner.prompt_extractor.extract

`generate` creates hypotheses, optionally using cross-workflow memory and a monolithic prompt instead of category-specific generation.

::: src.benchmark.scanner.hypothesis_generator.generate

## Ranking and live validation

`rank` returns ranked hypotheses and discarded `(hypothesis, reason)` pairs. Structural validation always runs; `skip_llm` bypasses the model ranking stage.

::: src.benchmark.scanner.llm_ranker.rank

`validate` writes recipes and executes independent GitHub trials through the ordinary runner. Dry-run candidates are skipped. Confirmation requires all requested trials to count as successes and no invalid trials. Inspect diagnostic evidence and corrections alongside validation status.

::: src.benchmark.scanner.live_validator.validate

## Diagnostics

Diagnostics classify execution/evaluation problems, refusal, ineffective payloads, and evaluator blind spots. `counts_as_success` is a scanner interpretation that can differ from the original metric verdict; retain the diagnostic evidence for review.

::: src.benchmark.scanner.diagnostics
    options:
      members: [DiagnosticResult, classify_run, should_escalate]

## Recipes and validation

Recipe writing returns the definition path; default output is a unique scanner-candidate root under `runs/`. Loading validates the hypothesis. Deletion requires generated ownership and refuses directories with additional files. See the [recipe format](../reference/recipes.md).

::: src.benchmark.scanner.recipe_scenario
    options:
      members: [RecipeScenario, write_recipe, delete_recipe, load_recipe]

::: src.benchmark.scanner.primitives
    options:
      members: [PrimitiveSpec, PRIMITIVES, validate_step, validate_trigger, validate_success_check, validate_setup_trigger_consistency, validate_hypothesis, recipe_fingerprint, primitive_catalog_for_prompt]

## Memory and reporting

`CrossWorkflowMemory` persists reusable recipe examples and can warm-start from research notes. Error results are excluded from learning. Live validation constructs its own memory instance; the CLI's `--no-memory` flag currently covers initial generation seeds only.

::: src.benchmark.scanner.memory.CrossWorkflowMemory
    options:
      members: [__init__, record, get_positive_examples, get_negative_examples, warm_start]

`report_generator.generate` writes Markdown/JSON and returns their paths.

::: src.benchmark.scanner.report_generator.generate

## Optional baselines

These wrappers invoke separately installed binaries and normalize findings. An unavailable executable produces no findings.

::: src.benchmark.scanner.baselines.zizmor_runner.run

::: src.benchmark.scanner.baselines.actionlint_runner.run
