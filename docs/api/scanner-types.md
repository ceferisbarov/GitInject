# Scanner types

`AttackHypothesis` combines an objective, rationale, severity, setup primitives, trigger, check, and provenance/tags. `ValidationResult` adds confirmation status, rates, attempts/invalid runs, recipe/run links, diagnostics, timing, and corrections. The serialization helpers preserve recipe-shaped data.

`ScanCost.total_usd` uses the repository's static price table. Unknown models contribute zero; this is an estimate from captured usage, not complete provider/workflow billing.

::: gitinject.scanner.types
    options:
      members: [EffectivePromptContext, SetupStep, TriggerSpec, SuccessCheck, AttackHypothesis, ValidationResult, MemoryEntry, ScanCost, cost_for_usage, roll_up_usage, hypothesis_to_dict, hypothesis_from_dict]
