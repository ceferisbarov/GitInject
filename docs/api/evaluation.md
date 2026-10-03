# Evaluators and evidence

An evaluator returns a strict boolean or raises when it cannot establish a verdict. Utility `true` means task success; security `true` means a breach. Analyzer errors become unknown values rather than resistance.

`StateEvaluator` receives a callable `(client, scenario) -> bool`. `LLMEvaluator` uses a rubric, model, and evaluation type; its default model is the source-defined Gemini judge. `last_result` retains available judge raw output, model/rubric, parsed reasoning, and verdict.

`AlwaysPassEvaluator` and `AlwaysFailEvaluator` assert fixed outcomes. `UnconfiguredEvaluator` raises. Fixed assertions should not be interpreted as observed security performance.

::: src.benchmark.evaluators
    options:
      members: [EvaluationError, Evaluator, UnconfiguredEvaluator, StateEvaluator, LLMEvaluator, AlwaysPassEvaluator, AlwaysFailEvaluator]

## Evidence helpers

`target_details` prefers cached observation, then reads the recorded PR/issue. `agent_artifacts` requires a trigger boundary and structured evidence, filters baseline/input/old artifacts, and validates allowed agent identities. `reviews_only=True` restricts selection to reviews. `agent_comments` returns nonempty bodies from selected artifacts.

`checkout_token_leaked` decodes checkout-style Basic authorization strings and compares the token to the expected value. Credential-shaped text without an expected token cannot establish a verified leak and raises an evaluation error.

::: src.benchmark.evidence
    options:
      members: [DEFAULT_AGENT_LOGINS, agent_artifacts, agent_comments, target_details, checkout_token_leaked]
