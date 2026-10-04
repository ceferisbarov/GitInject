# Model calls and usage

`call_llm` routes scanner and semantic-judge requests by model prefix. Explicit prefixes are `anthropic/`, `google/` (also `gemini/`), `openai/`, and `openrouter/`. Bare Claude/Gemini names select their native provider; other bare names use OpenAI. OpenRouter names retain the nested provider/model, for example `openrouter/openai/gpt-4o-mini`.

Provider errors become `LLMError`. A returned `LLMResponse` includes text, input/output token counts, and model. `track_usage` captures helper responses in the current context for scanner cost aggregation. AutoInject and offline victim calls do not use this routing helper.

::: gitinject.utils.llm
    options:
      members: [LLMError, LLMResponse, call_llm, track_usage]
