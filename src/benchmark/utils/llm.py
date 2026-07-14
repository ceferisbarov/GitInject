from __future__ import annotations

import os
from contextvars import ContextVar
from dataclasses import dataclass


class LLMError(Exception):
    pass


@dataclass
class LLMResponse:
    text: str
    input_tokens: int
    output_tokens: int
    model: str


_usage_log: ContextVar[list[LLMResponse] | None] = ContextVar("usage_log", default=None)


class track_usage:
    """Context manager that captures every LLMResponse produced within its scope.

    Usage:
        with track_usage() as log:
            call_llm(...)
            call_llm(...)
        # log is a list[LLMResponse]
    """

    def __enter__(self) -> list[LLMResponse]:
        self._log: list[LLMResponse] = []
        self._token = _usage_log.set(self._log)
        return self._log

    def __exit__(self, *exc):
        _usage_log.reset(self._token)


def _record(resp: LLMResponse) -> None:
    log = _usage_log.get()
    if log is not None:
        log.append(resp)


def _parse_model(model: str) -> tuple[str, str]:
    """Parse 'provider/model-name' into (provider, model_name).

    Supported providers: anthropic, google, openai, openrouter.
    Bare model names fall back to heuristic detection.
    """
    if model.startswith("openrouter/"):
        return "openrouter", model[len("openrouter/") :]
    if "/" in model:
        provider, model_name = model.split("/", 1)
        return provider, model_name
    if model.startswith("claude"):
        return "anthropic", model
    if model.startswith("gemini"):
        return "google", model
    return "openai", model


def call_llm(
    model: str,
    system: str,
    user: str,
    max_tokens: int = 2048,
    temperature: float | None = None,
) -> LLMResponse:
    """Call an LLM and return an LLMResponse with text and token usage.

    model format: 'provider/model-name'  e.g. 'anthropic/claude-sonnet-4-6',
    'google/gemini-2.5-flash', 'openai/gpt-4o', 'openrouter/openai/gpt-4o'.
    Bare model names are accepted with heuristic provider detection.
    """
    provider, model_name = _parse_model(model)

    try:
        if provider == "anthropic":
            resp = _call_anthropic(model_name, system, user, max_tokens, temperature)
        elif provider in ("google", "gemini"):
            resp = _call_google(model_name, system, user, max_tokens, temperature)
        elif provider == "openrouter":
            resp = _call_openai(
                model_name,
                system,
                user,
                max_tokens,
                temperature,
                base_url="https://openrouter.ai/api/v1",
                api_key=os.environ.get("OPENROUTER_API_KEY", ""),
            )
        else:
            resp = _call_openai(model_name, system, user, max_tokens, temperature)
    except LLMError:
        raise
    except Exception as e:
        raise LLMError(str(e)) from e

    _record(resp)
    return resp


def _call_anthropic(model: str, system: str, user: str, max_tokens: int, temperature: float | None) -> LLMResponse:
    import anthropic

    try:
        client = anthropic.Anthropic()
        kwargs: dict = dict(
            model=model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": user}],
        )
        if system:
            kwargs["system"] = system
        if temperature is not None:
            kwargs["temperature"] = temperature
        response = client.messages.create(**kwargs)
        usage = getattr(response, "usage", None)
        return LLMResponse(
            text=response.content[0].text,
            input_tokens=int(getattr(usage, "input_tokens", 0) or 0),
            output_tokens=int(getattr(usage, "output_tokens", 0) or 0),
            model=model,
        )
    except anthropic.AuthenticationError as e:
        raise LLMError(f"Anthropic authentication failed: {e}") from e
    except anthropic.PermissionDeniedError as e:
        raise LLMError(f"Anthropic access denied (credits exhausted?): {e}") from e
    except anthropic.RateLimitError as e:
        raise LLMError(f"Anthropic rate limit: {e}") from e


def _call_google(model: str, system: str, user: str, max_tokens: int, temperature: float | None) -> LLMResponse:
    from google import genai

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise LLMError("GEMINI_API_KEY is not set")
    client = genai.Client(api_key=api_key)
    config: dict = {"max_output_tokens": max_tokens}
    if system:
        config["system_instruction"] = system
    if temperature is not None:
        config["temperature"] = temperature
    response = client.models.generate_content(model=model, contents=user, config=config)
    text = response.text
    if text is None:
        raise LLMError(f"Google model returned empty response (blocked?): {response}")
    usage = getattr(response, "usage_metadata", None)
    return LLMResponse(
        text=text,
        input_tokens=int(getattr(usage, "prompt_token_count", 0) or 0),
        output_tokens=int(getattr(usage, "candidates_token_count", 0) or 0),
        model=model,
    )


def _call_openai(
    model: str,
    system: str,
    user: str,
    max_tokens: int,
    temperature: float | None,
    base_url: str | None = None,
    api_key: str | None = None,
) -> LLMResponse:
    from openai import AuthenticationError, OpenAI, RateLimitError

    kwargs: dict = {}
    if base_url:
        kwargs["base_url"] = base_url
    if api_key:
        kwargs["api_key"] = api_key
    client = OpenAI(**kwargs)

    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": user})

    request: dict = dict(model=model, messages=messages, max_completion_tokens=max_tokens)
    if temperature is not None:
        request["temperature"] = temperature

    try:
        response = client.chat.completions.create(**request)
        content = response.choices[0].message.content
        if not content:
            finish_reason = response.choices[0].finish_reason if response.choices else "unknown"
            raise LLMError(f"OpenAI returned empty content (finish_reason={finish_reason}, model={model})")
        usage = getattr(response, "usage", None)
        return LLMResponse(
            text=content,
            input_tokens=int(getattr(usage, "prompt_tokens", 0) or 0),
            output_tokens=int(getattr(usage, "completion_tokens", 0) or 0),
            model=model,
        )
    except AuthenticationError as e:
        raise LLMError(f"OpenAI authentication failed: {e}") from e
    except RateLimitError as e:
        raise LLMError(f"OpenAI rate limit: {e}") from e
