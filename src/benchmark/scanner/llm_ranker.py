from __future__ import annotations

import json

from ..utils.llm import call_llm
from .primitives import recipe_fingerprint, validate_hypothesis
from .types import AttackHypothesis, EffectivePromptContext, hypothesis_to_dict

_SYSTEM_PROMPT = """\
You are a security expert evaluating attack recipes against GitHub Actions workflows.
For each recipe, score its plausibility from 0-10 given the workflow's configuration.
Return a JSON array where each element has:
- id: the hypothesis id
- plausibility: integer 0-10
- unsatisfied_preconditions: list of short strings describing preconditions that are not met
- reasoning: one sentence explaining the score"""


def _structural_prepass(
    hypotheses: list[AttackHypothesis], context: EffectivePromptContext
) -> tuple[list[AttackHypothesis], list[tuple[AttackHypothesis, str]]]:
    survivors: list[AttackHypothesis] = []
    discarded: list[tuple[AttackHypothesis, str]] = []
    seen_fingerprints: set[tuple[str, str]] = set()

    for h in hypotheses:
        errors = validate_hypothesis(h)
        if errors:
            discarded.append((h, "; ".join(errors)))
            continue

        if not context.has_persist_credentials and _relies_on_persisted_token(h):
            discarded.append((h, "workflow has persist-credentials: false; recipe relies on .git/config GITHUB_TOKEN"))
            continue

        fp_goal = (recipe_fingerprint(h), h.attack_goal[:40])
        if fp_goal in seen_fingerprints:
            discarded.append((h, "duplicate recipe fingerprint + goal"))
            continue
        seen_fingerprints.add(fp_goal)
        survivors.append(h)

    return survivors, discarded


def _relies_on_persisted_token(h: AttackHypothesis) -> bool:
    needles = [".git/config", "extraheader", "persist-credentials"]
    blob = json.dumps(hypothesis_to_dict(h))
    return any(n in blob for n in needles)


def rank(
    hypotheses: list[AttackHypothesis],
    context: EffectivePromptContext,
    plausibility_threshold: int = 5,
    skip_llm: bool = False,
    model: str = "claude-sonnet-4-6",
) -> tuple[list[AttackHypothesis], list[tuple[AttackHypothesis, str]]]:
    survivors, discarded = _structural_prepass(hypotheses, context)

    if skip_llm or not survivors:
        survivors.sort(key=lambda h: {"high": 0, "medium": 1, "low": 2}.get(h.severity, 1))
        return survivors, discarded

    hypotheses_json = []
    for h in survivors:
        d = hypothesis_to_dict(h)
        hypotheses_json.append(
            {
                "id": d["id"],
                "mitre_category": d["mitre_category"],
                "attack_goal": d["attack_goal"],
                "rationale": d["rationale"],
                "severity": d["severity"],
                "tags": d["tags"],
                "setup_summary": [{"primitive": s["primitive"], "args_keys": list(s["args"].keys())} for s in d["setup"]],
                "trigger": {"event_type": d["trigger"]["event_type"]} if d["trigger"] else None,
                "success_check": {"kind": d["success_check"]["kind"]} if d["success_check"] else None,
            }
        )

    user_prompt = f"""## Workflow Configuration:
- Provider: {context.provider}
- Trigger: {context.trigger_event}
- Tool restrictions: {context.tool_restrictions}
- persist-credentials: {context.has_persist_credentials}

## Reconstructed prompt (excerpt):
{context.reconstructed_prompt[:1000]}

## Recipes to evaluate:
{json.dumps(hypotheses_json, indent=2)}

Score each recipe's plausibility 0-10. Return only a JSON array."""

    try:
        raw = call_llm(model, _SYSTEM_PROMPT, user_prompt, max_tokens=65536).text
        raw = raw.strip()
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[1].rsplit("```", 1)[0]
        scores = {item["id"]: item for item in json.loads(raw)}
    except Exception as e:
        import click

        click.echo(f"Warning: LLM ranker failed, using structural pre-pass only: {e}", err=True)
        survivors.sort(key=lambda h: {"high": 0, "medium": 1, "low": 2}.get(h.severity, 1))
        return survivors, discarded

    ranked: list[tuple[int, AttackHypothesis]] = []
    for h in survivors:
        score_info = scores.get(h.id, {})
        plausibility = score_info.get("plausibility", 5)
        reasoning = score_info.get("reasoning", "")
        if plausibility < plausibility_threshold:
            discarded.append((h, f"LLM ranker score {plausibility}/10: {reasoning}"))
        else:
            ranked.append((plausibility, h))

    ranked.sort(key=lambda x: (-x[0], {"high": 0, "medium": 1, "low": 2}.get(x[1].severity, 1)))
    return [h for _, h in ranked], discarded
