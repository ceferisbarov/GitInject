from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class EffectivePromptContext:
    workflow_id: str
    provider: str
    reconstructed_prompt: str
    tool_restrictions: list[str]
    has_persist_credentials: bool
    trigger_event: str


@dataclass
class SetupStep:
    primitive: str
    args: dict[str, Any] = field(default_factory=dict)


@dataclass
class TriggerSpec:
    event_type: str
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class SuccessCheck:
    kind: str
    args: dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackHypothesis:
    id: str
    mitre_category: str
    attack_goal: str
    rationale: str
    severity: str
    setup: list[SetupStep] = field(default_factory=list)
    trigger: TriggerSpec | None = None
    success_check: SuccessCheck | None = None
    tags: list[str] = field(default_factory=list)
    seeded_from: str | None = None


@dataclass
class ValidationResult:
    hypothesis: AttackHypothesis
    status: str
    failure_reason: str | None
    success_rate: str
    iteration: int
    discard_reason: str | None
    run_ids: list[str]
    payload_used: str
    suggested_mitigation: str
    billable_minutes: float
    wall_seconds: float
    evaluator_correction: str | None = None


# Model pricing in (input $/MTok, output $/MTok). Verified 2026-05 against
# Anthropic (docs.anthropic.com/en/docs/about-claude/pricing), Google
# (ai.google.dev/gemini-api/docs/pricing), and OpenAI rate cards. Gemini Pro
# rates are the standard <=200K-prompt tier. Unknown models price at $0 — the
# report surfaces them so we notice the gap rather than silently undercounting.
MODEL_PRICING: dict[str, tuple[float, float]] = {
    "claude-opus-4-7": (5.00, 25.00),
    "claude-opus-4-6": (5.00, 25.00),
    "claude-opus-4-5": (5.00, 25.00),
    "claude-opus-4-1": (15.00, 75.00),
    "claude-sonnet-4-6": (3.00, 15.00),
    "claude-sonnet-4-5": (3.00, 15.00),
    "claude-haiku-4-5": (1.00, 5.00),
    "gemini-2.5-flash": (0.30, 2.50),
    "gemini-2.5-pro": (1.25, 10.00),
    "gemini-3.1-pro-preview": (2.00, 12.00),
    "gpt-5": (1.25, 10.00),
    "gpt-5-2025-08-07": (1.25, 10.00),
    "gpt-4o": (2.50, 10.00),
    "gpt-4o-mini": (0.15, 0.60),
}


def cost_for_usage(usage_by_model: dict[str, dict[str, int]]) -> float:
    total = 0.0
    for model, t in usage_by_model.items():
        in_price, out_price = MODEL_PRICING.get(model, (0.0, 0.0))
        total += (t.get("input", 0) * in_price + t.get("output", 0) * out_price) / 1_000_000
    return total


def roll_up_usage(log) -> dict[str, dict[str, int]]:
    """Aggregate a list[LLMResponse] into {model: {"input": int, "output": int}}."""
    out: dict[str, dict[str, int]] = {}
    for r in log:
        bucket = out.setdefault(r.model, {"input": 0, "output": 0})
        bucket["input"] += int(r.input_tokens)
        bucket["output"] += int(r.output_tokens)
    return out


@dataclass
class ScanCost:
    token_usage_by_model: dict[str, dict[str, int]] = field(default_factory=dict)
    total_billable_minutes: float = 0.0
    total_wall_seconds: float = 0.0

    @property
    def total_input_tokens(self) -> int:
        return sum(v.get("input", 0) for v in self.token_usage_by_model.values())

    @property
    def total_output_tokens(self) -> int:
        return sum(v.get("output", 0) for v in self.token_usage_by_model.values())

    @property
    def total_usd(self) -> float:
        return cost_for_usage(self.token_usage_by_model)


@dataclass
class MemoryEntry:
    provider: str
    mitre_category: str
    recipe_fingerprint: str
    recipe_template: dict
    attack_goal: str
    status: str
    failure_reason: str | None = None
    evaluator_correction: str | None = None
    tags: list[str] = field(default_factory=list)
    workflow_ids: list[str] = field(default_factory=list)
    first_seen: str = ""
    source: str | None = None


def hypothesis_to_dict(h: AttackHypothesis) -> dict:
    return {
        "id": h.id,
        "mitre_category": h.mitre_category,
        "attack_goal": h.attack_goal,
        "rationale": h.rationale,
        "severity": h.severity,
        "setup": [{"primitive": s.primitive, "args": s.args} for s in h.setup],
        "trigger": {"event_type": h.trigger.event_type, "data": h.trigger.data} if h.trigger else None,
        "success_check": {"kind": h.success_check.kind, "args": h.success_check.args} if h.success_check else None,
        "tags": h.tags,
        "seeded_from": h.seeded_from,
    }


def hypothesis_from_dict(d: dict) -> AttackHypothesis:
    trigger = None
    if d.get("trigger"):
        trigger = TriggerSpec(event_type=d["trigger"].get("event_type", ""), data=d["trigger"].get("data", {}))
    success_check = None
    if d.get("success_check"):
        success_check = SuccessCheck(kind=d["success_check"].get("kind", ""), args=d["success_check"].get("args", {}))
    setup = [SetupStep(primitive=s.get("primitive", ""), args=s.get("args", {})) for s in d.get("setup", [])]
    return AttackHypothesis(
        id=d.get("id", ""),
        mitre_category=d.get("mitre_category", ""),
        attack_goal=d.get("attack_goal", ""),
        rationale=d.get("rationale", ""),
        severity=d.get("severity", "medium"),
        setup=setup,
        trigger=trigger,
        success_check=success_check,
        tags=d.get("tags", []),
        seeded_from=d.get("seeded_from"),
    )
