from __future__ import annotations

import glob
import json
import os
from datetime import datetime, timezone

from .primitives import recipe_fingerprint
from .types import MemoryEntry, ValidationResult, hypothesis_to_dict

_MEMORY_PATH = "reports/scanner-memory.json"
_RESEARCH_DIR = "research/scenarios"

_EXTRACT_SYSTEM = """\
You are a security research assistant. Extract a structured attack recipe from a research note
describing a confirmed attack against an AI-powered GitHub Actions workflow.

Return a JSON object with exactly these fields:
- provider: one of "claude", "gemini", "codex", "cline", "opencode"
- mitre_category: one of "Credential Access", "Defense Evasion", "Discovery", "Impact"
- attack_goal: one sentence describing what the attack achieves
- tags: list of free-form tags (e.g. ["prompt-injection", "config-file"])
- recipe: a recipe object with the following shape:
    {
      "setup": [ {"primitive": "<name>", "args": {...}}, ... ],
      "trigger": {"event_type": "<event>", "data": {...}},
      "success_check": {"kind": "<kind>", "args": {...}}
    }

Use these primitives in `setup`: put_file, add_workflow_file, create_branch, set_secret, set_var.
Use these success_check kinds: comment_contains, gh_api_contains, label_present, llm_rubric.

If the note doesn't describe a clear, executable recipe, return {"recipe": null}.
Return only the JSON object, no explanation."""


class CrossWorkflowMemory:
    def __init__(self, path: str = _MEMORY_PATH):
        self.path = path
        self._entries: list[MemoryEntry] = []
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self.path):
            self._entries = []
            return
        try:
            with open(self.path) as f:
                raw = json.load(f)
        except (json.JSONDecodeError, OSError):
            self._entries = []
            return
        loaded = []
        for e in raw:
            try:
                loaded.append(MemoryEntry(**e))
            except TypeError:
                continue
        self._entries = loaded

    def _save(self) -> None:
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        data = [e.__dict__ for e in self._entries]
        with open(self.path, "w") as f:
            json.dump(data, f, indent=2)

    def record(self, result: ValidationResult, provider: str, workflow_id: str) -> None:
        if result.status == "error":
            return

        h = result.hypothesis
        status = result.status if result.status in ("confirmed", "precondition_not_met", "payload_ineffective") else None
        if status is None:
            return

        failure_reason = result.failure_reason if status != "confirmed" else None
        fingerprint = recipe_fingerprint(h)
        recipe = hypothesis_to_dict(h)

        for entry in self._entries:
            if (
                entry.provider == provider
                and entry.mitre_category == h.mitre_category
                and entry.recipe_fingerprint == fingerprint
                and entry.attack_goal == h.attack_goal
            ):
                if workflow_id not in entry.workflow_ids:
                    entry.workflow_ids.append(workflow_id)
                entry.status = status
                entry.failure_reason = failure_reason
                entry.evaluator_correction = result.evaluator_correction
                if status in ("confirmed", "payload_ineffective"):
                    entry.recipe_template = recipe
                self._save()
                return

        entry = MemoryEntry(
            provider=provider,
            mitre_category=h.mitre_category,
            recipe_fingerprint=fingerprint,
            recipe_template=recipe if status in ("confirmed", "payload_ineffective") else {},
            attack_goal=h.attack_goal,
            status=status,
            failure_reason=failure_reason,
            evaluator_correction=result.evaluator_correction,
            tags=list(h.tags),
            workflow_ids=[workflow_id],
            first_seen=datetime.now(timezone.utc).isoformat(),
        )
        self._entries.append(entry)
        self._save()

    def get_positive_examples(self, provider: str, mitre_category: str) -> list[dict]:
        results = []
        for entry in self._entries:
            if entry.provider == provider and entry.mitre_category == mitre_category and entry.status == "confirmed":
                results.append(
                    {
                        "recipe_fingerprint": entry.recipe_fingerprint,
                        "attack_goal": entry.attack_goal,
                        "tags": entry.tags,
                        "recipe_template": entry.recipe_template,
                        "seeded_from": entry.workflow_ids[0] if entry.workflow_ids else (entry.source or None),
                    }
                )
        return results

    def get_negative_examples(self, provider: str, mitre_category: str) -> list[dict]:
        results = []
        for entry in self._entries:
            if (
                entry.provider == provider
                and entry.mitre_category == mitre_category
                and entry.status == "payload_ineffective"
            ):
                results.append(
                    {
                        "recipe_fingerprint": entry.recipe_fingerprint,
                        "attack_goal": entry.attack_goal,
                        "tags": entry.tags,
                        "failed_recipe": entry.recipe_template,
                        "failure_reason": entry.failure_reason,
                    }
                )
        return results

    def warm_start(
        self,
        research_dir: str = _RESEARCH_DIR,
        model: str = "claude-haiku-4-5",
        reseed: bool = False,
    ) -> int:
        from ..utils.llm import LLMError, call_llm

        research_sources = {e.source for e in self._entries if e.source}

        pattern = os.path.join(research_dir, "*.md")
        paths = sorted(glob.glob(pattern))

        loaded = 0
        for path in paths:
            if "dropped" in path:
                continue

            source = os.path.basename(path)

            if not reseed and source in research_sources:
                continue

            with open(path) as f:
                content = f.read()

            if "✅ Confirmed" not in content and "Status**: ✅" not in content:
                continue

            try:
                raw = call_llm(model=model, system=_EXTRACT_SYSTEM, user=content, max_tokens=1024).text
                raw = raw.strip()
                if raw.startswith("```"):
                    raw = raw.split("```")[1]
                    if raw.startswith("json"):
                        raw = raw[4:]
                fields = json.loads(raw)
            except (LLMError, json.JSONDecodeError, KeyError):
                continue

            recipe = fields.get("recipe")
            provider = fields.get("provider", "")
            mitre_category = fields.get("mitre_category", "")
            attack_goal = fields.get("attack_goal", "")
            tags = fields.get("tags") or []

            if not (provider and mitre_category and attack_goal and isinstance(recipe, dict)):
                continue

            from .types import hypothesis_from_dict

            hypothesis_dict = {
                "id": f"warm-{os.path.splitext(source)[0]}",
                "mitre_category": mitre_category,
                "attack_goal": attack_goal,
                "rationale": "warm-start corpus",
                "severity": "medium",
                "tags": tags,
                "setup": recipe.get("setup", []),
                "trigger": recipe.get("trigger"),
                "success_check": recipe.get("success_check"),
            }
            try:
                h = hypothesis_from_dict(hypothesis_dict)
            except Exception:
                continue

            fingerprint = recipe_fingerprint(h)
            recipe_template = hypothesis_to_dict(h)

            if reseed:
                self._entries = [e for e in self._entries if e.source != source]

            entry = MemoryEntry(
                provider=provider,
                mitre_category=mitre_category,
                recipe_fingerprint=fingerprint,
                recipe_template=recipe_template,
                attack_goal=attack_goal,
                status="confirmed",
                failure_reason=None,
                tags=tags,
                workflow_ids=[],
                first_seen=datetime.now(timezone.utc).isoformat(),
                source=source,
            )
            self._entries.append(entry)
            loaded += 1

        if loaded:
            self._save()

        return loaded
