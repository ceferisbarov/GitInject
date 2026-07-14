from __future__ import annotations

import os
import re

import yaml

from .types import EffectivePromptContext

GITHUB_CONTEXT_VARS = {
    "${{ github.event.pull_request.body }}": "{{PR_BODY}}",
    "${{ github.event.pull_request.title }}": "{{PR_TITLE}}",
    "${{ github.event.pull_request.head.ref }}": "{{PR_HEAD_REF}}",
    "${{ github.event.issue.body }}": "{{ISSUE_BODY}}",
    "${{ github.event.issue.title }}": "{{ISSUE_TITLE}}",
    "${{ github.event.comment.body }}": "{{COMMENT_BODY}}",
    "${{ github.event.review.body }}": "{{REVIEW_BODY}}",
    "${{ github.event.review_comment.body }}": "{{REVIEW_COMMENT_BODY}}",
    "${{ github.event.commits[0].message }}": "{{COMMIT_MESSAGE}}",
    "${{ github.repository }}": "{{REPO}}",
    "${{ github.actor }}": "{{ACTOR}}",
}


_PROVIDER_PATTERNS = [
    (re.compile(r"anthropics/claude-code-action"), "claude"),
    (re.compile(r"google-github-actions/run-gemini"), "gemini"),
    (re.compile(r"openai/codex"), "codex"),
    (re.compile(r"cline"), "cline"),
    (re.compile(r"opencode"), "opencode"),
]


def _detect_provider(workflow_dict: dict) -> str:
    raw = yaml.dump(workflow_dict)
    for pattern, name in _PROVIDER_PATTERNS:
        if pattern.search(raw):
            return name
    return "unknown"


def _find_workflow_ymls(workflow_dir: str) -> list[str]:
    contents_dir = os.path.join(workflow_dir, "contents")
    if not os.path.isdir(contents_dir):
        return []
    results = []
    for root, _dirs, files in os.walk(contents_dir):
        for f in files:
            if f.endswith(".yml") or f.endswith(".yaml"):
                results.append(os.path.join(root, f))
    return results


def _substitute_vars(text: str) -> str:
    for original, placeholder in GITHUB_CONTEXT_VARS.items():
        text = text.replace(original, placeholder)
    return text


def _extract_tool_restrictions(workflow_dict: dict) -> list[str]:
    restrictions = []
    raw = yaml.dump(workflow_dict)
    allowed_tools_match = re.search(r"--allowedTools\s+[\"']?([^\"'\n]+)", raw)
    if allowed_tools_match:
        restrictions.append(f"--allowedTools {allowed_tools_match.group(1).strip()}")
    if "--disallowedTools" in raw:
        m = re.search(r"--disallowedTools\s+[\"']?([^\"'\n]+)", raw)
        if m:
            restrictions.append(f"--disallowedTools {m.group(1).strip()}")
    return restrictions


def _has_persist_credentials(workflow_dict: dict) -> bool:
    for job in (workflow_dict or {}).get("jobs", {}).values():
        for step in job.get("steps", []):
            with_block = step.get("with") or {}
            if str(with_block.get("persist-credentials", "")).lower() == "false":
                return False
    return True


def _extract_trigger_event(workflow_dict: dict) -> str:
    on = workflow_dict.get("on") or workflow_dict.get(True) or {}
    if not on:
        return ""
    if isinstance(on, str):
        return on
    if isinstance(on, list):
        return ",".join(str(e) for e in on)
    if isinstance(on, dict):
        return ",".join(on.keys())
    return str(on)


def _reconstruct_prompt(workflow_dict: dict) -> str:
    parts = []
    for job in (workflow_dict or {}).get("jobs", {}).values():
        for step in job.get("steps", []):
            with_block = step.get("with") or {}
            for key in ("prompt", "args"):
                val = with_block.get(key)
                if val:
                    parts.append(_substitute_vars(str(val)))
    return "\n\n".join(parts) if parts else "(no explicit prompt — uses defaults)"


def extract(workflow_id: str, workflows_dir: str = "src/benchmark/workflows") -> EffectivePromptContext:
    workflow_dir = os.path.join(workflows_dir, workflow_id)
    ymls = _find_workflow_ymls(workflow_dir)

    merged: dict = {}
    for yml_path in ymls:
        with open(yml_path) as f:
            doc = yaml.safe_load(f) or {}
            merged.setdefault("jobs", {}).update(doc.get("jobs", {}))
            on_val = doc.get("on") or doc.get(True)
            if on_val and not merged.get("on") and not merged.get(True):
                merged["on"] = on_val

    provider = _detect_provider(merged)
    reconstructed_prompt = _reconstruct_prompt(merged)
    tool_restrictions = _extract_tool_restrictions(merged)
    has_persist_creds = _has_persist_credentials(merged)
    trigger_event = _extract_trigger_event(merged)

    return EffectivePromptContext(
        workflow_id=workflow_id,
        provider=provider,
        reconstructed_prompt=reconstructed_prompt,
        tool_restrictions=tool_restrictions,
        has_persist_credentials=has_persist_creds,
        trigger_event=trigger_event,
    )
