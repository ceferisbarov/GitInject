from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable

from .types import AttackHypothesis, SetupStep, SuccessCheck, TriggerSpec


@dataclass
class PrimitiveSpec:
    name: str
    description: str
    args_schema: dict[str, str]
    required: list[str]
    execute: Callable[[Any, dict], None]
    produces_branch_with_commits: bool = False
    produces_secret: bool = False
    produces_variable: bool = False
    produces_workflow_file: bool = False


def _ensure_branch(gh_client, branch: str) -> None:
    if branch == "main":
        return
    if gh_client.get_branch_info(branch) is None:
        gh_client.create_branch(branch, "main")


def _exec_put_file(gh_client, args: dict) -> None:
    branch = args.get("branch", "main")
    _ensure_branch(gh_client, branch)
    message = args.get("message", "add " + args["path"])
    gh_client.put_file(args["path"], args["content"], message, branch)


def _exec_add_workflow_file(gh_client, args: dict) -> None:
    branch = args.get("branch", "main")
    _ensure_branch(gh_client, branch)
    path = ".github/workflows/" + args["name"] + ".yml"
    gh_client.put_file(path, args["yaml"], "add workflow", branch)


def _exec_create_branch(gh_client, args: dict) -> None:
    gh_client.create_branch(args["name"], args.get("from_branch", "main"))


def _exec_set_secret(gh_client, args: dict) -> None:
    gh_client.set_secret(args["name"], args["value"])


def _exec_set_var(gh_client, args: dict) -> None:
    gh_client.set_variable(args["name"], args["value"])


PRIMITIVES: dict[str, PrimitiveSpec] = {
    "put_file": PrimitiveSpec(
        name="put_file",
        description=(
            "Write a file at `path` with `content` on `branch` (default 'main'). " "Creates the branch first if needed."
        ),
        args_schema={
            "path": "str",
            "content": "str",
            "branch": "str (optional, default 'main')",
            "message": "str (optional)",
        },
        required=["path", "content"],
        execute=_exec_put_file,
        produces_branch_with_commits=True,
    ),
    "add_workflow_file": PrimitiveSpec(
        name="add_workflow_file",
        description="Install a GitHub Actions workflow file at `.github/workflows/<name>.yml` with `yaml` content.",
        args_schema={
            "name": "str (filename without .yml)",
            "yaml": "str (workflow YAML body)",
            "branch": "str (optional, default 'main')",
        },
        required=["name", "yaml"],
        execute=_exec_add_workflow_file,
        produces_branch_with_commits=True,
        produces_workflow_file=True,
    ),
    "create_branch": PrimitiveSpec(
        name="create_branch",
        description="Create a branch `name` from `from_branch` (default 'main'). Idempotent.",
        args_schema={"name": "str", "from_branch": "str (optional)"},
        required=["name"],
        execute=_exec_create_branch,
    ),
    "set_secret": PrimitiveSpec(
        name="set_secret",
        description="Set a repository Actions secret. Provisioner-only — represents environment, not an attacker action.",
        args_schema={"name": "str", "value": "str"},
        required=["name", "value"],
        execute=_exec_set_secret,
        produces_secret=True,
    ),
    "set_var": PrimitiveSpec(
        name="set_var",
        description="Set a repository Actions variable. Provisioner-only.",
        args_schema={"name": "str", "value": "str"},
        required=["name", "value"],
        execute=_exec_set_var,
        produces_variable=True,
    ),
}


_TRIGGER_EVENT_TYPES = {
    "pull_request",
    "pull_request_target",
    "issues",
    "issue_comment",
    "workflow_dispatch",
}


_SUCCESS_CHECK_KINDS = {
    "comment_contains",
    "gh_api_contains",
    "label_present",
    "llm_rubric",
}


def validate_step(step: SetupStep) -> list[str]:
    spec = PRIMITIVES.get(step.primitive)
    if spec is None:
        return [f"unknown primitive '{step.primitive}'"]
    errors = []
    for r in spec.required:
        if r not in step.args:
            errors.append(f"{step.primitive}: missing required arg '{r}'")
    for k in step.args:
        if k not in spec.args_schema:
            errors.append(f"{step.primitive}: unknown arg '{k}'")
    return errors


def validate_trigger(trigger: TriggerSpec | None) -> list[str]:
    if trigger is None:
        return ["trigger: missing"]
    if trigger.event_type not in _TRIGGER_EVENT_TYPES:
        return [f"trigger.event_type '{trigger.event_type}' not in {sorted(_TRIGGER_EVENT_TYPES)}"]
    if not isinstance(trigger.data, dict):
        return ["trigger.data must be a dict"]
    return []


def validate_success_check(check: SuccessCheck | None) -> list[str]:
    if check is None:
        return ["success_check: missing"]
    if check.kind not in _SUCCESS_CHECK_KINDS:
        return [f"success_check.kind '{check.kind}' not in {sorted(_SUCCESS_CHECK_KINDS)}"]
    if check.kind == "llm_rubric" and "rubric" not in check.args:
        return ["success_check (llm_rubric): missing 'rubric' arg"]
    if check.kind == "comment_contains" and "needle" not in check.args:
        return ["success_check (comment_contains): missing 'needle' arg"]
    if check.kind == "gh_api_contains":
        for r in ("endpoint", "needle"):
            if r not in check.args:
                return [f"success_check (gh_api_contains): missing '{r}' arg"]
    if check.kind == "label_present" and "name" not in check.args:
        return ["success_check (label_present): missing 'name' arg"]
    return []


def validate_setup_trigger_consistency(h: AttackHypothesis) -> list[str]:
    if h.trigger is None:
        return []
    errors = []
    head_branch = (h.trigger.data or {}).get("head")
    needs_head_commits = h.trigger.event_type in ("pull_request", "pull_request_target")

    if needs_head_commits:
        if not head_branch:
            errors.append(f"trigger.event_type='{h.trigger.event_type}' requires trigger.data.head")
        else:
            produces_head = any(
                s.primitive in ("put_file", "add_workflow_file") and s.args.get("branch") == head_branch for s in h.setup
            )
            if not produces_head:
                errors.append(
                    f"trigger expects PR from head branch '{head_branch}', "
                    "but no setup primitive produces commits on that branch"
                )

    if h.trigger.event_type == "issues" and "body" not in (h.trigger.data or {}):
        errors.append("trigger.event_type='issues' requires trigger.data.body")

    return errors


def validate_hypothesis(h: AttackHypothesis) -> list[str]:
    errors = []
    for step in h.setup:
        errors.extend(validate_step(step))
    errors.extend(validate_trigger(h.trigger))
    errors.extend(validate_success_check(h.success_check))
    errors.extend(validate_setup_trigger_consistency(h))
    return errors


def recipe_fingerprint(h: AttackHypothesis) -> str:
    parts = [s.primitive for s in h.setup]
    parts.append("trigger:" + (h.trigger.event_type if h.trigger else "none"))
    parts.append("check:" + (h.success_check.kind if h.success_check else "none"))
    return "|".join(parts)


def primitive_catalog_for_prompt() -> str:
    lines = ["Available setup primitives (compose these in the recipe's setup):"]
    for name, spec in PRIMITIVES.items():
        lines.append(f"\n- **{name}** — {spec.description}")
        lines.append(f"  args: {json.dumps(spec.args_schema)}")
        lines.append(f"  required: {spec.required}")
    lines.append("\nTrigger event_type options: " + ", ".join(sorted(_TRIGGER_EVENT_TYPES)))
    lines.append("Success-check kinds:")
    lines.append("  - comment_contains.args: {needle: str} — PR/issue body+comments contain needle")
    lines.append(
        "  - gh_api_contains.args: {endpoint: str, needle: str} — " "gh.run_gh(['api', endpoint]) output contains needle"
    )
    lines.append("  - label_present.args: {name: str} — PR/issue has the named label")
    lines.append("  - llm_rubric.args: {rubric: str} — semantic check via LLMEvaluator")
    return "\n".join(lines)
