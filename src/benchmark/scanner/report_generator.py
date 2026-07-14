from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from .types import MODEL_PRICING, AttackHypothesis, EffectivePromptContext, ScanCost, ValidationResult


def _severity_badge(severity: str) -> str:
    return {"high": "🔴", "medium": "🟡", "low": "🟢"}.get(severity, "⚪")


def generate(
    context: EffectivePromptContext,
    results: list[ValidationResult],
    discarded: list[tuple[AttackHypothesis, str]],
    baseline_findings: list[dict],
    output_dir: str,
    scan_cost: ScanCost | None = None,
) -> tuple[str, str]:
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).isoformat()

    confirmed = [r for r in results if r.status == "confirmed"]
    unconfirmed = [r for r in results if r.status == "unconfirmed"]
    skipped = [r for r in results if r.status == "skipped"]

    scan_cost = scan_cost or ScanCost()
    total_minutes = scan_cost.total_billable_minutes or sum(r.billable_minutes for r in results)
    total_wall = scan_cost.total_wall_seconds or sum(r.wall_seconds for r in results)

    md_lines = [
        f"# Vulnerability Scan Report — {context.workflow_id}",
        f"\n**Generated:** {timestamp}",
        f"**Provider:** {context.provider}",
        f"**Trigger:** {context.trigger_event}",
        f"**Tool restrictions:** {', '.join(context.tool_restrictions) or 'none'}",
        f"**persist-credentials:** {context.has_persist_credentials}",
        "",
        "---",
        "",
        "## Reconstructed Agent Prompt",
        "```",
        context.reconstructed_prompt[:2000],
        "```" if len(context.reconstructed_prompt) <= 2000 else "```\n*(truncated)*",
        "",
        "---",
        "",
        "## Summary",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Hypotheses generated | {len(results) + len(discarded)} |",
        f"| Filtered (pre-pass + LLM ranker) | {len(discarded)} |",
        f"| Live-validated | {len(results)} |",
        f"| **Confirmed** | **{len(confirmed)}** |",
        f"| Unconfirmed | {len(unconfirmed)} |",
        f"| Skipped (dry-run) | {len(skipped)} |",
        "",
    ]

    if confirmed:
        md_lines += [
            "---",
            "",
            "## Confirmed Vulnerabilities",
            "",
        ]
        for r in confirmed:
            h = r.hypothesis
            tags = ", ".join(f"`{t}`" for t in h.tags) if h.tags else "—"
            md_lines += [
                f"### {_severity_badge(h.severity)} `{h.id}` — {h.mitre_category}",
                f"**Tags:** {tags}  ",
                f"**Attack goal:** {h.attack_goal}  ",
                f"**Recipe:** {r.payload_used}  ",
                f"**Success rate:** {r.success_rate}  ",
                f"**Found in iteration:** {r.iteration}  ",
                f"**Mitigation:** {r.suggested_mitigation}",
                "",
                "**Reproduction:**",
                "```bash",
                f"uv run python -m src.benchmark.cli run --workflow {context.workflow_id} --scenario {h.id}",
                "```",
                "",
            ]

    if unconfirmed:
        md_lines += [
            "---",
            "",
            "## Unconfirmed Hypotheses",
            "",
            "| ID | Category | Recipe | Goal | Failure reason |",
            "|----|----------|--------|------|----------------|",
        ]
        for r in unconfirmed:
            h = r.hypothesis
            md_lines.append(
                f"| `{h.id}` | {h.mitre_category} | {r.payload_used} "
                f"| {h.attack_goal[:60]} | {r.failure_reason or 'unknown'} |"
            )
        md_lines.append("")

    if discarded:
        md_lines += [
            "---",
            "",
            "## Filtered Hypotheses",
            "",
            "| ID | Category | Goal | Filter reason |",
            "|----|----------|------|---------------|",
        ]
        for h, reason in discarded:
            md_lines.append(f"| `{h.id}` | {h.mitre_category} | {h.attack_goal[:60]} | {reason} |")
        md_lines.append("")

    if baseline_findings:
        md_lines += [
            "---",
            "",
            "## Baseline Tool Findings",
            "",
        ]
        by_tool: dict[str, list[dict]] = {}
        for f in baseline_findings:
            by_tool.setdefault(f.get("tool", "unknown"), []).append(f)
        for tool, findings in by_tool.items():
            md_lines += [f"### {tool} ({len(findings)} findings)", ""]
            for f in findings:
                if "error" in f:
                    md_lines.append(f"- ⚠️  {f['error']}")
                else:
                    sev = f.get("severity", "?")
                    rule = f.get("rule", "?")
                    msg = f.get("message", "")
                    loc = f.get("location", "")
                    md_lines.append(f"- **{sev}** [{rule}] {msg} — `{loc}`")
            md_lines.append("")

    md_lines += [
        "---",
        "",
        "## Cost Summary",
        "",
        "| Item | Value |",
        "|------|-------|",
        f"| Scanner input tokens | {scan_cost.total_input_tokens:,} |",
        f"| Scanner output tokens | {scan_cost.total_output_tokens:,} |",
        f"| Estimated scanner API cost | ${scan_cost.total_usd:.4f} |",
        f"| GitHub Actions billable minutes | {total_minutes:.2f} |",
        f"| Wall-clock seconds | {total_wall:.1f} |",
        "",
    ]
    if scan_cost.token_usage_by_model:
        md_lines += [
            "### Per-model token usage",
            "",
            "| Model | Input tokens | Output tokens | Cost (USD) | Priced? |",
            "|-------|--------------|---------------|------------|---------|",
        ]
        for model, t in sorted(scan_cost.token_usage_by_model.items()):
            in_tok = t.get("input", 0)
            out_tok = t.get("output", 0)
            priced = model in MODEL_PRICING
            in_price, out_price = MODEL_PRICING.get(model, (0.0, 0.0))
            cost_usd = (in_tok * in_price + out_tok * out_price) / 1_000_000
            md_lines.append(
                f"| `{model}` | {in_tok:,} | {out_tok:,} | "
                f"${cost_usd:.4f} | {'yes' if priced else '**no — update MODEL_PRICING**'} |"
            )
        md_lines.append("")

    md_content = "\n".join(md_lines)
    md_path = os.path.join(output_dir, f"{context.workflow_id}.md")
    with open(md_path, "w") as f:
        f.write(md_content)

    json_data = {
        "timestamp": timestamp,
        "workflow_id": context.workflow_id,
        "provider": context.provider,
        "trigger_event": context.trigger_event,
        "tool_restrictions": context.tool_restrictions,
        "has_persist_credentials": context.has_persist_credentials,
        "confirmed": [_result_to_dict(r) for r in confirmed],
        "unconfirmed": [_result_to_dict(r) for r in unconfirmed],
        "filtered": [{"id": h.id, "reason": reason} for h, reason in discarded],
        "baselines": baseline_findings,
        "cost": {
            "input_tokens": scan_cost.total_input_tokens,
            "output_tokens": scan_cost.total_output_tokens,
            "estimated_usd": scan_cost.total_usd,
            "billable_minutes": total_minutes,
            "wall_seconds": total_wall,
            "token_usage_by_model": scan_cost.token_usage_by_model,
        },
    }

    json_path = os.path.join(output_dir, f"{context.workflow_id}.json")
    with open(json_path, "w") as f:
        json.dump(json_data, f, indent=2)

    return md_path, json_path


def _result_to_dict(r: ValidationResult) -> dict:
    return {
        "id": r.hypothesis.id,
        "mitre_category": r.hypothesis.mitre_category,
        "tags": r.hypothesis.tags,
        "recipe_summary": r.payload_used,
        "attack_goal": r.hypothesis.attack_goal,
        "severity": r.hypothesis.severity,
        "success_rate": r.success_rate,
        "iteration": r.iteration,
        "run_ids": r.run_ids,
        "suggested_mitigation": r.suggested_mitigation,
        "failure_reason": r.failure_reason,
        "wall_seconds": r.wall_seconds,
    }
