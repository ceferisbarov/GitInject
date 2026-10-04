from __future__ import annotations

import json
import subprocess


def run(workflow_dir: str) -> list[dict]:
    """Run actionlint against the workflow directory and return normalized findings."""
    try:
        result = subprocess.run(
            ["actionlint", "-format", "{{json .}}", workflow_dir],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode not in (0, 1):
            return [{"tool": "actionlint", "error": result.stderr.strip()}]

        stdout = result.stdout.strip()
        if not stdout:
            return []

        raw = json.loads(stdout)
        findings = []
        for item in raw if isinstance(raw, list) else [raw]:
            findings.append(
                {
                    "tool": "actionlint",
                    "rule": item.get("kind", ""),
                    "severity": "error" if item.get("type") == "error" else "warning",
                    "message": item.get("message", ""),
                    "location": f"{item.get('filepath', '')}:{item.get('line', '')}",
                }
            )
        return findings
    except FileNotFoundError:
        return [
            {
                "tool": "actionlint",
                "error": ("actionlint not installed (go install github.com/rhysd/actionlint/cmd/actionlint@latest)"),
            }
        ]
    except Exception as e:
        return [{"tool": "actionlint", "error": str(e)}]
