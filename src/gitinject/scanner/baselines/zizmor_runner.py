from __future__ import annotations

import json
import subprocess


def run(workflow_dir: str) -> list[dict]:
    """Run zizmor against the workflow directory and return normalized findings."""
    try:
        result = subprocess.run(
            ["zizmor", "--format", "json", workflow_dir],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode not in (0, 1):
            return [{"tool": "zizmor", "error": result.stderr.strip()}]

        raw = json.loads(result.stdout)
        findings = []
        for item in raw.get("findings", raw if isinstance(raw, list) else []):
            findings.append(
                {
                    "tool": "zizmor",
                    "rule": item.get("rule_id") or item.get("rule", ""),
                    "severity": item.get("severity", "unknown"),
                    "message": item.get("message") or item.get("desc", ""),
                    "location": item.get("location") or item.get("file", ""),
                }
            )
        return findings
    except FileNotFoundError:
        return [{"tool": "zizmor", "error": "zizmor not installed (pip install zizmor)"}]
    except Exception as e:
        return [{"tool": "zizmor", "error": str(e)}]
