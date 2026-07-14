#!/usr/bin/env bash
#
# Run the 11 named GitInject attacks (paper Table 6) against their target
# workflows. Each pair provisions an ephemeral repo, triggers the real workflow,
# evaluates via the GitHub API, and cleans up.
#
# Usage:
#   ./scripts/run_paper_scenarios.sh                       # all 11, once each
#   REPEAT=5 ./scripts/run_paper_scenarios.sh              # 5 runs each (as in the paper)
#   ./scripts/run_paper_scenarios.sh codex-pr-review pr_token_exfiltration_via_git_config
#
# Credentials (GITHUB_TOKEN + the provider keys you need) are read from
# references/run.sh, which is gitignored — create it from your own account.
set -euo pipefail

cd "$(dirname "$0")/.."
[ -f references/run.sh ] && source references/run.sh

REPEAT="${REPEAT:-1}"

# workflow:scenario pairs, in paper Table 6 order
PAIRS=(
  "codex-pr-review:pr_token_exfiltration_via_git_config"    # pr_body_github_token_exfiltration
  "claude-pr-review:claude_md_instructions_injection"       # claude_md_token_exfiltration
  "codex-pr-review:codex_agents_md_injection"               # agents_md_token_exfiltration
  "gemini-assistant:gemini_md_instructions_injection"       # gemini_md_token_exfiltration
  "claude-pr-review:supply_chain_malicious_code"            # claude_md_approval_manipulation
  "codex-pr-review:agents_md_approval_manipulation"         # agents_md_approval_manipulation
  "gemini-assistant:gemini_md_approval_manipulation"        # gemini_md_approval_manipulation
  "codex-pr-review:unauthorized_pr_approval"                # pr_body_approval_manipulation
  "gemini-assistant:issue_onboarding_secret_exfiltration"   # issue_body_github_token_exfiltration
  "cline-assistant:cline_issue_body_injection"              # issue_body_reconnaissance
  "claude-pr-review:dos_request_flood"                      # denial_of_wallet
)

# Optionally run a single "workflow scenario" pair passed as arguments.
if [ "$#" -eq 2 ]; then
  PAIRS=("$1:$2")
fi

fail=0
for pair in "${PAIRS[@]}"; do
  wf="${pair%%:*}"
  sc="${pair##*:}"
  echo "=== ${wf}  x  ${sc}  (repeat=${REPEAT}) ==="
  if ! uv run python -m src.benchmark.cli run --workflow "$wf" --scenario "$sc" --repeat "$REPEAT"; then
    echo "FAILED: ${wf} x ${sc}"
    fail=1
  fi
done

exit "$fail"
