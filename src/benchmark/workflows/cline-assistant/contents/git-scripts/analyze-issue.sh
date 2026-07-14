#!/bin/bash
# Analyze a GitHub issue using Cline CLI

if [ -z "$1" ]; then
    echo "Usage: $0 <github-issue-url> [prompt] [address]"
    echo "Example: $0 https://github.com/owner/repo/issues/123"
    echo "Example: $0 https://github.com/owner/repo/issues/123 'What is the root cause of this issue?'"
    echo "Example: $0 https://github.com/owner/repo/issues/123 'What is the root cause of this issue?' 127.0.0.1:46529"
    exit 1
fi

# Gather the args
ISSUE_URL="$1"
PROMPT="${2:-What is the root cause of this issue?}"
if [ -n "$3" ]; then
    ADDRESS="--address $3"
fi

# Fetch the actual issue contents first so Cline analyzes repository data directly
# instead of relying on web access to the GitHub issue URL.
ISSUE_JSON="$(gh issue view "$ISSUE_URL" --json number,title,body,comments,url)"
ISSUE_CONTEXT="$(
    printf '%s' "$ISSUE_JSON" | jq -r '
        "Issue URL: \(.url)\n" +
        "Issue #\(.number): \(.title)\n\n" +
        "Body:\n\(.body // "")\n\n" +
        (
            if (.comments | length) > 0 then
                "Comments:\n" +
                (.comments | map("- " + (.body // "")) | join("\n\n"))
            else
                "Comments:\n(none)"
            end
        )
    '
)"

# Ask Cline for its analysis, showing only the final completion text.
# Cline CLI 2.x removed `--mode act`; `-y` runs headless in autonomous mode.
printf '%s\n' "$ISSUE_CONTEXT" | cline -y --json "$PROMPT" $ADDRESS | \
    sed -n '/^{/,$p' | \
    jq -r 'select(.say == "completion_result") | .text' | \
    sed 's/\\n/\n/g'
