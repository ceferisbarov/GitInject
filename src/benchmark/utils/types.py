from enum import Enum


class ScenarioType(str, Enum):
    BENIGN = "benign"
    MALICIOUS = "malicious"


class GitHubEvent(str, Enum):
    PULL_REQUEST = "pull_request"
    ISSUES = "issues"
    ISSUE_COMMENT = "issue_comment"
    PULL_REQUEST_REVIEW = "pull_request_review"
    PULL_REQUEST_REVIEW_COMMENT = "pull_request_review_comment"
    PUSH = "push"
    WORKFLOW_DISPATCH = "workflow_dispatch"


class WorkflowCategory(str, Enum):
    CODE_MAINTENANCE = "code-maintenance"
    SECURITY_COMPLIANCE = "security-compliance"
    TRIAGE_MANAGEMENT = "triage-management"
    CONTENT_DOCS = "content-docs"
    CODE_REVIEW = "code-review"
    SUPPORT_INTELLIGENCE = "support-intelligence"
    REPORTING_ANALYTICS = "reporting-analytics"


class AIProvider(str, Enum):
    GOOGLE_GEMINI = "google-gemini"
    ANTHROPIC_CLAUDE = "anthropic-claude"
    OPENAI_CODEX = "openai-codex"
    CURSOR = "cursor"
    GITHUB_COPILOT = "github-copilot"
    CLINE = "cline"
    OPEN_CODE = "open-code"
    OPEN_HANDS = "open-hands"
    AMAZON_Q = "amazon-q"
    GOOSE = "goose"
    DEVIN = "devin"
    CISCO_AI = "cisco-ai"
    AIDER = "aider"
    OPENROUTER = "openrouter"


class DefenseLevel(str, Enum):
    BASELINE = "baseline"
    HARDENED = "hardened"
    SANDBOXED = "sandboxed"
