import json
import os
import tempfile


class GitHubEventSimulator:
    """Simulates GitHub event payloads for local benchmark testing."""

    def __init__(self, workspace_dir):
        self.workspace_dir = workspace_dir

    def create_event_payload(self, event_type, data):
        """Creates a GitHub event payload file and returns its path."""
        payload = {}

        if event_type == "pull_request":
            payload = self._generate_pull_request_payload(data)
        elif event_type == "issue":
            payload = self._generate_issue_payload(data)
        elif event_type == "issue_comment":
            payload = self._generate_issue_comment_payload(data)
        else:
            payload = data  # Use raw data if type is unknown

        fd, path = tempfile.mkstemp(
            suffix=".json", prefix=f"github_event_{event_type}_"
        )
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f)

        return path

    def _generate_pull_request_payload(self, data):
        return {
            "action": data.get("action", "opened"),
            "number": data.get("number", 1),
            "pull_request": {
                "number": data.get("number", 1),
                "title": data.get("title", "Test PR"),
                "body": data.get("body", "Test PR body"),
                "user": {"login": data.get("user", "test-user")},
                "head": {
                    "ref": data.get("head_ref", "feature-branch"),
                    "sha": data.get("head_sha", "abc1234"),
                },
                "base": {
                    "ref": data.get("base_ref", "main"),
                    "sha": data.get("base_sha", "def5678"),
                },
            },
            "repository": {
                "full_name": data.get("repo", "owner/repo"),
                "name": data.get("repo_name", "repo"),
                "owner": {"login": data.get("repo_owner", "owner")},
            },
        }

    def _generate_issue_payload(self, data):
        return {
            "action": data.get("action", "opened"),
            "issue": {
                "number": data.get("number", 1),
                "title": data.get("title", "Test Issue"),
                "body": data.get("body", "Test Issue body"),
                "user": {"login": data.get("user", "test-user")},
            },
            "repository": {
                "full_name": data.get("repo", "owner/repo"),
                "name": data.get("repo_name", "repo"),
                "owner": {"login": data.get("repo_owner", "owner")},
            },
        }

    def _generate_issue_comment_payload(self, data):
        return {
            "action": data.get("action", "created"),
            "issue": {
                "number": data.get("number", 1),
                "title": data.get("title", "Test Issue"),
            },
            "comment": {
                "id": data.get("comment_id", 123),
                "body": data.get("body", "Test comment body"),
                "user": {"login": data.get("user", "test-user")},
            },
            "repository": {
                "full_name": data.get("repo", "owner/repo"),
            },
        }
