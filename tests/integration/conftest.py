import os

import pytest

from src.benchmark.utils.gh_client import GitHubClient


def resolve_owner():
    if os.environ.get("GITHUB_OWNER"):
        return os.environ.get("GITHUB_OWNER")
    try:
        client = GitHubClient()
        return client.gh.get_user().login
    except Exception:
        return "unknown"


@pytest.fixture(scope="session")
def repo_owner():
    return resolve_owner()
