from unittest.mock import MagicMock, patch

import pytest
from github import GithubException

from src.benchmark.utils.gh_client import GitHubClient


@pytest.fixture
def mock_github():
    with patch("src.benchmark.utils.gh_client.Github") as mock:
        # Mock the token retrieval to avoid subprocess calls during init
        with patch("src.benchmark.utils.gh_client.GitHubClient._get_token", return_value="fake-token"):
            yield mock


def test_gh_client_get_repo_info(mock_github):
    client = GitHubClient(repo="test/repo")
    mock_repo = MagicMock()
    mock_repo.name = "repo"
    mock_repo.owner.login = "test"
    mock_repo.default_branch = "main"
    mock_repo.size = 100
    mock_github.return_value.get_repo.return_value = mock_repo

    info = client.get_repo_info()

    assert info["name"] == "repo"
    assert info["owner"]["login"] == "test"
    assert info["defaultBranchRef"]["name"] == "main"
    assert info["isEmpty"] is False
    mock_github.return_value.get_repo.assert_called_with("test/repo")


def test_gh_client_create_repo(mock_github):
    client = GitHubClient(repo="test/repo")
    mock_user = MagicMock()
    mock_user.login = "test"
    mock_github.return_value.get_user.return_value = mock_user

    success, err = client.create_repo(public=True)

    assert success is True
    # create_repo is called on the user/org, and we extract name from self.repo_name
    mock_user.create_repo.assert_called_with("repo", private=False)


def test_gh_client_get_branch_info(mock_github):
    client = GitHubClient(repo="test/repo")
    mock_repo = MagicMock()
    mock_branch = MagicMock()
    mock_branch.name = "main"
    mock_branch.commit.sha = "abc123"
    mock_repo.get_branch.return_value = mock_branch
    mock_github.return_value.get_repo.return_value = mock_repo

    info = client.get_branch_info("main")

    assert info["name"] == "main"
    assert info["commit"]["sha"] == "abc123"
    mock_repo.get_branch.assert_called_with("main")


def test_gh_client_create_branch(mock_github):
    client = GitHubClient(repo="test/repo")
    mock_repo = MagicMock()
    mock_repo.default_branch = "main"
    mock_branch = MagicMock()
    mock_branch.commit.sha = "abc123"
    mock_repo.get_branch.return_value = mock_branch
    mock_github.return_value.get_repo.return_value = mock_repo

    success, err = client.create_branch("new-feature")

    assert success is True
    mock_repo.create_git_ref.assert_called_with(ref="refs/heads/new-feature", sha="abc123")


def test_gh_client_put_file_create(mock_github):
    client = GitHubClient(repo="test/repo")
    mock_repo = MagicMock()
    mock_repo.default_branch = "main"
    # Mock file not existing (get_contents raises 404)
    mock_repo.get_contents.side_effect = GithubException(404, {"message": "Not Found"}, {})
    mock_github.return_value.get_repo.return_value = mock_repo

    success, err = client.put_file("test.txt", "hello world", "commit msg", branch="main")

    assert success is True
    mock_repo.create_file.assert_called_with("test.txt", "commit msg", "hello world", branch="main")


def test_gh_client_put_file_update(mock_github):
    client = GitHubClient(repo="test/repo")
    mock_repo = MagicMock()
    mock_repo.default_branch = "main"
    mock_content = MagicMock()
    mock_content.sha = "old-sha"
    mock_repo.get_contents.return_value = mock_content
    mock_github.return_value.get_repo.return_value = mock_repo

    success, err = client.put_file("test.txt", "new content", "update msg", branch="main")

    assert success is True
    mock_repo.update_file.assert_called_with("test.txt", "update msg", "new content", "old-sha", branch="main")


def test_gh_client_get_pr_details(mock_github):
    client = GitHubClient(repo="test/repo")
    mock_repo = MagicMock()
    mock_pr = MagicMock()
    mock_pr.title = "Fix bug"
    mock_pr.body = "Fixed it."
    mock_pr.state = "open"

    mock_issue_comment = MagicMock()
    mock_issue_comment.body = "LGTM"
    mock_pr.get_issue_comments.return_value = [mock_issue_comment]

    mock_review = MagicMock()
    mock_review.body = "Good progress"
    mock_pr.get_reviews.return_value = [mock_review]

    mock_review_comment = MagicMock()
    mock_review_comment.body = "Small typo here"
    mock_pr.get_review_comments.return_value = [mock_review_comment]

    mock_repo.get_pull.return_value = mock_pr
    mock_github.return_value.get_repo.return_value = mock_repo

    details = client.get_pr_details(42)

    assert details["title"] == "Fix bug"
    assert details["body"] == "Fixed it."
    assert "LGTM" in details["comments"]
    assert "Good progress" in details["comments"]
    assert "Small typo here" in details["comments"]
    mock_repo.get_pull.assert_called_with(42)


def test_gh_client_fork_repo(mock_github):
    client = GitHubClient(repo="my-user/new-repo")
    mock_template_repo = MagicMock()
    mock_github.return_value.get_repo.return_value = mock_template_repo
    mock_user = MagicMock()
    mock_user.login = "my-user"
    mock_github.return_value.get_user.return_value = mock_user

    success, err = client.fork_repo("source/template")

    assert success is True
    mock_template_repo.create_fork.assert_called_with(name="new-repo", default_branch_only=True)


def test_gh_client_delete_repo(mock_github):
    client = GitHubClient(repo="test/repo")
    mock_repo = MagicMock()
    mock_github.return_value.get_repo.return_value = mock_repo

    success, err = client.delete_repo()

    assert success is True
    mock_repo.delete.assert_called_once()


def test_gh_client_batch_sync(mock_github):
    client = GitHubClient(repo="test/repo")
    mock_repo = MagicMock()
    mock_repo.default_branch = "main"
    mock_github.return_value.get_repo.return_value = mock_repo

    mock_ref = MagicMock()
    mock_repo.get_git_ref.return_value = mock_ref

    mock_old_commit = MagicMock()
    mock_repo.get_git_commit.return_value = mock_old_commit

    mock_tree = MagicMock()
    mock_item = MagicMock()
    mock_item.path = ".github/workflows/old.yml"
    mock_item.type = "blob"
    mock_item.mode = "100644"
    mock_item.sha = "old-sha"
    mock_tree.tree = [mock_item]
    mock_repo.get_git_tree.return_value = mock_tree

    mock_new_tree = MagicMock()
    mock_repo.create_git_tree.return_value = mock_new_tree

    mock_new_commit = MagicMock()
    mock_new_commit.sha = "new-sha"
    mock_repo.create_git_commit.return_value = mock_new_commit

    additions = {".github/workflows/new.yml": "new content"}
    deletions = [".github/workflows/old.yml"]

    success, err = client.batch_sync(additions, deletions, "batch commit", branch="main")

    assert success is True
    # Verify create_git_tree was called with the new element
    args, kwargs = mock_repo.create_git_tree.call_args
    elements = args[0]
    assert len(elements) == 1
    # InputGitTreeElement stores attributes as _InputGitTreeElement__path etc. in some versions
    # or just path. We can check if it's there.
    element = elements[0]
    found_path = getattr(element, "path", None) or getattr(element, "_InputGitTreeElement__path", None)
    assert found_path == ".github/workflows/new.yml"

    mock_repo.create_git_commit.assert_called_once()
    mock_ref.edit.assert_called_with("new-sha")
