from unittest.mock import MagicMock

import pytest

from src.benchmark.utils.provisioner import RepoProvisioner


@pytest.fixture
def mock_gh_client():
    client = MagicMock()
    # Default behavior: repo exists, default branch is main, not empty
    client.get_repo_info.return_value = {
        "defaultBranchRef": {"name": "main"},
        "isEmpty": False,
        "name": "repo",
        "owner": "test",
    }
    client.get_default_branch.return_value = "main"
    client.repo_name = "test/repo"
    client.create_repo.return_value = (True, "")
    client.fork_repo.return_value = (True, "")
    client.delete_repo.return_value = (True, "")
    client.put_file.return_value = (True, "")
    client.batch_sync.return_value = (True, "")
    client.list_files.return_value = []
    return client


def test_provision_basic(mock_gh_client, tmp_path):
    # Create a directory for the workflow
    workflow_dir = tmp_path / "test-workflow-dir"
    workflow_dir.mkdir()
    workflow_file = workflow_dir / "workflow.yml"
    workflow_file.write_text("workflow content")

    provisioner = RepoProvisioner(mock_gh_client)
    provisioner.provision(workflow_dir=str(workflow_dir))

    # Check if batch_sync was called for workflows
    mock_gh_client.batch_sync.assert_called_once()
    args, kwargs = mock_gh_client.batch_sync.call_args
    assert ".github/workflows/workflow.yml" in args[0]
    assert args[0][".github/workflows/workflow.yml"] == "workflow content"
    assert args[3] == "main"


def test_provision_standard_structure(mock_gh_client, tmp_path):
    # Create a directory for the workflow with standard structure
    workflow_dir = tmp_path / "standard-workflow"
    workflow_dir.mkdir()

    contents_dir = workflow_dir / "contents"
    contents_dir.mkdir()

    # Add a workflow file
    workflows_dir = contents_dir / ".github" / "workflows"
    workflows_dir.mkdir(parents=True)
    main_yml = workflows_dir / "main.yml"
    main_yml.write_text("main workflow content")

    # Add a script
    scripts_dir = contents_dir / "scripts"
    scripts_dir.mkdir()
    test_sh = scripts_dir / "test.sh"
    test_sh.write_text("echo hello")

    # Add a root file
    readme = contents_dir / "README.md"
    readme.write_text("repo readme")

    provisioner = RepoProvisioner(mock_gh_client)
    provisioner.provision(workflow_dir=str(workflow_dir))

    # We expect 1 call to batch_sync for the workflows and contents on default branch
    mock_gh_client.batch_sync.assert_called_once()
    args, _ = mock_gh_client.batch_sync.call_args
    additions = args[0]

    assert ".github/workflows/main.yml" in additions
    assert "scripts/test.sh" in additions
    assert "README.md" in additions
    assert additions[".github/workflows/main.yml"] == "main workflow content"


def test_provision_with_files(mock_gh_client, tmp_path):
    # Create an empty workflow dir to satisfy the provisioner
    workflow_dir = tmp_path / "empty-workflow"
    workflow_dir.mkdir()

    provisioner = RepoProvisioner(mock_gh_client)
    required_files = {"file.txt": "content"}

    provisioner.provision(workflow_dir=str(workflow_dir), required_files=required_files)

    # Check if batch_sync was called twice: once for workflows (clearing), once for scenario files
    assert mock_gh_client.batch_sync.call_count == 2

    # Check scenario files sync
    args, kwargs = mock_gh_client.batch_sync.call_args
    assert args[0] == {"file.txt": "content"}
    assert args[3] == "main"


def test_provision_new_branch(mock_gh_client, tmp_path):
    # Create an empty workflow dir
    workflow_dir = tmp_path / "empty-workflow"
    workflow_dir.mkdir()

    # Branch doesn't exist initially
    mock_gh_client.get_branch_info.return_value = {}
    mock_gh_client.create_branch.return_value = (True, "")

    provisioner = RepoProvisioner(mock_gh_client)
    required_files = {"test.txt": "data"}
    provisioner.provision(workflow_dir=str(workflow_dir), required_files=required_files, branch="feature")

    # Verify branch creation
    mock_gh_client.create_branch.assert_called_once_with("feature", "main")

    # Verify batch_sync was called twice
    assert mock_gh_client.batch_sync.call_count == 2

    # Verify second batch_sync for scenario files went to feature branch
    args, kwargs = mock_gh_client.batch_sync.call_args
    assert args[0] == {"test.txt": "data"}
    assert args[3] == "feature"


def test_provision_create_repo(mock_gh_client, tmp_path):
    # Create an empty workflow dir
    workflow_dir = tmp_path / "empty-workflow"
    workflow_dir.mkdir()

    # Repo doesn't exist
    mock_gh_client.get_repo_info.side_effect = [
        None,
        {"defaultBranchRef": {"name": "main"}, "isEmpty": False},
        {"defaultBranchRef": {"name": "main"}, "isEmpty": False},
        {"defaultBranchRef": {"name": "main"}, "isEmpty": False},
    ]
    mock_gh_client.create_repo.return_value = (True, "")

    provisioner = RepoProvisioner(mock_gh_client)
    provisioner.provision(workflow_dir=str(workflow_dir))

    mock_gh_client.create_repo.assert_called_once()
    # Should still have put README.md as initial commit via put_file for now
    mock_gh_client.put_file.assert_any_call(
        "README.md",
        "# Benchmark Repository\nGenerated by AI Benchmark Suite.",
        "initial commit",
        "main",
    )


def test_provision_empty_repo(mock_gh_client, tmp_path):
    # Create an empty workflow dir
    workflow_dir = tmp_path / "empty-workflow"
    workflow_dir.mkdir()

    # Repo exists but is empty
    mock_gh_client.get_repo_info.side_effect = [
        {"isEmpty": True, "defaultBranchRef": {"name": "main"}},
        {"isEmpty": False, "defaultBranchRef": {"name": "main"}},
    ]

    provisioner = RepoProvisioner(mock_gh_client)
    provisioner.provision(workflow_dir=str(workflow_dir))

    # Should have put README.md
    mock_gh_client.put_file.assert_any_call(
        "README.md",
        "# Benchmark Repository\nGenerated by AI Benchmark Suite.",
        "initial commit",
        "main",
    )


def test_provision_fork_repo(mock_gh_client, tmp_path):
    # Create an empty workflow dir
    workflow_dir = tmp_path / "empty-workflow"
    workflow_dir.mkdir()

    # Repo doesn't exist initially
    mock_gh_client.get_repo_info.side_effect = [
        None,
        {"defaultBranchRef": {"name": "main"}, "isEmpty": False},
        {"defaultBranchRef": {"name": "main"}, "isEmpty": False},
        {"defaultBranchRef": {"name": "main"}, "isEmpty": False},
    ]

    provisioner = RepoProvisioner(mock_gh_client)
    provisioner.provision(workflow_dir=str(workflow_dir), template_repo="source/template")

    mock_gh_client.fork_repo.assert_called_once_with("source/template")
    # Should NOT have put README.md as fork should already have content
    for call in mock_gh_client.put_file.call_args_list:
        assert call[0][0] != "README.md"


def test_teardown(mock_gh_client):
    provisioner = RepoProvisioner(mock_gh_client)
    provisioner.teardown()

    mock_gh_client.delete_repo.assert_called_once()
