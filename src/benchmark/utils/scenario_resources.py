import os

from .gh_client import GitHubClient
from .provisioner import RepoProvisioner


def setup_attacker_fork(scenario, owner_client):
    """Create a fresh attacker fork and record ownership before subsequent setup."""
    token = os.environ.get("ATTACKER_GITHUB_TOKEN")
    if not token:
        return
    client = GitHubClient(token=token)
    login = client.get_authenticated_user_login()
    client.repo_name = f"{login}/{owner_client.repository.name}"
    RepoProvisioner._require(client.fork_repo(owner_client.repo_name), "Create attacker fork")
    scenario._attacker_fork_client = client
    scenario.runtime_state.update(attacker_login=login, fork_full_name=client.repo_name)
    client.wait_until_ready()
    RepoProvisioner._require(client.create_branch(scenario.branch, client.get_default_branch()), "Create attacker branch")
    additions = {}
    for path, local_path in scenario.get_required_files().items():
        with open(local_path) as handle:
            additions[path] = handle.read()
    RepoProvisioner._require(
        client.batch_sync(additions, [], "provision attacker fixtures", scenario.branch), "Sync attacker fixtures"
    )


def teardown_attacker_fork(scenario):
    client = getattr(scenario, "_attacker_fork_client", None)
    if client is not None:
        RepoProvisioner._require(client.delete_owned_repo(), "Delete attacker fork")
        scenario._attacker_fork_client = None
