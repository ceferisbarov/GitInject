import importlib.util
import json
import os
import random
import string
import time

import click

from .scenario_base import AbstractScenario
from .utils.gl_client import GitLabClient
from .utils.gl_provisioner import GitLabProvisioner


class GitLabRunner:
    """Orchestrates a benchmark run on a real GitLab project."""

    def __init__(self, workspace_dir: str, project_prefix: str = "benchmark-run"):
        self.workspace_dir = workspace_dir
        self.project_prefix = project_prefix
        self.gl_client = GitLabClient()
        self.project_name = self._generate_project_name(project_prefix)

    def _generate_project_name(self, prefix: str) -> str:
        base = prefix.split("/")[-1] if "/" in prefix else prefix
        suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
        return f"{base}-{suffix}"

    def run(self, workflow_id: str, scenario_id: str, cleanup: bool = True) -> dict:
        workflow_dir = os.path.join(self.workspace_dir, "src/benchmark/workflows", workflow_id)
        scenario_path = self._find_scenario_path(scenario_id)

        if not os.path.exists(workflow_dir):
            return {"error": f"Workflow directory not found: {workflow_id}"}
        if not scenario_path:
            return {"error": f"Scenario not found: {scenario_id}"}

        meta_path = os.path.join(workflow_dir, "metadata.json")
        workflow_meta: dict = {}
        if os.path.exists(meta_path):
            with open(meta_path) as f:
                workflow_meta = json.load(f)

        scenario = self._load_scenario(scenario_path)
        if not scenario:
            return {"error": f"Failed to load scenario: {scenario_id}"}

        provisioner = GitLabProvisioner(self.gl_client)

        try:
            # Collect CI/CD variables from environment
            required_secrets = workflow_meta.get("required_secrets", [])
            variables: dict[str, str] = {k: v for k in required_secrets if (v := os.environ.get(k))}
            variables.update(scenario.get_secrets())

            target_branch = getattr(scenario, "branch", None)

            click.echo(f"Provisioning GitLab project {self.project_name}...")
            provisioner.provision(
                self.project_name,
                workflow_dir,
                required_files=scenario.get_required_files(),
                branch=target_branch,
                variables=variables,
            )

            click.echo("Setting up scenario state...")
            scenario.setup_state(self.gl_client)

            timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            runs_dir = os.path.join(self.workspace_dir, "runs", timestamp.replace(":", "-"))
            os.makedirs(runs_dir, exist_ok=True)

            click.echo("Triggering GitLab event (creating MR)...")
            event = scenario.get_event()
            data = event.get("data", {})
            mr_iid = self.gl_client.create_merge_request(
                source_branch=data["source_branch"],
                target_branch=data.get("target_branch", self.gl_client.get_default_branch()),
                title=data.get("title", "Benchmark MR"),
                description=data.get("description", ""),
            )
            scenario.runtime_state["mr_iid"] = mr_iid
            click.echo(f"MR !{mr_iid} created: {self.gl_client.get_project_url()}/-/merge_requests/{mr_iid}")

            click.echo("Waiting for MR pipeline to appear...")
            pipeline_id = self._wait_for_mr_pipeline(mr_iid, timeout_s=120)
            if not pipeline_id:
                return {"error": "No pipeline appeared for the MR within timeout."}

            click.echo(f"Pipeline {pipeline_id} found. Waiting for completion...")
            final_status = self.gl_client.wait_for_pipeline(pipeline_id, timeout_s=600)
            click.echo(f"Pipeline finished: {final_status}")

            run_result = {
                "status": "completed" if final_status in ("success", "failed") else final_status,
                "conclusion": final_status,
                "stdout": "",
                "stderr": "",
            }

            click.echo("Evaluating results...")
            utility = scenario.get_utility_evaluator().evaluate(run_result, self.gl_client, scenario)
            security = scenario.get_security_evaluator().evaluate(run_result, self.gl_client, scenario)

            analysis = {
                "utility_achieved": utility,
                "security_breached": security,
                "autonomy_achieved": final_status == "success",
            }

            result = {
                "workflow": workflow_id,
                "scenario": scenario_id,
                "platform": "gitlab",
                "analysis": analysis,
                "project": self.project_name,
                "project_url": self.gl_client.get_project_url(),
                "mr_iid": mr_iid,
                "pipeline_id": pipeline_id,
                "pipeline_status": final_status,
                "timestamp": timestamp,
            }

            with open(os.path.join(runs_dir, "metadata.json"), "w") as f:
                json.dump(result, f, indent=4)
            click.echo(f"Run results saved to: {runs_dir}")

            self._print_summary(analysis)
            return result

        finally:
            if cleanup:
                click.echo("Tearing down scenario state...")
                scenario.teardown_state(self.gl_client)
                provisioner.teardown()
            else:
                click.echo(click.style(f"SKIP CLEANUP: project '{self.project_name}' remains active.", fg="yellow"))

    def _wait_for_mr_pipeline(self, mr_iid: int, timeout_s: int = 120, poll_interval: int = 10) -> int | None:
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            pipelines = self.gl_client.get_mr_pipelines(mr_iid)
            if pipelines:
                return pipelines[0].id
            click.echo("  No pipeline yet, waiting...")
            time.sleep(poll_interval)
        return None

    def _print_summary(self, analysis: dict) -> None:
        utility = click.style("PASS", fg="green") if analysis["utility_achieved"] else click.style("FAIL", fg="red")
        security = click.style("BREACHED", fg="red") if analysis["security_breached"] else click.style("SAFE", fg="green")
        click.echo(click.style("\n--- Results ---", bold=True))
        click.echo(f"  Utility:  {utility}")
        click.echo(f"  Security: {security}")

    def _find_scenario_path(self, scenario_id: str) -> str | None:
        scenarios_dir = os.path.join(self.workspace_dir, "src/benchmark/scenarios")
        for root, dirs, files in os.walk(scenarios_dir):
            if scenario_id in dirs:
                path = os.path.join(root, scenario_id)
                if os.path.exists(os.path.join(path, "scenario.py")):
                    return path
            if f"{scenario_id}.py" in files:
                return os.path.join(root, f"{scenario_id}.py")
        return None

    def _load_scenario(self, scenario_path: str) -> AbstractScenario | None:
        if os.path.isdir(scenario_path):
            scenario_dir = scenario_path
            scenario_file = os.path.join(scenario_path, "scenario.py")
        else:
            scenario_dir = os.path.dirname(scenario_path)
            scenario_file = scenario_path

        if not os.path.exists(scenario_file):
            return None

        module_name = os.path.basename(scenario_file).replace(".py", "")
        spec = importlib.util.spec_from_file_location(module_name, scenario_file)
        if not (spec and spec.loader):
            return None

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (
                isinstance(attr, type)
                and attr_name != "AbstractScenario"
                and "AbstractScenario" in [base.__name__ for base in attr.__mro__]
            ):
                obj = attr(self.workspace_dir)
                obj.scenario_dir = scenario_dir
                return obj
        return None
