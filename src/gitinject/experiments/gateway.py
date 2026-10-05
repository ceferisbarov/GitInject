"""Trusted actor-bound transport. No API endpoint catalog or mutation retry."""

import base64
import os
import re
import uuid
from urllib.parse import quote, urlsplit

import requests

from .contracts import require


class PolicyError(ValueError):
    pass


class AmbiguousOperation(RuntimeError):
    """A request may have reached GitHub; reconcile before issuing a new mutation."""


class Gateway:
    def __init__(self, token, actor, timeout=30):
        require(bool(token), f"Missing {actor} credentials")
        self._token = token
        self.actor = actor
        self.timeout = timeout
        self.record_event = None
        self.before_request = None
        self.session = requests.Session()
        self.session.trust_env = False

    @classmethod
    def from_environment(cls, actor):
        name = "GITHUB_TOKEN" if actor == "defense" else "ATTACKER_GITHUB_TOKEN"
        token = os.environ.get(name)
        if not token and actor == "defense":
            import subprocess

            try:
                token = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, check=True).stdout.strip()
            except (OSError, subprocess.CalledProcessError):
                pass
        return cls(token, actor)

    def identity(self):
        result = self.rest({"method": "GET", "endpoint": "/user"})
        if result["status"] != 200:
            raise RuntimeError(f"Cannot authenticate {self.actor}: HTTP {result['status']}")
        data = result["body"]
        require(type(data.get("id")) is int and bool(data.get("login")), "Missing immutable GitHub identity")
        return {"id": data["id"], "login": data["login"], "role": self.actor}

    def rest(self, parameters):
        if self.before_request:
            self.before_request()
        parameters = dict(parameters)
        allowed = {"method", "endpoint", "json", "data", "params", "headers"}
        if set(parameters) - allowed:
            raise PolicyError("Unsupported request options; transport credentials, TLS and routing cannot be overridden")
        endpoint = parameters.pop("endpoint")
        method = parameters.pop("method", "GET").upper()
        if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
            raise PolicyError("Invalid HTTP method")
        url = endpoint if "://" in endpoint else "https://api.github.com/" + endpoint.lstrip("/")
        parsed = urlsplit(url)
        if (parsed.scheme, parsed.netloc) != ("https", "api.github.com") or parsed.fragment or parsed.username:
            raise PolicyError("Credentials may only be sent to https://api.github.com")
        headers = requests.structures.CaseInsensitiveDict(parameters.pop("headers", {}))
        if set(key.lower() for key in headers) & {"authorization", "host", "cookie", "proxy-authorization"}:
            raise PolicyError("Actor credentials and routing cannot be overridden")
        headers["Authorization"] = "Bearer " + self._token
        headers.setdefault("Accept", "application/vnd.github+json")
        request_id = uuid.uuid4().hex
        if self.record_event:
            self.record_event(
                "transport_request",
                request_id=request_id,
                method=method,
                url=url,
                parameters=parameters,
                authorization="actor-bound GitHub permissions",
            )
        try:
            response = self.session.request(
                method, url, headers=headers, timeout=self.timeout, allow_redirects=False, **parameters
            )
        except requests.RequestException as exc:
            if self.record_event:
                self.record_event("transport_response", request_id=request_id, status=None, uncertain=True)
            raise AmbiguousOperation("Transport failed; request outcome is uncertain. No mutation was retried.") from exc
        try:
            body = response.json()
        except ValueError:
            body = response.text
        result = {
            "status": response.status_code,
            "body": body,
            "headers": {k: response.headers[k] for k in ("X-GitHub-Request-Id", "ETag", "Link") if k in response.headers},
        }
        if self.record_event:
            self.record_event("transport_response", request_id=request_id, **result)
        return result

    def perform(self, action):
        if action.transport == "rest":
            return self.rest(action.parameters)
        if action.transport == "graphql":
            if set(action.parameters) - {"query", "variables"}:
                raise PolicyError("Unsupported GraphQL options")
            return self.rest({"method": "POST", "endpoint": "/graphql", "json": dict(action.parameters)})
        if action.transport == "gh":
            return self.rest(self.gh_api(action.parameters.get("argv", ())))
        if action.transport == "git":
            return self.git(action.parameters)
        raise PolicyError("Unsupported transport")

    @staticmethod
    def gh_api(argv):
        """The gh api surface, without executing aliases, extensions or host commands."""
        argv = list(argv)
        if not argv or argv.pop(0) != "api":
            raise PolicyError("The isolated gh transport supports gh api; use REST/GraphQL for other operations")
        result = {"method": "GET"}
        data = {}
        headers = {}
        while argv:
            arg = argv.pop(0)
            if arg in {"--method", "-X", "--field", "-F", "--raw-field", "-f", "--header", "-H"}:
                if not argv:
                    raise PolicyError("Missing gh api argument")
                value = argv.pop(0)
                if arg in {"--method", "-X"}:
                    result["method"] = value
                elif arg in {"--header", "-H"}:
                    name, separator, content = value.partition(":")
                    if not separator:
                        raise PolicyError("Invalid header")
                    headers[name] = content.strip()
                else:
                    name, separator, content = value.partition("=")
                    if not separator or content.startswith("@"):
                        raise PolicyError("gh api fields must be inline key=value")
                    if arg in {"--field", "-F"}:
                        import json

                        try:
                            content = json.loads(content)
                        except ValueError:
                            pass
                    data[name] = content
            elif arg.startswith("-") or "endpoint" in result:
                raise PolicyError("Unsupported gh api argument")
            else:
                result["endpoint"] = arg
        if "endpoint" not in result:
            raise PolicyError("Missing gh api endpoint")
        if headers:
            result["headers"] = headers
        if data:
            if result["method"] == "GET":
                result["method"] = "POST"
            result["json"] = data
        return result

    def git(self, parameters):
        """Git database transport: arbitrary Git objects and refs through GitHub's Git API."""
        repository = parameters.get("repository", "")
        if not re.fullmatch(r"[\w.-]+/[\w.-]+", repository):
            raise PolicyError("Invalid Git repository")
        operation = parameters.get("operation")
        if operation == "request":
            path = parameters.get("path", "")
            if not path.startswith("git/") or ".." in path.split("/"):
                raise PolicyError("Git database path must start with git/")
            request = {"method": parameters.get("method", "GET"), "endpoint": f"/repos/{repository}/{path}"}
            if "json" in parameters:
                request["json"] = parameters["json"]
            return self.rest(request)
        if operation == "commit":
            branch = parameters.get("branch", "main")
            if not re.fullmatch(r"[\w./-]+", branch) or ".." in branch:
                raise PolicyError("Invalid Git branch")
            ref = self.rest({"endpoint": f"/repos/{repository}/git/ref/heads/{branch}"})
            if ref["status"] != 200:
                return ref
            parent = ref["body"]["object"]["sha"]
            commit = self.rest({"endpoint": f"/repos/{repository}/git/commits/{parent}"})
            if commit["status"] != 200:
                return commit
            tree = []
            from .contracts import Asset

            for path, content in parameters.get("files", {}).items():
                Asset(path=path, content=content)
                tree.append({"path": path, "mode": "100644", "type": "blob", "content": content})
            result = self.rest(
                {
                    "method": "POST",
                    "endpoint": f"/repos/{repository}/git/trees",
                    "json": {"base_tree": commit["body"]["tree"]["sha"], "tree": tree},
                }
            )
            if result["status"] != 201:
                return result
            result = self.rest(
                {
                    "method": "POST",
                    "endpoint": f"/repos/{repository}/git/commits",
                    "json": {
                        "message": parameters.get("message", "experiment action"),
                        "tree": result["body"]["sha"],
                        "parents": [parent],
                    },
                }
            )
            if result["status"] != 201:
                return result
            sha = result["body"]["sha"]
            result = self.rest(
                {
                    "method": "PATCH",
                    "endpoint": f"/repos/{repository}/git/refs/heads/{branch}",
                    "json": {"sha": sha, "force": False},
                }
            )
            result["commit_sha"] = sha
            return result
        raise PolicyError("Unsupported Git operation; use request for arbitrary Git database operations")

    def owned_repositories(self):
        results = {}
        page = 1
        while True:
            response = self.rest(
                {"endpoint": "/user/repos", "params": {"affiliation": "owner", "per_page": 100, "page": page}}
            )
            if response["status"] != 200:
                raise RuntimeError(f"Cannot inventory account repositories: HTTP {response['status']}")
            for repo in response["body"]:
                results[repo["id"]] = repo["full_name"]
            if len(response["body"]) < 100:
                return results
            page += 1

    def install_secret(self, repository, name, value):
        """Use existing PyGitHub encryption; never put plaintext in the action journal."""
        from github import Auth, Github

        Github(auth=Auth.Token(self._token), retry=0).get_repo(repository).create_secret(name, value)

    def delete_repository(self, name, identity):
        found = self.rest({"endpoint": f"/repos/{name}"})
        if found["status"] == 404:
            return
        if found["status"] != 200 or found["body"].get("id") != identity:
            raise RuntimeError("Refusing cleanup: repository identity changed or is unobservable")
        result = self.rest({"method": "DELETE", "endpoint": f"/repos/{name}"})
        if result["status"] not in {204, 404}:
            raise RuntimeError(f"Cleanup failed: HTTP {result['status']}")


class Redactor:
    def __init__(self, secrets=()):
        self.secrets = set()
        for secret in secrets:
            self.add(secret)

    def add(self, value):
        if value:
            self.secrets.add(value)
            self.secrets.add(quote(value, safe=""))
            self.secrets.add(base64.b64encode(value.encode()).decode())

    def __call__(self, value):
        if isinstance(value, str):
            for secret in sorted(self.secrets, key=len, reverse=True):
                value = value.replace(secret, "[REDACTED]")
            return value
        if isinstance(value, dict):
            value = dict(value)
            if value.get("encoding") == "base64" and isinstance(value.get("content"), str):
                try:
                    decoded = base64.b64decode(value["content"])
                    for secret in self.secrets:
                        decoded = decoded.replace(secret.encode(), b"[REDACTED]")
                    value["content"] = base64.b64encode(decoded).decode()
                except ValueError:
                    pass
            return {self(str(k)): self(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self(v) for v in value]
        return value
