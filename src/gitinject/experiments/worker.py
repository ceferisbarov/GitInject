"""Linux Bubblewrap boundary: no host home, environment, network, or evaluator mounts."""

import hashlib
import json
import os
import platform
import resource
import selectors
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

from .contracts import require
from .gateway import PolicyError

MAX_MESSAGE = 1024 * 1024


def boundary_command():
    executable = shutil.which("bwrap")
    if not executable:
        raise RuntimeError("Bubblewrap is required for attack controllers; there is no unsandboxed fallback")
    command = [
        executable,
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--ro-bind",
        "/usr",
        "/usr",
    ]
    for path in ("/lib", "/lib64"):
        if Path(path).exists():
            command += ["--ro-bind", path, path]
    return command + [
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--setenv",
        "PATH",
        "/usr/bin",
        "--setenv",
        "HOME",
        "/tmp",
    ]


def check_boundary():
    result = subprocess.run(
        boundary_command() + ["/usr/bin/python3", "-I", "-c", "print('isolated')"],
        env={},
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode or result.stdout.strip() != "isolated":
        raise RuntimeError("Bubblewrap isolation unavailable; refusing controller execution: " + result.stderr[:1000])


def _seccomp_filter():
    require(platform.machine() == "x86_64", "Worker process filter currently supports Linux x86_64 only")
    instructions = [(0x20, 0, 0, 4), (0x15, 1, 0, 0xC000003E), (0x06, 0, 0, 0x80000000), (0x20, 0, 0, 0)]
    for syscall in (56, 57, 58, 435):
        instructions += [(0x15, 0, 1, syscall), (0x06, 0, 0, 0x00050001)]
    instructions += [(0x06, 0, 0, 0x7FFF0000)]
    return b"".join(struct.pack("HBBI", *instruction) for instruction in instructions)


def _limits():
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (4 * 1024 * 1024, 4 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))


def run_controller(session):
    ref = session.spec.attack.controller
    source = session.record.directory / "inputs/controller" / Path(ref.path).name
    require(hashlib.sha256(source.read_bytes()).hexdigest() == ref.sha256, "Controller snapshot drift")
    runtime = Path(__file__).with_name("worker_bootstrap.py")
    session.record.snapshot("worker-runtime", runtime)
    with tempfile.TemporaryDirectory(prefix="gitinject-worker-") as directory:
        root = Path(directory)
        controller = root / "controller.py"
        controller.write_bytes(source.read_bytes())
        assets = root / "assets"
        assets.mkdir()
        for asset in session.spec.attack.assets:
            path = assets / asset.path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(asset.content)
        command = boundary_command() + [
            "--ro-bind",
            str(root),
            "/controller",
            "--ro-bind",
            str(runtime),
            "/worker.py",
            "--chdir",
            "/controller",
            "/usr/bin/python3",
            "-I",
            "/worker.py",
            "/controller/controller.py",
        ]
        complete = False
        with tempfile.TemporaryFile() as errors, tempfile.TemporaryFile() as seccomp:
            seccomp.write(_seccomp_filter())
            seccomp.flush()
            seccomp.seek(0)
            command = command[:-4] + ["--seccomp", str(seccomp.fileno())] + command[-4:]
            process = subprocess.Popen(
                command,
                env={},
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=errors,
                preexec_fn=_limits,
                pass_fds=(seccomp.fileno(),),
            )
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            buffer = b""
            try:
                while True:
                    session._check()
                    if not selector.select(min(0.5, session.remaining_seconds)):
                        if process.poll() is not None:
                            break
                        continue
                    chunk = os.read(process.stdout.fileno(), 65536)
                    if not chunk:
                        break
                    buffer += chunk
                    if len(buffer) > MAX_MESSAGE:
                        raise PolicyError("Controller message exceeds protocol limit")
                    while b"\n" in buffer:
                        line, buffer = buffer.split(b"\n", 1)
                        message = json.loads(line)
                        require(
                            isinstance(message, dict) and set(message) == {"operation", "parameters"},
                            "Invalid worker request",
                        )
                        operation = message["operation"]
                        parameters = message["parameters"]
                        require(isinstance(parameters, dict), "Invalid worker parameters")
                        allowed = {
                            "act": session.act,
                            "observe": session.observations,
                            "wait": session.wait,
                            "checkpoint": session.checkpoint,
                            "cancel": session.cancel,
                            "escalation": session.record_escalation,
                            "acquire_authority": session.use_acquired_authority,
                        }
                        if operation == "controller_complete":
                            require(not parameters, "Invalid controller completion")
                            complete = True
                            result = None
                        elif operation in allowed:
                            result = allowed[operation](**parameters)
                            if operation in {"act", "wait"} and session.spec.threat_model.adaptation != "online":
                                result = {"recorded": True}
                        else:
                            raise PolicyError("Worker operation is unavailable")
                        response = json.dumps({"result": session.redactor(result)}, allow_nan=False).encode() + b"\n"
                        if len(response) > MAX_MESSAGE:
                            raise PolicyError("Observation exceeds worker protocol limit; request narrower evidence")
                        process.stdin.write(response)
                        process.stdin.flush()
                status = process.wait(timeout=max(0.1, min(5, session.remaining_seconds)))
                errors.seek(0)
                session.record.artifact(
                    "controller-output.json",
                    {"stderr": errors.read(MAX_MESSAGE).decode(errors="replace"), "exit_code": status},
                )
                require(status == 0 and complete, "Controller failed or exited without completing protocol")
            finally:
                selector.close()
                if process.poll() is None:
                    process.kill()
                process.wait()
                process.stdin.close()
                process.stdout.close()
