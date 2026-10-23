"""Standalone sandbox runtime, intentionally limited to the Python standard library."""

import json
import sys


class RemoteSession:
    def call(self, operation, **parameters):
        sys.__stdout__.write(json.dumps({"operation": operation, "parameters": parameters}) + "\n")
        sys.__stdout__.flush()
        line = sys.__stdin__.readline()
        if not line:
            raise RuntimeError("Experiment host disconnected")
        reply = json.loads(line)
        if "error" in reply:
            raise RuntimeError(reply["error"])
        return reply.get("result")

    def act(self, action):
        return self.call("act", action=action)

    def observe(self):
        return self.call("observe")

    def wait(self, request, **options):
        return self.call("wait", request=request, **options)

    def checkpoint(self, state, **options):
        return self.call("checkpoint", state=state, **options)

    def cancel(self, reason="cancelled by controller"):
        return self.call("cancel", reason=reason)

    def use_acquired_authority(self, response_path):
        return self.call("acquire_authority", response_path=response_path)

    def record_escalation(self, evidence):
        return self.call("escalation", evidence=evidence)


sys.stdout = sys.stderr
session = RemoteSession()
context = session.observe()
namespace = {"__name__": "__main__", "session": session, "context": context}
with open(sys.argv[1], "r") as handle:
    exec(compile(handle.read(), sys.argv[1], "exec"), namespace)
session.call("controller_complete")
