from .base import AbstractAttack


class StaticAttack(AbstractAttack):
    """
    Fixed payload attack. No LLM call. Accepts an inline string or a file path,
    enabling the transfer workflow: take best_payload.txt from an AutoInject run
    and feed it here to test on a different scenario.
    """

    name = "static"

    def __init__(self, payload: str | None = None, payload_file: str | None = None):
        if payload is None and payload_file is None:
            raise ValueError("Either payload or payload_file must be provided.")
        if payload is not None and payload_file is not None:
            raise ValueError("Provide either payload or payload_file, not both.")
        self._payload = payload
        self._payload_file = payload_file

    def generate(self, goal: str, context: str) -> str:
        if self._payload is not None:
            return self._payload
        with open(self._payload_file) as f:
            return f.read()
