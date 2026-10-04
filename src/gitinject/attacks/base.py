from abc import ABC, abstractmethod


class AbstractAttack(ABC):
    name: str

    @abstractmethod
    def generate(self, goal: str, context: str) -> str:
        """
        Produce the injection payload string.

        goal:    What we want the victim LLM to do.
        context: The full text the victim LLM will see. Used by adaptive attacks
                 to tailor the suffix to the specific prompt.

        Returns the raw payload string. The runner handles substitution into
        the scenario's injection slots.
        """

    def update(self, score: float) -> None:
        """
        Called by the optimizer after each iteration with the binary security
        score (1.0 = attack succeeded, 0.0 = failed). Stateless attacks ignore
        this. Adaptive attacks use it to improve the next generate() call.
        """

    @property
    def best_payload(self) -> str | None:
        """
        The highest-scoring payload seen across all generate()/update() cycles.
        None for stateless attacks. Written to best_payload.txt by the optimizer.
        """
        return None
