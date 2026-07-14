import os

from .autoinject import AutoInjectAttack
from .base import AbstractAttack
from .static import StaticAttack


def load_attack(attack_id: str, payload: str | None = None, payload_file: str | None = None) -> AbstractAttack:
    """
    Instantiate an attack by name. Configuration is read from environment variables
    where needed (e.g. OPENROUTER_API_KEY, ATTACK_VICTIM_MODEL).
    """
    if attack_id == "static":
        return StaticAttack(payload=payload, payload_file=payload_file)

    if attack_id == "autoinject":
        return AutoInjectAttack(
            victim_model=os.environ.get("ATTACK_VICTIM_MODEL", "gpt-4o-mini"),
            attacker_model=os.environ.get("ATTACK_ATTACKER_MODEL", "openai/gpt-4o-mini"),
        )

    raise ValueError(f"Unknown attack: '{attack_id}'. Available: static, autoinject")


__all__ = ["AbstractAttack", "StaticAttack", "AutoInjectAttack", "load_attack"]
