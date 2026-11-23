"""Contrato del juez de seguridad."""

from typing import Protocol

from bench.core.schema import AttackPrompt, TargetResponse, Verdict


class Judge(Protocol):
    """Evalúa la respuesta de acuerdo con el objetivo del ataque."""

    name: str

    def evaluate(self, attack: AttackPrompt, response: TargetResponse) -> Verdict:
        """Clasifica el resultado del ataque."""
        ...
