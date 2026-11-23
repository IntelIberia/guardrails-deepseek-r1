"""Interfaz común de las salvaguardas de entrada y salida."""

from typing import Protocol

from bench.core.schema import GuardDecision, JsonObject, Stage


class Guardrail(Protocol):
    """Evalúa texto y devuelve una decisión, sin controlar la orquestación."""

    name: str
    stages: frozenset[Stage]

    def check(self, text: str, stage: Stage, context: JsonObject) -> GuardDecision:
        """Examina entrada o salida; el contexto conserva los campos por separado."""
        ...
