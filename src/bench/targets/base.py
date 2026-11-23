"""Contrato del modelo objetivo."""

from typing import Protocol

from bench.core.schema import TargetResponse


class TargetModel(Protocol):
    """Modelo capaz de responder a una entrada del banco de pruebas."""

    name: str
    params: dict[str, object]

    def generate(self, prompt: str) -> TargetResponse:
        """Genera una respuesta y entrega sus metadatos."""
        ...
