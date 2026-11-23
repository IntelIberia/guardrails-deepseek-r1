"""Configuración común: ninguna prueba puede abrir conexiones de red reales."""

import socket
from typing import Any

import pytest


@pytest.fixture(autouse=True)
def _sin_red(monkeypatch: pytest.MonkeyPatch) -> None:
    """Bloquea DNS y conexiones salientes; el transporte HTTP se simula en memoria.

    También fija el modo sin conexión de las dependencias que podrían intentar
    enviar telemetría o descargar modelos, para que un fallo sea inmediato y
    visible en lugar de una espera indefinida.
    """
    def deny(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("Las pruebas no pueden usar la red real")

    monkeypatch.setattr(socket.socket, "connect", deny)
    monkeypatch.setattr(socket.socket, "connect_ex", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    monkeypatch.setattr(socket, "create_connection", deny)
    for name, value in {
        "NEMO_GUARDRAILS_NO_USAGE_STATS": "1",
        "HF_HUB_OFFLINE": "1",
        "TRANSFORMERS_OFFLINE": "1",
        "HF_HUB_DISABLE_TELEMETRY": "1",
    }.items():
        monkeypatch.setenv(name, value)
