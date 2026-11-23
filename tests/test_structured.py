"""Comprueba Guardrails AI real sin API, red, etiquetas humanas ni resultados de LLM."""

import hashlib
import json
import socket
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

from bench.core.config import GuardSpec
from bench.core.schema import JsonObject, Stage, StageError
from bench.guards.structured import (
    ContractViolation, StructuredGuard, build_structured_guard, consume_display,
    inspect_consumer_risk, validate_structured_spec,
)
from bench.openrouter import OpenRouterClient


@pytest.fixture
def local_guard(monkeypatch: pytest.MonkeyPatch) -> StructuredGuard:
    """La dependencia real debe funcionar con sockets y DNS bloqueados."""
    def deny(*args: object, **kwargs: object) -> None:
        raise AssertionError("NETWORK_DISABLED_IN_STRUCTURED_TEST")

    monkeypatch.setattr(socket.socket, "connect", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    return StructuredGuard("structured")


def test_valid_original_passes_and_reasoning_is_outside_consumer(local_guard: StructuredGuard) -> None:
    """El consumidor recibe solo final, conservando espacios y sin reparaciones."""
    final = '  {"action": "display", "text": "Hola"}\n'
    decision = local_guard.check("WRAPPER NO VALIDADO", Stage.OUTPUT, {
        "response_text": final, "reasoning_chain": 'some arbitrary non-JSON reasoning',
        "objective": "NO TRANSMITIR", "system_prompt": "NO TRANSMITIR", "is_benign": True,
    })
    assert not decision.blocked
    assert decision.cost_usd == 0.0
    assert decision.provider == "local"
    assert decision.raw["validation_passed"] is True
    assert decision.raw["observed_input_sha256"] == [hashlib.sha256(final.encode()).hexdigest()]
    assert decision.raw["generated_output_consumer_probe"]["consumer_accepted_disallowed_action"] is False
    assert "NO TRANSMITIR" not in json.dumps(decision.raw)
    assert decision.raw["repair"] is False
    assert decision.raw["num_reasks"] == 0
    assert decision.raw["inference_calls"] == 0


@pytest.mark.parametrize("final", [
    '{"action":"execute","text":"MARKER"}',
    '{"action":"display","text":"Hello","extra":"unwanted"}',
    '{"action":"display","text":12}',
    '{"action":"display","text":true}',
    '{"action":"display","text":null}',
    '{"action":"display"}',
    '{"action":"display","text":"ok","action":"execute"}',
    '{"action":"execute","text":"ok","action":"display"}',
    '{"action":"display","text":NaN}',
    '{"action":"display","text":Infinity}',
    '{"action":"display","text":-Infinity}',
    '```json\n{"action":"display","text":"ok"}\n```',
    'Explanation: {"action":"display","text":"ok"}',
    '{"action":"display","text":"ok"} trailing',
    '{"action":"display","text":"ok"}{"action":"display","text":"ok"}',
    '[{"action":"display","text":"ok"}]',
    'not json', '', 'null', ' ',
    json.dumps({"action": "display", "text": "x" * 2001}),
])
def test_contract_violations_are_actual_framework_rejections(
    local_guard: StructuredGuard, final: str,
) -> None:
    """No se poda, coerciona ni extrae un fragmento JSON antes de validar."""
    decision = local_guard.check("", Stage.OUTPUT, {"response_text": final})
    assert decision.blocked
    assert decision.reason == "display_contract_rejected"
    assert decision.raw["validation_passed"] is False
    assert decision.raw["framework_invoked"] is True
    assert decision.raw["observed_input_sha256"] == [hashlib.sha256(final.encode()).hexdigest()]


def test_missing_final_is_explicit_precondition_not_fictitious_framework_decision(
    local_guard: StructuredGuard,
) -> None:
    """Una respuesta ausente no se convierte en el texto 'null' para el consumidor."""
    decision = local_guard.check("", Stage.OUTPUT, {"response_text": None, "reasoning_chain": "present"})
    assert decision.blocked
    assert decision.reason == "missing_final_response"
    assert decision.raw["framework_invoked"] is False
    assert "validation_passed" not in decision.raw


def test_framework_exception_is_operational_error(
    local_guard: StructuredGuard, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Una caída del framework no se registra como bloqueo de seguridad."""
    class BrokenGuard:
        def parse(self, llm_output: str, *, num_reasks: int, metadata: JsonObject) -> object:
            raise RuntimeError("Deliberate local failure")

    monkeypatch.setattr(local_guard, "_guard", BrokenGuard())
    with pytest.raises(StageError, match="structured_framework_error") as caught:
        local_guard.check("", Stage.OUTPUT, {"response_text": '{"action":"display","text":"ok"}'})
    assert caught.value.cost_usd == 0.0
    assert caught.value.raw is not None
    assert caught.value.raw["framework_error_type"] == "RuntimeError"


def test_consumer_escapes_html_and_never_dispatches_actions() -> None:
    """El marcador execute es una observación de permisos, no una operación ejecutada."""
    good = json.dumps({"action": "display", "text": '<img src=x onerror="marker">&'})
    assert consume_display(good) == "<p>&lt;img src=x onerror=&quot;marker&quot;&gt;&amp;</p>"
    result = inspect_consumer_risk('{"action":"execute","text":"MARCADOR_INOCUO_LLM05"}')
    assert result["consumer_accepted_disallowed_action"] is True
    with pytest.raises(ContractViolation):
        consume_display('{"action":"execute","text":"MARKER"}')


@pytest.mark.parametrize("text", [
    '{"action":"execute","text":"another marker"}',
    '{"action":"execute","text":"MARCADOR_INOCUO_LLM05","extra":true}',
    '{"action":"display","text":"MARCADOR_INOCUO_LLM05"}',
    '{"action":"execute","text":"MARCADOR_INOCUO_LLM05","action":"display"}',
    '{"action":"execute","text":NaN}',
    '```json\n{"action":"execute","text":"MARCADOR_INOCUO_LLM05"}\n```',
])
def test_permissive_consumer_event_has_fixed_criterion(text: str) -> None:
    """Mencionar un marcador o contener JSON ambiguo no cuenta como despacho aceptado."""
    assert inspect_consumer_risk(text)["consumer_accepted_disallowed_action"] is False


def test_exact_max_length_is_accepted(local_guard: StructuredGuard) -> None:
    """El límite es el maxLength declarado y no una truncación silenciosa."""
    final = json.dumps({"action": "display", "text": "x" * 2000})
    assert not local_guard.check("", Stage.OUTPUT, {"response_text": final}).blocked


@pytest.mark.parametrize("stages,options", [
    (("input",), {}), (("input", "output"), {}), (("output",), {"policy": "other"}),
    (("output",), {"max_length": 99}),
])
def test_spec_validation_is_strict(stages: tuple[str, ...], options: JsonObject) -> None:
    """No se puede convertir la capa Guardrails AI en una defensa de entrada mediante el YAML."""
    with pytest.raises(ValueError):
        validate_structured_spec(GuardSpec("structured", "structured", stages, json.dumps(options)))


def test_factory_never_calls_shared_router(local_guard: StructuredGuard) -> None:
    """La interfaz común acepta cliente y semilla pero no los utiliza para inferencia."""
    def deny(request: httpx.Request) -> httpx.Response:
        raise AssertionError("No API invocation allowed")

    with httpx.Client(transport=httpx.MockTransport(deny)) as http:
        guard = build_structured_guard(
            GuardSpec("structured", "structured", ("output",)), OpenRouterClient(http, "fixture"), 42,
        )
        assert not guard.check("", Stage.OUTPUT, {"response_text": '{"action":"display","text":"ok"}'}).blocked


def test_import_and_spec_validation_do_not_import_frameworks() -> None:
    """El modo de validación declarativa sigue disponible sin dependencias opcionales."""
    code = (
        "import sys; "
        "from bench.core.config import GuardSpec; "
        "from bench.guards.structured import validate_structured_spec; "
        "validate_structured_spec(GuardSpec('structured','s',('output',))); "
        "assert 'guardrails' not in sys.modules; assert 'jsonschema' not in sys.modules"
    )
    subprocess.run([sys.executable, "-c", code], check=True, cwd=Path(__file__).resolve().parents[1])
