"""Pruebas del adaptador LG4 con transporte simulado; no son resultados de eficacia."""

import json

import httpx
import pytest

from bench.core.config import GuardSpec
from bench.core.schema import JsonObject, Stage, StageError
from bench.guards.llama_guard import (
    MODEL, build_llama_guard, parse_assessment, validate_llama_guard_spec,
)
from bench.openrouter import OpenRouterClient


def completion(content: object, cost: float | None = 0.01, finish: str = "stop") -> JsonObject:
    """Respuesta de transporte local para comprobar decisiones y contabilidad."""
    return {
        "choices": [{"finish_reason": finish, "message": {"content": content}}],
        "provider": "DeepInfra", "usage": {"cost": cost},
    }


@pytest.mark.parametrize("value,expected", [
    ("safe", (False, [])), (" safe\n", (False, [])),
    ("unsafe\nS1", (True, ["S1"])),
    ("unsafe\r\nS1, S14\n", (True, ["S1", "S14"])),
])
def test_parser_accepts_only_native_assessments(value: str, expected: tuple[bool, list[str]]) -> None:
    """Las categorías son códigos de la política nativa, sin inferencias añadidas."""
    assert parse_assessment(value) == expected


@pytest.mark.parametrize("value", [
    None, "", "SAFE", "safe\nS1", "unsafe", "unsafe\nS15", "unsafe\nS01",
    "unsafe\nS1,S1", "unsafe\nS1,\nS2", "unsafe\nS1\nExplanation", "I cannot evaluate",
])
def test_parser_rejects_missing_or_ambiguous_outputs(value: object) -> None:
    """Un formato inválido nunca se convierte en una decisión safe por defecto."""
    with pytest.raises(ValueError):
        parse_assessment(value)


def test_input_uses_native_user_message_and_fixed_parameters() -> None:
    """No transmite sistema, objetivo, etiquetas ni identificadores del oráculo."""
    requests: list[JsonObject] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        return httpx.Response(200, json=completion("safe"))

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        client = OpenRouterClient(http, "fixture", sleep_fn=lambda _: None)
        guard = build_llama_guard(GuardSpec("llama_guard", "LG4", ("input", "output")), client, 42)
        decision = guard.check("Consulta inocua", Stage.INPUT, {
            "objective": "oracle", "system_prompt": "NO TRANSMITIR", "is_benign": True,
        })
    assert len(requests) == 1
    assert requests[0]["messages"] == [{"role": "user", "content": "Consulta inocua"}]
    assert requests[0]["model"] == MODEL
    assert requests[0]["temperature"] == 0
    assert requests[0]["seed"] == 42
    assert requests[0]["provider"] == {
        "only": ["deepinfra"], "allow_fallbacks": False, "require_parameters": True,
    }
    assert "response_format" not in requests[0]
    assert not decision.blocked
    assert decision.cost_usd == 0.01


def test_output_evaluates_final_and_reasoning_separately_and_sums_costs() -> None:
    """La coincidencia de un canal inseguro bloquea sin ocultar el otro canal."""
    responses = iter([completion("safe", 0.01), completion("unsafe\nS14", 0.02)])
    requests: list[JsonObject] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        return httpx.Response(200, json=next(responses))

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        guard = build_llama_guard(
            GuardSpec("llama_guard", "LG4", ("output",)),
            OpenRouterClient(http, "fixture", sleep_fn=lambda _: None), 42,
        )
        decision = guard.check("WRAPPER NO EVALUADO", Stage.OUTPUT, {
            "input_text": "Entrada", "response_text": "Respuesta", "reasoning_chain": "Razonamiento",
        })
    assert [request["messages"] for request in requests] == [
        [{"role": "user", "content": "Entrada"}, {"role": "assistant", "content": "Respuesta"}],
        [{"role": "user", "content": "Entrada"}, {"role": "assistant", "content": "Razonamiento"}],
    ]
    assert decision.blocked
    assert decision.cost_usd == pytest.approx(0.03)
    assert decision.attempts == 2
    assert decision.provider == "DeepInfra"
    assert decision.reason == "reasoning_chain: S14"
    assert [call["categories"] for call in decision.raw["calls"]] == [[], ["S14"]]


def test_second_output_failure_preserves_first_raw_cost_and_latency() -> None:
    """El fallo del segundo canal conserva el gasto de ambos y no inventa veredicto."""
    responses = iter([completion("safe", 0.01), completion("ambiguous", 0.02)])

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=next(responses))

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        guard = build_llama_guard(
            GuardSpec("llama_guard", "LG4", ("output",)),
            OpenRouterClient(http, "fixture", sleep_fn=lambda _: None), 42,
        )
        with pytest.raises(StageError, match="llama_guard_invalid_output") as caught:
            guard.check("", Stage.OUTPUT, {
                "input_text": "Entrada", "response_text": "Final", "reasoning_chain": "Reason",
            })
    error = caught.value
    assert error.cost_usd == pytest.approx(0.03)
    assert error.attempts == 2
    assert error.latency_ms is not None and error.latency_ms > 0
    assert error.wall_latency_ms is not None and error.wall_latency_ms > 0
    assert error.raw is not None
    assert [call["status"] for call in error.raw["calls"]] == ["completed", "error"]
    assert error.raw["calls"][0]["raw"]["choices"][0]["message"]["content"] == "safe"
    assert error.raw["calls"][1]["raw"]["choices"][0]["message"]["content"] == "ambiguous"


@pytest.mark.parametrize("finish", ["length", "content_filter", "error"])
def test_incomplete_classifier_is_error(finish: str) -> None:
    """Ni siquiera el prefijo safe es válido si la generación no terminó."""
    with httpx.Client(transport=httpx.MockTransport(
        lambda request: httpx.Response(200, json=completion("safe", finish=finish)),
    )) as http:
        guard = build_llama_guard(
            GuardSpec("llama_guard", "LG4", ("input",)), OpenRouterClient(http, "fixture"), 42,
        )
        with pytest.raises(StageError, match="llama_guard_incomplete"):
            guard.check("Entrada", Stage.INPUT, {})


def test_unknown_call_cost_remains_unknown() -> None:
    """Un usage sin coste no se reemplaza por cero ni por tarifas estimadas."""
    with httpx.Client(transport=httpx.MockTransport(
        lambda request: httpx.Response(200, json=completion("safe", cost=None)),
    )) as http:
        guard = build_llama_guard(
            GuardSpec("llama_guard", "LG4", ("input",)), OpenRouterClient(http, "fixture"), 42,
        )
        assert guard.check("Entrada", Stage.INPUT, {}).cost_usd is None


def test_recorded_messages_do_not_reintroduce_credential() -> None:
    """El registro de mensajes redacta una credencial si aparece en el texto."""
    key = "fixture-secret-not-real"
    with httpx.Client(transport=httpx.MockTransport(
        lambda request: httpx.Response(200, json=completion("safe")),
    )) as http:
        guard = build_llama_guard(
            GuardSpec("llama_guard", "LG4", ("input",)), OpenRouterClient(http, key), 42,
        )
        decision = guard.check(f"Texto {key}", Stage.INPUT, {})
    assert key not in json.dumps(decision.raw)
    assert decision.raw["calls"][0]["messages"][0]["content"] == "Texto [REDACTED]"


@pytest.mark.parametrize("options", [
    {"policy": "canary"}, {"model": "another-model"}, {"provider": " "},
    {"max_tokens": True}, {"max_tokens": 1}, {"max_tokens": 10000}, {"unexpected": True},
])
def test_invalid_options_rejected_offline(options: JsonObject) -> None:
    """La validación declarativa no necesita ni construye un cliente HTTP."""
    with pytest.raises(ValueError):
        validate_llama_guard_spec(GuardSpec("llama_guard", "LG4", ("input",), json.dumps(options)))
