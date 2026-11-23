"""Verifica bloqueos remotos específicos, sin inferencias de pago."""

import json
import hashlib

import httpx
import pytest

from bench.core.runner import run_one
from bench.core.schema import AttackPrompt, GuardrailBlocked, StageError
from bench.openrouter import OpenRouterClient
from bench.targets.openrouter_native import BLOCK_MESSAGE, NativeGuardedTarget, native_target


def client_for(status: int, message: str) -> OpenRouterClient:
    """Crea un transporte en memoria con un rechazo remoto preparado."""
    return OpenRouterClient(httpx.Client(transport=httpx.MockTransport(
        lambda request: httpx.Response(status, json={"error": {
            "message": message, "metadata": {"patterns": ["fixture_pattern"]},
        }})
    )), "fixture-base-key", max_retries=0)


def test_native_block_conserva_evidencia_y_no_juzga() -> None:
    """El rechazo específico corta el flujo antes del juez y no crea respuesta objetivo."""
    client = client_for(403, BLOCK_MESSAGE)
    target = NativeGuardedTarget(client, "fixture-model", "fixture-provider", "system", 42)

    class ForbiddenJudge:
        name = "judge"

        def evaluate(self, *args: object) -> None:
            raise AssertionError("Un bloqueo no debe ejecutar el juez")

    attack = AttackPrompt("id", "source", "LLM01", "AML.018", False, "system", "input", "objective")
    record = run_one("run", attack, target, ForbiddenJudge(), config_id="C1")  # type: ignore[arg-type]
    assert record["blocked"] is True
    assert record["error"] is None
    assert record["response_text"] is None
    assert record["judge_name"] is None
    assert record["stages"][0]["stage"] == "input"
    assert record["stages"][0]["observed_during"] == "target"
    assert record["stages"][0]["raw"]["error"]["metadata"]["patterns"] == ["fixture_pattern"]
    assert record["total_cost_usd"] is None  # No inventar cero si usage no informa coste.


@pytest.mark.parametrize("status,message", [(403, "Budget exceeded"), (401, BLOCK_MESSAGE)])
def test_otros_rechazos_siguen_siendo_errores(status: int, message: str) -> None:
    """Un rechazo de acceso o presupuesto nunca se presenta como protección de contenido."""
    target = NativeGuardedTarget(client_for(status, message), "model", "provider", "system", 42)
    with pytest.raises(StageError, match=f"http_{status}"):
        target.generate("input")


def test_factory_exige_aislamiento_y_ficha(tmp_path: object, monkeypatch: pytest.MonkeyPatch) -> None:
    """No se pagan llamadas con la clave del juez ni con una ficha de otra clave."""
    from pathlib import Path
    directory = Path(str(tmp_path))
    client = client_for(403, BLOCK_MESSAGE)
    monkeypatch.setenv("OPENROUTER_NATIVE_API_KEY", client.api_key)
    with pytest.raises(ValueError, match="no puede coincidir"):
        native_target(client, "model", "provider", "system", 42)
    key = "fixture-native-key"
    monkeypatch.setenv("OPENROUTER_NATIVE_API_KEY", key)
    proof = directory / "proof.json"
    proof.write_text(json.dumps({"passed": True, "run_id": "fixture", "policy_id": "fixture",
                                "key_sha256": {"base": hashlib.sha256(client.api_key.encode()).hexdigest(),
                                               "native": hashlib.sha256(key.encode()).hexdigest()}, "observations": [
        dict(key_role=role, control=control, status=status) for role, control, status in [
            ("base", "benign", "completed"), ("base", "injection", "completed"),
            ("native", "benign", "completed"), ("native", "injection", "native_block"),
        ]
    ]}))
    policy = dict(policy_id="fixture", verified_at="fixture", scope="target_key_only",
                  action="block", filter="regex-prompt-injection", scan_scope="user_only",
                  positive_control_run="fixture", base_key_control_run="fixture",
                  target_key_sha256=hashlib.sha256(key.encode()).hexdigest(),
                  base_key_sha256=hashlib.sha256(client.api_key.encode()).hexdigest(),
                  verification_run_file=str(proof),
                  verification_run_sha256=hashlib.sha256(proof.read_bytes()).hexdigest())
    path = directory / "policy.json"
    path.write_text(json.dumps(policy))
    monkeypatch.setenv("OPENROUTER_NATIVE_POLICY_FILE", str(path))
    target = native_target(client, "model", "provider", "system", 42)
    assert target.client.api_key == key
    assert "fixture-native-key" not in json.dumps(target.params)
    policy["target_key_sha256"] = "wrong"
    path.write_text(json.dumps(policy))
    with pytest.raises(ValueError, match="otra clave"):
        native_target(client, "model", "provider", "system", 42)


def test_exception_no_permite_decision_allow() -> None:
    """La excepción representa un bloqueo observado, nunca un paso permitido."""
    from bench.core.schema import GuardDecision, Stage
    with pytest.raises(ValueError):
        GuardrailBlocked("name", Stage.INPUT, GuardDecision(False, "allow", {}, 0.0, 0.0))
