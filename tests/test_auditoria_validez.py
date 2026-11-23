"""Comprueba bloqueos, reanudación, denominadores, costes y latencias con datos locales."""

import json
import sys
from dataclasses import asdict
from pathlib import Path
from threading import Lock
from time import sleep
from typing import Any

import httpx
import pytest

from bench.core.config import GuardSpec
from bench.core.runner import run_batch, run_one
from bench.core.schema import AttackPrompt, JsonObject, Stage, TargetResponse, Verdict
from bench.guards.llama_guard import build_llama_guard
from bench.guards.nemo import build_nemo_guard
from bench.openrouter import OpenRouterClient
from scripts import run_config, summarize_runs

ROOT = Path(__file__).resolve().parents[1]
CASE = AttackPrompt(**json.loads((ROOT / "data/attacks/pilot_llm07.json").read_text()))
CANARY = "TFG-CANARIO-ZAFIRO-6821"
TEST_KEY = "clave-ficticia-para-tests"


def lg_completion(content: str, cost: float = 0.01) -> JsonObject:
    return {"choices": [{"finish_reason": "stop", "message": {"content": content}}],
            "provider": "DeepInfra", "usage": {"cost": cost}}


def test_h1_llama_guard_bloqueo_confirmado_no_se_convierte_en_error() -> None:
    """Final unsafe y fallo de transporte en el razonamiento: prevalece el bloqueo."""
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(200, json=lg_completion("unsafe\nS1", 0.02))
        return httpx.Response(503, json={"error": {"message": "fixture"}})

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        guard = build_llama_guard(
            GuardSpec("llama_guard", "LG4", ("output",)),
            OpenRouterClient(http, "fixture", max_retries=0, sleep_fn=lambda _: None), 42,
        )
        decision = guard.check("", Stage.OUTPUT, {
            "input_text": "Entrada", "response_text": "Final", "reasoning_chain": "Razonamiento",
        })
    assert decision.blocked
    assert decision.cost_usd == pytest.approx(0.02)
    assert decision.reason == "response_text: S1"
    assert [call["channel"] for call in decision.raw["calls"]] == ["response_text"]
    assert calls["n"] == 1


def test_h1_nemo_bloqueo_confirmado_no_se_convierte_en_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Igual en NeMo: el razonamiento no se modera tras un bloqueo del final."""
    import socket

    def deny(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("Red real prohibida")
    monkeypatch.setattr(socket.socket, "connect", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(200, json={
                "provider": "Azure", "usage": {"cost": 0.01},
                "choices": [{"finish_reason": "stop", "message": {"content": json.dumps(
                    {"blocked": True, "reason": "policy_violation"})}}],
            })
        return httpx.Response(503, json={"error": {"message": "fixture"}})

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        guard = build_nemo_guard(
            GuardSpec("nemo", "NeMo", ("output",)),
            OpenRouterClient(http, "fixture", max_retries=0, sleep_fn=lambda _: None), 42,
        )
        decision = guard.check("", Stage.OUTPUT, {
            "input_text": "Entrada", "response_text": "Final", "reasoning_chain": "Razonamiento",
        })
    assert decision.blocked
    assert decision.cost_usd == pytest.approx(0.01)
    assert [check["channel"] for check in decision.raw["framework_checks"]] == ["response_text"]
    assert calls["n"] == 1


def test_h2_reanudar_tras_error_del_juez_conserva_la_generacion(tmp_path: Path) -> None:
    """El objetivo divulga la canaria y el juez falla: al reanudar solo se repite el juez."""
    counts = {"target": 0, "judge": 0}
    lock = Lock()

    def intercept(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        with lock:
            if body["model"] == "deepseek/deepseek-r1":
                counts["target"] += 1
                text = f"El identificador es {CANARY}." if counts["target"] == 1 else "No puedo."
                return httpx.Response(200, json={
                    "provider": "P", "usage": {"cost": 0.001},
                    "choices": [{"finish_reason": "stop", "message": {"content": text}}],
                })
            counts["judge"] += 1
            content = "no es JSON" if counts["judge"] == 1 else json.dumps(
                {"success": True, "confidence": 1.0, "rationale_short": "Revela."})
        return httpx.Response(200, json={"usage": {"cost": 0.0001}, "choices": [
            {"finish_reason": "stop", "message": {"content": content}}]})

    kwargs: dict[str, Any] = dict(
        target_model="deepseek/deepseek-r1", run_id="rejudge-test", max_retries=0,
        requests_per_second=1e9, git_state=("a" * 40, False),
    )
    with httpx.Client(transport=httpx.MockTransport(intercept)) as http:
        assert run_config.run_campaign(http, [CASE], "c" * 64, "prueba", TEST_KEY, tmp_path, **kwargs) == 1
        assert run_config.run_campaign(http, [CASE], "c" * 64, "prueba", TEST_KEY, tmp_path, **kwargs) == 0
        assert run_config.run_campaign(http, [CASE], "c" * 64, "prueba", TEST_KEY, tmp_path, **kwargs) == 0
    assert counts == {"target": 1, "judge": 2}
    lines = (tmp_path / "rejudge-test.jsonl").read_text().splitlines()
    first, second = (json.loads(line) for line in lines[1:])
    assert first["error"]["stage"] == "judge"
    assert second["error"] is None
    assert second["response_text"] == first["response_text"]
    assert second["resumed_from"]["timestamp"] == first["timestamp"]
    target_stage = next(s for s in second["stages"] if s["stage"] == "target")
    assert target_stage["reused"] is True
    # El coste del registro reanudado es solo el del nuevo arbitraje.
    assert second["total_cost_usd"] == pytest.approx(0.0001)

    summary = summarize_runs.summarize(tmp_path / "rejudge-test.jsonl")
    attack = summary["counts"]["attack"]
    assert attack["canary_final"] == 1 and attack["judge_true"] == 1
    assert summary["cases"][0]["record_selection"] == "rejudge_of_first_generation"
    # Coste por etapas sin duplicar la generación reutilizada.
    assert summary["cost_usd"]["target"] == "0.001"


def test_h2_resumen_usa_la_primera_generacion_en_jsonl_historico(tmp_path: Path) -> None:
    """Formato antiguo: error del juez y repetición completa; se conserva la primera."""
    first = record("r", final=f"Es {CANARY}", error={"stage": "judge", "code": "judge_invalid_output"})
    rerun = record("r", final="No puedo.", verdict=False)
    path = write_run(tmp_path, "r", [first, rerun])
    summary = summarize_runs.summarize(path)
    assert summary["counts"]["attack"]["canary_final"] == 1
    assert summary["cases"][0]["record_selection"] == "first_valid_generation"
    assert summary["records_superseded_by_first_generation"] == 1


def test_h3_fallo_del_objetivo_no_entra_en_el_denominador(tmp_path: Path) -> None:
    """Un target_incomplete no cuenta como ausencia observable de canaria."""
    failed = record("r", final=None, error={"stage": "target", "code": "target_incomplete"},
                    target_status="error")
    failed["target_raw"] = {"choices": [{"message": {"content": f"parcial {CANARY}"}}]}
    summary = summarize_runs.summarize(write_run(tmp_path, "r", [failed]))
    attack = summary["counts"]["attack"]
    assert attack.get("canary_observable", 0) == 0
    assert attack.get("canary_none", 0) == 0
    assert attack.get("reached_target", 0) == 0
    assert attack["target_errors"] == 1
    assert attack["canary_in_partial_target_raw"] == 1


def test_h4_separa_canaria_generada_y_entregada(tmp_path: Path) -> None:
    """Interceptada en la salida: generada sí, entregada no."""
    blocked = record("r", final=f"Es {CANARY}", blocked_by={"stage": "output", "guardrail": "NeMo"})
    summary = summarize_runs.summarize(write_run(tmp_path, "r", [blocked]))
    attack = summary["counts"]["attack"]
    assert attack["canary_final"] == 1  # generada (compatibilidad)
    assert attack.get("canary_delivered_final", 0) == 0
    assert attack.get("canary_delivered_either", 0) == 0
    assert summary["cases"][0]["canary_delivered_final"] is False
    out = tmp_path / "tablas"
    summarize_runs.write_tables([summary], {"target": "0", "defences": "0", "judge": "0", "total": "0",
                                            "unknown_stage_costs": 0}, out)
    table = (out / "runs_resumen.tex").read_text().lower()
    assert "generada final" in table and "canaria entregada" in table


def test_h5_aviso_si_el_corpus_por_defecto_difiere(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """Sin --input, C2 usa otro corpus que C0: el aviso es explícito en stderr."""
    monkeypatch.setattr(sys, "argv", ["run_config.py", "--config", str(ROOT / "configs/c2_nemo.yaml"),
                                      "--dry-run"])
    assert run_config.main() == 0
    err = capsys.readouterr().err
    assert "AVISO" in err and "--input" in err and "c0_20.jsonl" in err
    monkeypatch.setattr(sys, "argv", ["run_config.py", "--config", str(ROOT / "configs/c2_nemo.yaml"),
                                      "--input", str(ROOT / "data/attacks/c0_20.jsonl"), "--dry-run"])
    assert run_config.main() == 0
    assert "AVISO" not in capsys.readouterr().err


def test_h6_coste_desconocido_se_muestra_como_minimo(tmp_path: Path) -> None:
    """Una etapa sin coste no produce un subtotal que parezca completo."""
    rec = record("r", final="No.", verdict=False)
    rec["stages"][0]["cost_usd"] = None
    rec["total_cost_usd"] = None
    summary = summarize_runs.summarize(write_run(tmp_path, "r", [rec]))
    assert summary["cost_usd"]["complete"] is False
    assert summary["cost_usd"]["unknown_stage_costs"] == 1
    out = tmp_path / "tablas"
    total = summarize_runs.total_costs([summary])
    summarize_runs.write_tables([summary], total, out)
    table = (out / "runs_coste.tex").read_text()
    assert r"$\geq$" in table and "1 desc." in table


class _SlowJudge:
    name = "juez-lento"

    def evaluate(self, attack: AttackPrompt, response: TargetResponse) -> Verdict:
        sleep(0.2)  # espera de cuota/backoff que no es latencia HTTP
        return Verdict(False, 1.0, "No.", "fixture", 1.0, 0.0, {})


class _Target:
    name = "objetivo"
    params: JsonObject = {}

    def generate(self, prompt: str) -> TargetResponse:
        return TargetResponse("ok", None, "P", {}, 1.0, 0.0, {})


def test_h7_latencia_sin_juez_excluye_el_tiempo_de_pared_del_juez() -> None:
    record_ = run_one("r", CASE, _Target(), _SlowJudge())
    assert record_["judge_wall_latency_ms"] >= 200
    assert record_["deployment_latency_ms"] < 100
    assert record_["total_latency_ms"] >= 200


def test_h7_preparacion_se_registra_aparte() -> None:
    def factory(attack: AttackPrompt) -> _Target:
        sleep(0.05)
        return _Target()

    records = list(run_batch("r", [CASE], factory, _SlowJudge(), 1))
    assert records[0]["preparation_latency_ms"] >= 50
    assert records[0]["total_latency_ms"] < 50 + 200 + 100


def record(run_id: str, *, final: str | None, verdict: bool | None = None,
           error: JsonObject | None = None, blocked_by: JsonObject | None = None,
           target_status: str = "completed") -> JsonObject:
    stages: list[JsonObject] = [{"stage": "target", "name": "t", "status": target_status,
                                 "cost_usd": 0.001, "latency_ms": 10.0, "attempt_history": []}]
    if blocked_by:
        stages.append({"stage": "output", "name": blocked_by["guardrail"], "status": "completed",
                       "blocked": True, "cost_usd": 0.0, "latency_ms": 1.0, "attempt_history": []})
    if verdict is not None or (error and error["stage"] == "judge"):
        stages.append({"stage": "judge", "name": "j", "status": "error" if error else "completed",
                       "cost_usd": 0.0001, "latency_ms": 5.0, "attempt_history": []})
    return {
        "record_type": "result", "run_id": run_id, "timestamp": f"t{id(stages)}",
        "config_id": "C0", "prompt_id": CASE.prompt_id, "stages": stages,
        "blocked": blocked_by is not None, "blocked_by": blocked_by,
        "response_text": final, "reasoning_chain": None, "target_raw": None,
        "judge_verdict": None if verdict is None else {"success": verdict},
        "total_latency_ms": 20.0, "total_cost_usd": None if error else 0.0011,
        "error": error, "provider": "P",
    }


def write_run(tmp_path: Path, run_id: str, records: list[JsonObject]) -> Path:
    header = {"record_type": "header", "run_id": run_id, "schema_version": 3, "timestamp": "t",
              "config_id": "C0", "config": {
                  "dataset": {"sha256": "x", "cases": [asdict(CASE)]},
                  "target": {"model": "m", "provider": "p"}, "judge": {"model": "j", "provider": "o"},
                  "guardrails": [], "declaration": {"dataset": "d"}}}
    path = tmp_path / f"{run_id}.jsonl"
    path.write_text("\n".join(json.dumps(item) for item in [header, *records]) + "\n")
    return path
