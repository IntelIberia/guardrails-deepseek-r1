"""Pruebas del cribado de entrada del nivel 1 con filtros simulados (sin red)."""

import json
from pathlib import Path

import pytest

from bench.core.schema import AttackPrompt, GuardDecision, GuardrailBlocked, Stage, StageError, TargetResponse
from scripts import run_input_screening as rs


def attack(pid: str, benign: bool = False) -> AttackPrompt:
    return AttackPrompt(pid, "s", "o", "n", benign, "sistema", f"texto {pid}", "obj")


class FakeGuard:
    def __init__(self, blocked: set[str]) -> None:
        self.blocked = blocked
        self.calls: list[tuple[str, Stage]] = []

    def check(self, text: str, stage: Stage, context: dict[str, str]) -> GuardDecision:
        self.calls.append((text, stage))
        assert context == {"input_text": text}
        if "error" in text:
            raise StageError("http_429", cost_usd=None)
        return GuardDecision(any(pid in text for pid in self.blocked), "motivo", {}, 5.0, 0.0001)


class FakeTarget:
    def __init__(self, mode: str) -> None:
        self.mode = mode

    def generate(self, prompt: str) -> TargetResponse:
        if self.mode == "block":
            raise GuardrailBlocked("openrouter-native-regex", Stage.INPUT,
                                   GuardDecision(True, "403", {}, 1.0, None))
        if self.mode == "truncated":
            raise StageError("target_incomplete", cost_usd=0.00002)
        if self.mode == "fail":
            raise StageError("http_500")
        return TargetResponse("x", None, "P", {}, 1.0, 0.00003, {})


def header(run_id: str = "sc2-test") -> dict[str, object]:
    return {"record_type": "header", "run_id": run_id, "config_fingerprint": "f", "config": {}}


def test_filtros_simulados_y_reanudacion(tmp_path: Path) -> None:
    guard = FakeGuard({"a1"})
    modes = {"a1": "block", "a2": "truncated", "b1": "ok", "error": "fail"}
    filters = {
        "nemo_input": rs.guard_filter(guard),
        "openrouter_native": rs.native_filter(lambda a: FakeTarget(modes[a.prompt_id])),
    }
    cases = [attack("a1"), attack("a2"), attack("b1", True), attack("error")]
    summary = rs.run_screening(cases, filters, header(), tmp_path, 2)
    assert summary["new"] == 8
    lines = [json.loads(x) for x in (tmp_path / "sc2-test.jsonl").read_text().splitlines()]
    by = {(r["prompt_id"], r["filter"]): r for r in lines[1:]}
    assert by[("a1", "nemo_input")]["status"] == "blocked"
    assert by[("a1", "openrouter_native")]["status"] == "blocked"
    assert by[("a2", "openrouter_native")]["status"] == "passed"
    assert by[("a2", "openrouter_native")]["reason"] == "truncada_por_max_tokens"
    assert by[("error", "nemo_input")]["status"] == "error"
    assert by[("error", "openrouter_native")]["error_code"] == "http_500"
    assert all(stage is Stage.INPUT for _, stage in guard.calls)
    # Reanudar solo repite los dos pares con error.
    again = rs.run_screening(cases, filters, header(), tmp_path, 1)
    assert again["already_done"] == 6 and again["new"] == 2


def test_reanudar_con_otra_configuracion_falla(tmp_path: Path) -> None:
    filters = {"nemo_input": rs.guard_filter(FakeGuard(set()))}
    rs.run_screening([attack("a1")], filters, header(), tmp_path, 1)
    other = header()
    other["config_fingerprint"] = "g"
    with pytest.raises(ValueError, match="no coincide"):
        rs.run_screening([attack("a1")], filters, other, tmp_path, 1)


def test_dry_run_y_validaciones(capsys: pytest.CaptureFixture[str]) -> None:
    assert rs.main(["--part", "2", "--run-id", "sc2-p2", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "Modo sin red" in out and "max_tokens=16" in out
    with pytest.raises(SystemExit):
        rs.main(["--run-id", "otro", "--dry-run"])
    with pytest.raises(SystemExit):
        rs.main(["--run-id", "sc2-x", "--filters", "inventado", "--dry-run"])


def test_cabecera_identifica_corpus_filtros_y_codigo() -> None:
    head = rs.build_header("sc2-p1", "a" * 64, [attack("a1")], 1, ["nemo_input"], {"x": 1}, 16,
                           ("c" * 40, False))
    assert head["config"]["measures"] == "solo_deteccion_de_entrada"
    assert head["config"]["dataset"]["prompt_ids"] == ["a1"]
    assert head["config_fingerprint"] != rs.build_header(
        "sc2-p1", "a" * 64, [attack("a1")], 1, ["nemo_input"], {"x": 1}, 8,
        ("c" * 40, False))["config_fingerprint"]


@pytest.mark.parametrize("extra", [["--part", "0"], ["--part", "5"],
                                   ["--native-max-tokens", "0"],
                                   ["--filters", "nemo_input,nemo_input"]])
def test_opciones_invalidas_no_generan_ejecuciones_vacias(extra: list[str]) -> None:
    with pytest.raises(SystemExit):
        rs.main(["--run-id", "sc2-test", "--dry-run", *extra])
