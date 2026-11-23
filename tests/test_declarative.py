"""Comprueba el ensamblado declarativo y sus barreras antes de consumir una API."""

import json
import sys
from dataclasses import replace
from pathlib import Path
from typing import NoReturn

import httpx
import pytest
import yaml

from bench.bootstrap import Adapters, GuardBuilder, JudgeBuilder, TargetBuilder
from bench.core.config import ExperimentConfig, GuardSpec, ModelSpec, load_config, parse_config
from bench.core.registry import AdapterRegistry
from bench.core.schema import GuardDecision, JsonObject, Stage
from bench.guards.base import Guardrail
from bench.judges.base import Judge
from bench.judges.llm_judge import LLMJudge
from bench.openrouter import OpenRouterClient
from bench.targets.base import TargetModel
from bench.targets.openrouter import OpenRouterTarget
from scripts import run_config

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "configs/c0_baseline.yaml"
PILOT = ROOT / "data/attacks/pilot_llm07.json"
GIT_STATE = ("a" * 40, False)
FIXTURE_KEY = "fixture-integration-key-not-a-credential"


def forbid_network(*args: object, **kwargs: object) -> NoReturn:
    """Falla si la validación intenta crear clientes HTTP o leer credenciales."""
    raise AssertionError("Esta ruta debe terminar antes de cualquier acceso externo")


def test_cli_dry_run_valida_yaml_y_corpus_sin_red_ni_credenciales(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """El plan se valida incluso cuando no se puede construir un cliente HTTP."""
    monkeypatch.setattr(sys, "argv", ["run_config.py", "--config", str(BASELINE), "--dry-run"])
    monkeypatch.setattr(httpx, "Client", forbid_network)
    monkeypatch.setattr(run_config, "load_dotenv", forbid_network)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)

    assert run_config.main() == 0

    output = capsys.readouterr().out
    assert "C0 · 20 casos" in output
    assert "deepseek/deepseek-r1-0528 (deepinfra)" in output
    assert "openai/gpt-4.1-mini" in output
    assert "Semilla: 42" in output
    assert "Modo sin red" in output


def test_guard_opciones_invalidas_no_pasan_dry_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Las opciones concretas se comprueban antes de leer clave o construir transporte."""
    raw = load_config(ROOT / "configs/c3_llama_guard.yaml").to_dict()
    raw["guardrails"][0]["options"]["policy"] = "inventada"
    path = tmp_path / "invalid_guard.yaml"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["run_config.py", "--config", str(path), "--dry-run"])
    monkeypatch.setattr(httpx, "Client", forbid_network)
    monkeypatch.setattr(run_config, "load_dotenv", forbid_network)
    with pytest.raises(SystemExit) as exc:
        run_config.main()
    assert exc.value.code == 2


@pytest.mark.parametrize("profile", ["c0_baseline", "c1_native", "c2_nemo", "c3_llama_guard", "c4_combined", "c5_combined", "integracion_guardrails_ai"])
def test_perfiles_validan_sin_red_ni_credenciales(
    profile: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """La planificación C0–C5 y el perfil auxiliar funcionan incluso sin clientes ni secretos disponibles."""
    monkeypatch.setattr(sys, "argv", ["run_config.py", "--config", str(ROOT / f"configs/{profile}.yaml"), "--dry-run"])
    monkeypatch.setattr(httpx, "Client", forbid_network)
    monkeypatch.setattr(run_config, "load_dotenv", forbid_network)
    assert run_config.main() == 0


def test_c4_y_c5_siguen_la_definicion_del_anteproyecto() -> None:
    """C4 = C1 + C2 + C3 y C5 = C4 + Guardrails AI en la salida, sin otras diferencias."""
    c1, c2, c3, c4, c5 = (
        load_config(ROOT / f"configs/{name}.yaml")
        for name in ("c1_native", "c2_nemo", "c3_llama_guard", "c4_combined", "c5_combined")
    )
    assert c4.target == c5.target == c1.target
    assert c4.target.adapter == "openrouter_native_guarded"
    assert c4.guardrails == c2.guardrails + c3.guardrails
    structured = [guard for guard in c5.guardrails if guard.adapter == "structured"]
    assert len(structured) == 1 and structured[0].stages == ("output",)
    assert tuple(guard for guard in c5.guardrails if guard.adapter != "structured") == c4.guardrails
    assert c4.judge == c5.judge and c4.execution == c5.execution and c4.dataset == c5.dataset
    auxiliary = load_config(ROOT / "configs/integracion_guardrails_ai.yaml")
    assert auxiliary.config_id not in {f"C{index}" for index in range(6)}
    assert auxiliary.guardrails == tuple(structured)


@pytest.mark.parametrize("role", ["target", "judge", "guard"])
def test_cli_rechaza_adaptador_desconocido_antes_de_red_o_clave(
    role: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Un nombre inexistente nunca llega al catálogo ni a la construcción de servicios."""
    raw = load_config(BASELINE).to_dict()
    if role == "guard":
        raw["config_id"] = "UnknownGuardTest"
        raw["guardrails"] = [{
            "adapter": "nonexistent_guard", "name": "unknown", "stages": ["input"],
        }]
    else:
        raw[role]["adapter"] = "nonexistent_adapter"
    config = tmp_path / "unknown.yaml"
    config.write_text(yaml.safe_dump(raw), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["run_config.py", "--config", str(config)])
    monkeypatch.setattr(httpx, "Client", forbid_network)
    monkeypatch.setattr(run_config, "load_dotenv", forbid_network)

    with pytest.raises(SystemExit) as exc:
        run_config.main()

    assert exc.value.code == 2
    assert "Adaptador desconocido" in capsys.readouterr().err


@pytest.mark.parametrize(
    "arguments",
    [
        ["--max-concurrency", "0"],
        ["--requests-per-second", "nan"],
        ["--max-retries", "-1"],
        ["--retry-base-delay", "-0.1"],
        ["--target-model", "openai/gpt-4.1-mini"],
    ],
)
def test_cli_revalida_overrides_antes_de_mostrar_o_ejecutar_un_plan(
    arguments: list[str], monkeypatch: pytest.MonkeyPatch,
) -> None:
    """La línea de órdenes no puede saltarse las invariantes del YAML validado."""
    monkeypatch.setattr(
        sys, "argv", ["run_config.py", "--config", str(BASELINE), "--dry-run", *arguments],
    )
    monkeypatch.setattr(httpx, "Client", forbid_network)
    monkeypatch.setattr(run_config, "load_dotenv", forbid_network)

    with pytest.raises(SystemExit) as exc:
        run_config.main()

    assert exc.value.code == 2


class AllowingGuard:
    """Capa de prueba que se construye desde una especificación del registro."""

    def __init__(self, spec: GuardSpec, events: list[str]) -> None:
        self.name = spec.name
        self.stages = frozenset(Stage(value) for value in spec.stages)
        self.events = events

    def check(self, text: str, stage: Stage, context: JsonObject) -> GuardDecision:
        """Permite el paso y marca en qué etapa fue invocada."""
        assert text
        assert context["input_text"]
        assert "is_benign" not in context and "objective" not in context
        assert "prompt_id" not in context and "system_prompt" not in context
        self.events.append(f"guard:{stage.value}")
        return GuardDecision(False, "Prueba de paso", {"fixture": True}, 1.0, 0.0)


def custom_experiment() -> ExperimentConfig:
    """Carga una configuración válida que necesita fábricas ajenas a los nombres predefinidos."""
    raw = load_config(BASELINE).to_dict()
    raw["config_id"] = "RegistryIntegration"
    raw["seed"] = 734
    raw["dataset"] = str(PILOT)
    raw["target"] = {
        "adapter": "custom_target", "model": "fixture/target", "provider": "fixture-target",
    }
    raw["judge"] = {
        "adapter": "custom_judge", "model": "fixture/judge", "provider": "fixture-judge",
    }
    raw["guardrails"] = [{
        "adapter": "custom_guard", "name": "declared-layer", "stages": ["input", "output"],
    }]
    raw["execution"]["max_retries"] = 0
    raw["execution"]["requests_per_second"] = 1e9
    return parse_config(raw)


def custom_adapters(events: list[str]) -> Adapters:
    """Registra fábricas de prueba; no altera el núcleo ni sus adaptadores predeterminados."""
    adapters = Adapters(
        AdapterRegistry[TargetBuilder](), AdapterRegistry[JudgeBuilder](), AdapterRegistry[GuardBuilder](),
    )

    def target(spec: ModelSpec, client: OpenRouterClient, system_prompt: str, seed: int) -> TargetModel:
        assert "TFG-CANARIO-ZAFIRO-6821" in system_prompt
        assert seed == 734
        return OpenRouterTarget(client, spec.model, spec.provider, system_prompt, seed)

    def judge(spec: ModelSpec, client: OpenRouterClient, seed: int) -> Judge:
        assert seed == 734
        return LLMJudge(client, spec.model, spec.provider, seed)

    def guard(spec: GuardSpec, client: OpenRouterClient, seed: int) -> Guardrail:
        assert seed == 734
        return AllowingGuard(spec, events)

    adapters.targets.register("custom_target", target)
    adapters.judges.register("custom_judge", judge)
    adapters.guards.register("custom_guard", guard)
    return adapters


def fixture_transport(events: list[str]) -> httpx.MockTransport:
    """Emula solo la respuesta HTTP para comprobar el transporte de la declaración."""
    def intercept(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["seed"] == 734
        assert body["provider"]["allow_fallbacks"] is False
        if body["model"] == "fixture/target":
            assert body["provider"]["only"] == ["fixture-target"]
            events.append("target")
            content = "Respuesta inocua de prueba."
            cost = 0.001
        else:
            assert body["model"] == "fixture/judge"
            assert body["provider"]["only"] == ["fixture-judge"]
            events.append("judge")
            content = json.dumps({
                "success": False, "confidence": 1.0, "rationale_short": "No se cumple el objetivo.",
            })
            cost = 0.002
        return httpx.Response(200, json={
            "provider": "fixture-provider",
            "choices": [{"finish_reason": "stop", "message": {"content": content}}],
            "usage": {"cost": cost},
        })
    return httpx.MockTransport(intercept)


def test_registro_custom_ejecuta_declaracion_y_reanuda_sin_repetir_peticiones(tmp_path: Path) -> None:
    """La configuración decide adaptadores y etapas; la segunda ejecución preserva los bytes crudos."""
    exp = custom_experiment()
    events: list[str] = []
    adapters = custom_adapters(events)
    cases, digest = run_config.load_attacks(PILOT)
    output = tmp_path / "declarative-run.jsonl"
    with httpx.Client(transport=fixture_transport(events)) as http:
        assert run_config.run_campaign(
            http, cases, digest, exp.target.provider, FIXTURE_KEY, tmp_path,
            experiment=exp, adapters=adapters, run_id="declarative-run", git_state=GIT_STATE,
        ) == 0
        initial = output.read_bytes()
        assert run_config.run_campaign(
            http, cases, digest, exp.target.provider, FIXTURE_KEY, tmp_path,
            experiment=exp, adapters=adapters, run_id="declarative-run", git_state=GIT_STATE,
        ) == 0

    assert events == ["guard:input", "target", "guard:output", "judge"]
    assert output.read_bytes() == initial
    header, result = [json.loads(line) for line in initial.decode().splitlines()]
    assert header["config_id"] == result["config_id"] == "RegistryIntegration"
    assert header["config"]["declaration"] == exp.to_dict()
    assert header["config"]["target"]["adapter"] == "custom_target"
    assert header["config"]["judge"]["adapter"] == "custom_judge"
    assert header["config"]["guardrails"][0]["adapter"] == "custom_guard"
    assert result["target_model"] == "fixture/target"
    assert result["judge_name"] == "fixture/judge"
    assert result["total_cost_usd"] == pytest.approx(0.003)
    assert result["error"] is None


def test_reanudacion_rechaza_declaracion_cambiada_antes_de_inferir(tmp_path: Path) -> None:
    """Cambiar la política de una capa no puede añadir datos a una campaña existente."""
    exp = custom_experiment()
    events: list[str] = []
    adapters = custom_adapters(events)
    cases, digest = run_config.load_attacks(PILOT)
    with httpx.Client(transport=fixture_transport(events)) as http:
        assert run_config.run_campaign(
            http, cases, digest, exp.target.provider, FIXTURE_KEY, tmp_path,
            experiment=exp, adapters=adapters, run_id="changed-config", git_state=GIT_STATE,
        ) == 0
        path = tmp_path / "changed-config.jsonl"
        original = path.read_bytes()
        events.clear()
        changed = replace(exp, guardrails=(replace(exp.guardrails[0], options_json='{"policy":"changed"}'),))
        with pytest.raises(ValueError, match="configuración no coincide"):
            run_config.run_campaign(
                http, cases, digest, exp.target.provider, FIXTURE_KEY, tmp_path,
                experiment=changed, adapters=adapters, run_id="changed-config", git_state=GIT_STATE,
            )

    assert events == []
    assert path.read_bytes() == original


def test_campana_con_arbol_sucio_falla_antes_de_red_o_resultados(tmp_path: Path) -> None:
    """Una revisión sin guardar no inicia inferencias ni crea un JSONL experimental."""
    exp = custom_experiment()
    events: list[str] = []
    adapters = custom_adapters(events)
    cases, digest = run_config.load_attacks(PILOT)
    with httpx.Client(transport=httpx.MockTransport(forbid_network)) as http:
        with pytest.raises(ValueError, match="revisión Git limpia"):
            run_config.run_campaign(
                http, cases, digest, exp.target.provider, FIXTURE_KEY, tmp_path,
                experiment=exp, adapters=adapters, run_id="dirty-config", git_state=("a" * 40, True),
            )

    assert events == []
    assert list(tmp_path.iterdir()) == []


def test_reanudacion_incompatible_no_sanea_ni_un_byte_de_cola_incompleta(tmp_path: Path) -> None:
    """Un fichero ajeno al plan solicitado queda intacto, incluida su cola truncada."""
    exp = custom_experiment()
    events: list[str] = []
    adapters = custom_adapters(events)
    cases, digest = run_config.load_attacks(PILOT)
    with httpx.Client(transport=fixture_transport(events)) as http:
        assert run_config.run_campaign(
            http, cases, digest, exp.target.provider, FIXTURE_KEY, tmp_path,
            experiment=exp, adapters=adapters, run_id="foreign-tail", git_state=GIT_STATE,
        ) == 0
        path = tmp_path / "foreign-tail.jsonl"
        original = path.read_bytes() + b'{"record_type":"result","run_id":"truncated'
        path.write_bytes(original)
        events.clear()
        changed = replace(exp, guardrails=(replace(exp.guardrails[0], options_json='{"policy":"changed"}'),))
        with pytest.raises(ValueError, match="configuración no coincide"):
            run_config.run_campaign(
                http, cases, digest, exp.target.provider, FIXTURE_KEY, tmp_path,
                experiment=changed, adapters=adapters, run_id="foreign-tail", git_state=GIT_STATE,
            )

    assert events == []
    assert path.read_bytes() == original


def test_resultado_json_valido_pero_incompleto_no_se_salta_ni_se_sobrescribe(tmp_path: Path) -> None:
    """La mera presencia de run_id y prompt_id no constituye una ejecución finalizada."""
    exp = custom_experiment()
    events: list[str] = []
    adapters = custom_adapters(events)
    cases, digest = run_config.load_attacks(PILOT)
    with httpx.Client(transport=fixture_transport(events)) as http:
        assert run_config.run_campaign(
            http, cases, digest, exp.target.provider, FIXTURE_KEY, tmp_path,
            experiment=exp, adapters=adapters, run_id="incomplete-result", git_state=GIT_STATE,
        ) == 0
        path = tmp_path / "incomplete-result.jsonl"
        first_line = path.read_bytes().splitlines(keepends=True)[0]
        minimal_result = {
            "record_type": "result", "run_id": "incomplete-result",
            "prompt_id": cases[0].prompt_id,
        }
        original = first_line + json.dumps(minimal_result).encode() + b"\n"
        path.write_bytes(original)
        events.clear()
        with pytest.raises(ValueError):
            run_config.run_campaign(
                http, cases, digest, exp.target.provider, FIXTURE_KEY, tmp_path,
                experiment=exp, adapters=adapters, run_id="incomplete-result", git_state=GIT_STATE,
            )

    assert events == []
    assert path.read_bytes() == original


def test_cli_arbol_sucio_falla_antes_de_credenciales_o_catalogo(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """La barrera de versión también se aplica en el punto de entrada de usuario."""
    monkeypatch.setattr(sys, "argv", ["run_config.py", "--config", str(BASELINE)])
    monkeypatch.setattr(run_config, "_git_state", lambda: ("a" * 40, True))
    monkeypatch.setattr(httpx, "Client", forbid_network)
    monkeypatch.setattr(run_config, "load_dotenv", forbid_network)

    with pytest.raises(SystemExit) as exc:
        run_config.main()

    assert exc.value.code == 2
