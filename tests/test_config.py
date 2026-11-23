"""Valida la declaración del experimento antes de construir servicios externos."""

import copy
import json
from collections.abc import Callable
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any

import pytest
import yaml

from bench.core.config import ConfigError, load_config, parse_config
from bench.core.registry import AdapterRegistry, RegistryError

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "configs/c0_baseline.yaml"


def declaration() -> dict[str, Any]:
    """Obtiene el YAML de referencia como entrada independiente del validador."""
    raw: dict[str, Any] = yaml.safe_load(BASELINE.read_text())
    return copy.deepcopy(raw)


def test_config_baseline_preserva_la_declaracion_y_es_inmutable() -> None:
    """El plan conserva modelo/proveedor, límites y la ausencia de guardrails de C0."""
    config = load_config(BASELINE)
    assert config.config_id == "C0"
    assert config.guardrails == ()
    assert config.target.model == "deepseek/deepseek-r1-0528"
    assert config.target.provider == "deepinfra"
    assert config.judge.provider == "openai"
    assert config.to_dict() == declaration()
    assert json.loads(json.dumps(config.to_dict(), allow_nan=False)) == declaration()
    with pytest.raises(FrozenInstanceError):
        setattr(config, "seed", 1)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("timeout_seconds", 0), ("timeout_seconds", float("nan")),
        ("timeout_seconds", float("inf")), ("timeout_seconds", True),
        ("max_concurrency", 0), ("max_concurrency", True),
        ("max_concurrency", 1.5), ("requests_per_second", -1),
        ("requests_per_second", float("nan")), ("max_retries", -1),
        ("max_retries", False), ("retry_base_delay_seconds", -0.1),
        ("retry_base_delay_seconds", float("inf")),
    ],
)
def test_config_rechaza_limites_no_ejecutables(field: str, value: object) -> None:
    """Los bool y números no finitos nunca alcanzan el transporte o el ejecutor."""
    raw = declaration()
    raw["execution"][field] = value
    with pytest.raises(ConfigError, match=f"execution.{field}"):
        parse_config(raw)


@pytest.mark.parametrize(
    ("field", "value"),
    [("schema_version", 2), ("schema_version", True), ("seed", True), ("config_id", "../C0"), ("dataset", "")],
)
def test_config_rechaza_versiones_y_identificadores_incorrectos(field: str, value: object) -> None:
    """Los identificadores no pueden introducir rutas ni tipos implícitos de YAML."""
    raw = declaration()
    raw[field] = value
    with pytest.raises(ConfigError):
        parse_config(raw)


def test_config_rechaza_campos_desconocidos_y_juez_no_independiente() -> None:
    """Un error ortográfico o usar el objetivo como juez causa un fallo explícito."""
    raw = declaration()
    raw["execution"]["request_per_second"] = 1
    with pytest.raises(ConfigError, match="desconocidos"):
        parse_config(raw)
    raw = declaration()
    raw["judge"]["model"] = raw["target"]["model"]
    with pytest.raises(ConfigError, match="distinto"):
        parse_config(raw)


def test_config_rechaza_campos_obligatorios_ausentes() -> None:
    """La ausencia de proveedor no activa un enrutamiento implícito."""
    raw = declaration()
    del raw["target"]["provider"]
    with pytest.raises(ConfigError, match="provider"):
        parse_config(raw)


def test_yaml_rechaza_claves_duplicadas_y_etiquetas_ejecutables(tmp_path: Path) -> None:
    """YAML no puede sobrescribir valores ni construir objetos de Python."""
    path = tmp_path / "bad.yaml"
    path.write_text(BASELINE.read_text() + "\nseed: 99\n")
    with pytest.raises(ConfigError, match="duplicada"):
        load_config(path)
    path.write_text("!!python/object/apply:builtins.print [no-debe-ejecutarse]\n")
    with pytest.raises(ConfigError, match="YAML"):
        load_config(path)


def guarded_declaration() -> dict[str, Any]:
    """Describe un adaptador futuro sin construirlo ni confundirlo con evidencia real."""
    raw = declaration()
    raw["config_id"] = "C3"
    raw["guardrails"] = [{
        "adapter": "test_guard", "name": "guard_input", "stages": ["input"],
        "options": {"policy": {"labels": ["a", "b"]}},
    }]
    return raw


def test_guard_options_no_comparten_estado_mutable_con_el_adaptador() -> None:
    """Modificar opciones entregadas a un adaptador no cambia la configuración guardada."""
    config = parse_config(guarded_declaration())
    options = config.guardrails[0].options
    options["policy"]["labels"].append("c")
    assert config.guardrails[0].options == {"policy": {"labels": ["a", "b"]}}
    assert config.to_dict()["guardrails"][0]["options"] == {"policy": {"labels": ["a", "b"]}}


def test_guard_rechaza_etapas_desconocidas_y_nombres_duplicados() -> None:
    """El orden declarado debe corresponder a etapas conocidas e instancias únicas."""
    raw = guarded_declaration()
    raw["guardrails"][0]["stages"] = ["reasoning"]
    with pytest.raises(ConfigError, match="stages"):
        parse_config(raw)
    raw = guarded_declaration()
    raw["guardrails"].append(copy.deepcopy(raw["guardrails"][0]))
    with pytest.raises(ConfigError, match="únicos"):
        parse_config(raw)
    raw = guarded_declaration()
    raw["config_id"] = "C0"
    with pytest.raises(ConfigError, match="C0"):
        parse_config(raw)


def test_guard_options_rechazan_nan_ciclos_y_tipos_ajenos_a_json(tmp_path: Path) -> None:
    """Las opciones no pueden producir una huella JSON inválida o recursión infinita."""
    raw = guarded_declaration()
    raw["guardrails"][0]["options"] = {"threshold": float("nan")}
    with pytest.raises(ConfigError, match="JSON"):
        parse_config(raw)
    path = tmp_path / "recursive.yaml"
    raw = guarded_declaration()
    recursive: dict[str, Any] = {}
    recursive["self"] = recursive
    raw["guardrails"][0]["options"] = recursive
    path.write_text(yaml.safe_dump(raw))
    with pytest.raises(ConfigError, match="cíclicas"):
        load_config(path)
    raw = guarded_declaration()
    raw["guardrails"][0]["options"] = {"unsupported": object()}
    with pytest.raises(ConfigError, match="JSON"):
        parse_config(raw)


def test_registry_resuelve_factories_y_rechaza_duplicados_o_desconocidos() -> None:
    """Añadir una fábrica no cambia el núcleo ni permite sustituir otra silenciosamente."""
    registry: AdapterRegistry[Callable[[int], str]] = AdapterRegistry()
    factory = lambda number: f"modelo-{number}"
    registry.register("example", factory)
    assert registry.resolve("example")(3) == "modelo-3"
    assert registry.names() == ("example",)
    with pytest.raises(RegistryError, match="ya registrado"):
        registry.register("example", factory)
    with pytest.raises(RegistryError, match="desconocido"):
        registry.resolve("os.system")
