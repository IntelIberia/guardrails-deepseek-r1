"""Carga declarativa estricta de un experimento, sin construir adaptadores."""

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from math import isfinite
from pathlib import Path
from typing import Any

import yaml
from yaml.nodes import MappingNode

from bench.core.schema import JsonObject


class ConfigError(ValueError):
    """La configuración no cumple el contrato del banco de pruebas."""


class _UniqueSafeLoader(yaml.SafeLoader):
    """Cargador YAML que rechaza claves repetidas."""

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Any, Any]:
        self.flatten_mapping(node)
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise ConfigError("Las claves de configuración deben ser cadenas")
            if key in mapping:
                raise ConfigError(f"Clave YAML duplicada en la línea {key_node.start_mark.line + 1}")
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


@dataclass(frozen=True)
class ModelSpec:
    """Identifica el adaptador, el modelo y su proveedor fijado."""

    adapter: str
    model: str
    provider: str

    def to_dict(self) -> JsonObject:
        return {"adapter": self.adapter, "model": self.model, "provider": self.provider}


@dataclass(frozen=True)
class GuardSpec:
    """Describe una salvaguarda; sus opciones se conservan como JSON inmutable."""

    adapter: str
    name: str
    stages: tuple[str, ...]
    options_json: str = "{}"

    @property
    def options(self) -> JsonObject:
        """Entrega una copia nueva para que el adaptador no modifique la configuración."""
        value: JsonObject = json.loads(self.options_json)
        return value

    def to_dict(self) -> JsonObject:
        """Devuelve las opciones como objeto JSON y no como una cadena anidada."""
        return {
            "adapter": self.adapter, "name": self.name,
            "stages": list(self.stages), "options": self.options,
        }


@dataclass(frozen=True)
class ExecutionConfig:
    """Límites del ejecutor y del transporte compartido."""

    timeout_seconds: float = 180.0
    max_concurrency: int = 2
    requests_per_second: float = 1.0
    max_retries: int = 3
    retry_base_delay_seconds: float = 1.0

    def to_dict(self) -> JsonObject:
        """Expone los límites efectivos para la cabecera del experimento."""
        return {
            "timeout_seconds": self.timeout_seconds,
            "max_concurrency": self.max_concurrency,
            "requests_per_second": self.requests_per_second,
            "max_retries": self.max_retries,
            "retry_base_delay_seconds": self.retry_base_delay_seconds,
        }


@dataclass(frozen=True)
class ExperimentConfig:
    """Declaración completa de una configuración experimental."""

    schema_version: int
    config_id: str
    dataset: str
    seed: int
    target: ModelSpec
    judge: ModelSpec
    guardrails: tuple[GuardSpec, ...]
    execution: ExecutionConfig

    def to_dict(self) -> JsonObject:
        """Produce una copia JSON estable, apta para huellas y registros."""
        return {
            "schema_version": self.schema_version, "config_id": self.config_id,
            "dataset": self.dataset, "seed": self.seed,
            "target": self.target.to_dict(), "judge": self.judge.to_dict(),
            "guardrails": [guard.to_dict() for guard in self.guardrails],
            "execution": self.execution.to_dict(),
        }


def _mapping(value: Any, path: str, required: set[str], optional: set[str] | None = None) -> JsonObject:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ConfigError(f"{path} debe ser un objeto con claves de texto")
    missing = required - value.keys()
    unknown = value.keys() - required - (optional or set())
    if missing:
        raise ConfigError(f"Faltan campos en {path}: {', '.join(sorted(missing))}")
    if unknown:
        raise ConfigError(f"Campos desconocidos en {path}: {', '.join(sorted(unknown))}")
    return value


def _text(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ConfigError(f"{path} debe ser texto no vacío sin espacios exteriores")
    return value


def _integer(value: Any, path: str, minimum: int | None = None) -> int:
    if type(value) is not int or (minimum is not None and value < minimum):
        requirement = "entero" if minimum is None else f"entero mayor o igual que {minimum}"
        raise ConfigError(f"{path} debe ser {requirement}")
    return value


def _number(value: Any, path: str, *, positive: bool) -> float:
    if type(value) not in (int, float):
        raise ConfigError(f"{path} debe ser un número finito")
    try:
        number = float(value)
    except OverflowError as exc:
        raise ConfigError(f"{path} debe ser un número finito") from exc
    if not isfinite(number) or (number <= 0 if positive else number < 0):
        requirement = "positivo" if positive else "no negativo"
        raise ConfigError(f"{path} debe ser un número finito {requirement}")
    return number


def _model(value: Any, path: str) -> ModelSpec:
    data = _mapping(value, path, {"adapter", "model", "provider"})
    return ModelSpec(*(_text(data[key], f"{path}.{key}") for key in ("adapter", "model", "provider")))


def _json_value(value: Any, active: set[int], depth: int = 0) -> None:
    """Rechaza ciclos, tipos propios de YAML y números JSON no finitos."""
    if depth > 32:
        raise ConfigError("Las opciones superan la profundidad máxima de 32 niveles")
    if value is None or type(value) in (str, bool, int):
        return
    if type(value) is float and isfinite(value):
        return
    if isinstance(value, (list, dict)):
        if id(value) in active:
            raise ConfigError("Las opciones no pueden contener referencias cíclicas")
        active.add(id(value))
        children: Iterable[Any]
        if isinstance(value, dict):
            if not all(isinstance(key, str) for key in value):
                raise ConfigError("Las claves de opciones deben ser cadenas")
            children = value.values()
        else:
            children = value
        for child in children:
            _json_value(child, active, depth + 1)
        active.remove(id(value))
        return
    raise ConfigError("Las opciones solo admiten tipos JSON y números finitos")


def _guard(value: Any, index: int) -> GuardSpec:
    path = f"guardrails[{index}]"
    data = _mapping(value, path, {"adapter", "name", "stages"}, {"options"})
    stages = data["stages"]
    if (
        not isinstance(stages, list) or not stages
        or any(type(stage) is not str or stage not in {"input", "output"} for stage in stages)
        or len(stages) != len(set(stages))
    ):
        raise ConfigError(f"{path}.stages debe listar input/output sin duplicados")
    options = data.get("options", {})
    if not isinstance(options, dict):
        raise ConfigError(f"{path}.options debe ser un objeto JSON")
    _json_value(options, set())
    return GuardSpec(
        _text(data["adapter"], f"{path}.adapter"), _text(data["name"], f"{path}.name"),
        tuple(stages), json.dumps(options, ensure_ascii=False, sort_keys=True, allow_nan=False),
    )


def parse_config(value: object) -> ExperimentConfig:
    """Valida los campos declarados antes de acceder a servicios o credenciales."""
    data = _mapping(value, "config", {
        "schema_version", "config_id", "dataset", "seed", "target", "judge", "guardrails", "execution",
    })
    version = _integer(data["schema_version"], "schema_version")
    if version != 1:
        raise ConfigError("schema_version debe ser 1")
    config_id = _text(data["config_id"], "config_id")
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", config_id):
        raise ConfigError("config_id debe ser un identificador de hasta 64 caracteres")
    target, judge = _model(data["target"], "target"), _model(data["judge"], "judge")
    if target.model == judge.model:
        raise ConfigError("El modelo del juez debe ser distinto del modelo objetivo")
    if not isinstance(data["guardrails"], list):
        raise ConfigError("guardrails debe ser una lista")
    guards = tuple(_guard(value, index) for index, value in enumerate(data["guardrails"]))
    if len({guard.name for guard in guards}) != len(guards):
        raise ConfigError("Los nombres de guardrails deben ser únicos")
    if config_id == "C0" and guards:
        raise ConfigError("C0 no puede declarar guardrails externos")
    execution = _mapping(data["execution"], "execution", {
        "timeout_seconds", "max_concurrency", "requests_per_second",
        "max_retries", "retry_base_delay_seconds",
    })
    limits = ExecutionConfig(
        timeout_seconds=_number(execution["timeout_seconds"], "execution.timeout_seconds", positive=True),
        max_concurrency=_integer(execution["max_concurrency"], "execution.max_concurrency", 1),
        requests_per_second=_number(execution["requests_per_second"], "execution.requests_per_second", positive=True),
        max_retries=_integer(execution["max_retries"], "execution.max_retries", 0),
        retry_base_delay_seconds=_number(execution["retry_base_delay_seconds"], "execution.retry_base_delay_seconds", positive=False),
    )
    return ExperimentConfig(
        version, config_id, _text(data["dataset"], "dataset"), _integer(data["seed"], "seed"),
        target, judge, guards, limits,
    )


def load_config(path: Path) -> ExperimentConfig:
    """Lee un YAML seguro con claves únicas y aplica el contrato estricto."""
    try:
        raw = yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueSafeLoader)
    except (yaml.YAMLError, UnicodeError) as exc:
        raise ConfigError("El fichero no es una configuración YAML UTF-8 válida") from exc
    return parse_config(raw)
