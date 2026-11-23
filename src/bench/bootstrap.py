"""Conecta los nombres usados en los YAML con cada implementación (objetivo, filtros y juez)."""

from dataclasses import dataclass, field
from collections.abc import Callable
from typing import Protocol

from bench.core.config import ExperimentConfig, GuardSpec, ModelSpec
from bench.core.registry import AdapterRegistry
from bench.core.schema import AttackPrompt, Stage
from bench.guards.base import Guardrail
from bench.guards.llama_guard import build_llama_guard, validate_llama_guard_spec
from bench.guards.nemo import build_nemo_guard, validate_nemo_spec
from bench.guards.structured import build_structured_guard, validate_structured_spec
from bench.judges.base import Judge
from bench.judges.llm_judge import LLMJudge
from bench.openrouter import OpenRouterClient
from bench.targets.base import TargetModel
from bench.targets.openrouter import OpenRouterTarget
from bench.targets.openrouter_native import native_target


class TargetBuilder(Protocol):
    """Firma de una fábrica de modelos objetivo."""

    def __call__(self, spec: ModelSpec, client: OpenRouterClient,
                 system_prompt: str, seed: int) -> TargetModel:
        ...


class JudgeBuilder(Protocol):
    """Firma de una fábrica de jueces."""

    def __call__(self, spec: ModelSpec, client: OpenRouterClient, seed: int) -> Judge:
        ...


class GuardBuilder(Protocol):
    """Firma de una fábrica de salvaguardas."""

    def __call__(self, spec: GuardSpec, client: OpenRouterClient, seed: int) -> Guardrail:
        ...


@dataclass
class Adapters:
    """Registros separados por el contrato que construye cada fábrica."""

    targets: AdapterRegistry[TargetBuilder]
    judges: AdapterRegistry[JudgeBuilder]
    guards: AdapterRegistry[GuardBuilder]
    guard_validators: dict[str, Callable[[GuardSpec], None]] = field(default_factory=dict)

    def validate(self, config: ExperimentConfig) -> None:
        """Resuelve nombres sin construir clientes ni hacer llamadas."""
        self.targets.resolve(config.target.adapter)
        self.judges.resolve(config.judge.adapter)
        for spec in config.guardrails:
            self.guards.resolve(spec.adapter)
            validator = self.guard_validators.get(spec.adapter)
            if validator is not None:
                validator(spec)

    def register_guard(self, adapter: str, builder: GuardBuilder,
                       validator: Callable[[GuardSpec], None]) -> None:
        """Registra construcción y validación sin red de una salvaguarda."""
        self.guards.register(adapter, builder)
        self.guard_validators[adapter] = validator


def _target(spec: ModelSpec, client: OpenRouterClient,
            system_prompt: str, seed: int) -> TargetModel:
    return OpenRouterTarget(client, spec.model, spec.provider, system_prompt, seed)


def _judge(spec: ModelSpec, client: OpenRouterClient, seed: int) -> Judge:
    return LLMJudge(client, spec.model, spec.provider, seed)


def _native_target(spec: ModelSpec, client: OpenRouterClient,
                   system_prompt: str, seed: int) -> TargetModel:
    return native_target(client, spec.model, spec.provider, system_prompt, seed)


def default_adapters() -> Adapters:
    """Registra solo implementaciones disponibles; no crea capas ficticias."""
    adapters = Adapters(AdapterRegistry(), AdapterRegistry(), AdapterRegistry())
    adapters.targets.register("openrouter", _target)
    adapters.targets.register("openrouter_native_guarded", _native_target)
    adapters.judges.register("openrouter_llm", _judge)
    adapters.register_guard("llama_guard", build_llama_guard, validate_llama_guard_spec)
    adapters.register_guard("nemo", build_nemo_guard, validate_nemo_spec)
    adapters.register_guard("structured", build_structured_guard, validate_structured_spec)
    return adapters


@dataclass
class Runtime:
    """Servicios compartidos y fábricas independientes de cada caso."""

    config: ExperimentConfig
    adapters: Adapters
    client: OpenRouterClient
    judge: Judge

    def target(self, attack: AttackPrompt) -> TargetModel:
        """Aplica el mensaje de sistema del caso al modelo declarado."""
        return self.adapters.targets.resolve(self.config.target.adapter)(
            self.config.target, self.client, attack.system_prompt, self.config.seed,
        )

    def guards(self, attack: AttackPrompt) -> tuple[Guardrail, ...]:
        """Crea capas por caso, preservando su orden y validando sus etapas."""
        result: list[Guardrail] = []
        for spec in self.config.guardrails:
            guard = self.adapters.guards.resolve(spec.adapter)(
                spec, self.client, self.config.seed,
            )
            expected = frozenset(Stage(stage) for stage in spec.stages)
            if guard.name != spec.name or guard.stages != expected:
                raise ValueError(f"El adaptador {spec.adapter} no respeta nombre/etapas declarados")
            result.append(guard)
        return tuple(result)


def build_runtime(config: ExperimentConfig, client: OpenRouterClient,
                  adapters: Adapters | None = None) -> Runtime:
    """Ensambla el flujo a partir de nombres registrados."""
    selected = adapters if adapters is not None else default_adapters()
    selected.validate(config)
    judge = selected.judges.resolve(config.judge.adapter)(config.judge, client, config.seed)
    return Runtime(config, selected, client, judge)


def remote_model_routes(config: ExperimentConfig) -> list[tuple[str, ModelSpec]]:
    """Enumera modelos remotos declarados para comprobar sus proveedores antes de pagar."""
    routes = [("objetivo", config.target), ("juez", config.judge)]
    for guard in config.guardrails:
        options = guard.options
        model, provider = options.get("model"), options.get("provider")
        if guard.adapter == "llama_guard":
            model = options.get("model", "meta-llama/llama-guard-4-12b")
            provider = options.get("provider", "deepinfra")
        if guard.adapter == "nemo":
            model = options.get("model", "openai/gpt-4.1-nano")
            provider = options.get("provider", "azure")
        if isinstance(model, str) and isinstance(provider, str):
            routes.append((guard.name, ModelSpec("openrouter", model, provider)))
    return routes
