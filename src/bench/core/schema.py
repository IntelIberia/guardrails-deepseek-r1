"""Tipos de datos que se intercambian el objetivo, los filtros, el juez y el motor."""

from dataclasses import dataclass
from enum import Enum
from typing import Any, TypeAlias

JsonObject: TypeAlias = dict[str, Any]


class Stage(str, Enum):
    """Posición de una salvaguarda en el flujo."""

    INPUT = "input"
    OUTPUT = "output"


@dataclass(frozen=True)
class GuardDecision:
    """Decisión observada de una salvaguarda y metadatos de su evaluación."""

    blocked: bool
    reason: str
    raw: JsonObject
    latency_ms: float
    cost_usd: float | None
    provider: str | None = None
    attempts: int = 1
    attempt_history: list[JsonObject] | None = None
    wall_latency_ms: float | None = None


class GuardrailBlocked(Exception):
    """Comunica un bloqueo observado en una capa externa durante otra llamada."""

    def __init__(self, name: str, stage: Stage, decision: GuardDecision) -> None:
        if not decision.blocked:
            raise ValueError("GuardrailBlocked requiere una decisión de bloqueo")
        super().__init__(decision.reason)
        self.name = name
        self.stage = stage
        self.decision = decision


@dataclass(frozen=True)
class AttackPrompt:
    """Caso documentado y criterio de éxito para el juez."""

    prompt_id: str
    prompt_source: str
    owasp_category: str
    nist_category: str
    is_benign: bool
    system_prompt: str
    prompt: str
    objective: str


@dataclass(frozen=True)
class TargetResponse:
    """Contenido y metadatos devueltos por el modelo objetivo."""

    text: str | None
    reasoning: str | None
    provider: str | None
    params: JsonObject
    latency_ms: float
    cost_usd: float | None
    raw: JsonObject
    attempts: int = 1
    attempt_history: list[JsonObject] | None = None
    wall_latency_ms: float | None = None


@dataclass(frozen=True)
class Verdict:
    """Etiqueta binaria, confianza declarada y motivo breve."""

    success: bool
    confidence: float
    rationale_short: str
    provider: str | None
    latency_ms: float
    cost_usd: float | None
    raw: JsonObject
    attempts: int = 1
    attempt_history: list[JsonObject] | None = None
    wall_latency_ms: float | None = None


class StageError(Exception):
    """Fallo de una etapa, con los datos disponibles de la llamada."""

    def __init__(
        self,
        code: str,
        raw: JsonObject | None = None,
        latency_ms: float | None = None,
        cost_usd: float | None = None,
        provider: str | None = None,
        attempts: int = 1,
        attempt_history: list[JsonObject] | None = None,
        wall_latency_ms: float | None = None,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.raw = raw
        self.latency_ms = latency_ms
        self.cost_usd = cost_usd
        self.provider = provider
        self.attempts = attempts
        self.attempt_history = attempt_history
        self.wall_latency_ms = wall_latency_ms
