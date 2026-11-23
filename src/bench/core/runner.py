"""Orquesta las etapas declaradas sin conocer adaptadores concretos."""

import json
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections.abc import Iterable, Iterator, Sequence
from time import perf_counter
from typing import Protocol

from bench.core.schema import (
    AttackPrompt, GuardrailBlocked, JsonObject, Stage, StageError, TargetResponse,
)
from bench.guards.base import Guardrail
from bench.judges.base import Judge
from bench.targets.base import TargetModel


class TargetFactory(Protocol):
    """Construye un adaptador que aplica el mensaje de sistema de un caso."""

    def __call__(self, attack: AttackPrompt) -> TargetModel:
        """Devuelve el modelo objetivo para el ataque recibido."""
        ...


class GuardFactory(Protocol):
    """Construye salvaguardas independientes para cada caso concurrente."""

    def __call__(self, attack: AttackPrompt) -> Sequence[Guardrail]:
        """Devuelve las capas en el orden declarado en la configuración."""
        ...


def run_one(
    run_id: str, attack: AttackPrompt, target: TargetModel, judge: Judge,
    *, config_id: str = "C0", guardrails: Sequence[Guardrail] = (),
    preparation_latency_ms: float | None = None,
) -> JsonObject:
    """Genera y juzga un caso, conservando los datos de etapas que ya terminaron.

    Latencias de pared del registro: ``total_latency_ms`` cubre la ejecución
    completa del caso; ``deployment_latency_ms`` termina cuando acaban las
    defensas de salida (o el primer bloqueo/error) y excluye todo el tiempo
    del juez, incluidas sus esperas de cuota y reintentos, que se registran en
    ``judge_wall_latency_ms``. ``preparation_latency_ms`` es la construcción de
    objetivo y defensas, previa al cronómetro de ejecución.
    """
    started = perf_counter()
    judge_started: float | None = None
    stages: list[JsonObject] = []
    record: JsonObject = {
        "record_type": "result",
        "run_id": run_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "config_id": config_id,
        "prompt_id": attack.prompt_id,
        "prompt_source": attack.prompt_source,
        "owasp_category": attack.owasp_category,
        "nist_category": attack.nist_category,
        "is_benign": attack.is_benign,
        "target_model": target.name,
        "provider": None,
        "model_params": target.params,
        "stages": stages,
        "blocked": False,
        "blocked_by": None,
        "response_text": None,
        "reasoning_chain": None,
        "target_raw": None,
        "judge_name": None,
        "judge_verdict": None,
        "judge_raw": None,
        "total_latency_ms": None,
        "deployment_latency_ms": None,
        "judge_wall_latency_ms": None,
        "preparation_latency_ms": preparation_latency_ms,
        "total_cost_usd": None,
        "error": None,
    }
    stage, name = "target", target.name
    # El criterio, las etiquetas de evaluación y el sistema/canaria no se
    # entregan a las defensas por defecto. Su política viene de su configuración.
    context: JsonObject = {"input_text": attack.prompt}

    def check_guards(position: Stage, text: str) -> bool:
        """Registra las decisiones y detiene el flujo en el primer bloqueo."""
        nonlocal stage, name
        for guard in guardrails:
            if position not in guard.stages:
                continue
            stage, name = position.value, guard.name
            decision = guard.check(text, position, context)
            stages.append({
                "stage": stage, "name": name, "status": "completed",
                "blocked": decision.blocked, "reason": decision.reason,
                "raw": decision.raw, "provider": decision.provider,
                "latency_ms": decision.latency_ms,
                "wall_latency_ms": decision.wall_latency_ms,
                "cost_usd": decision.cost_usd, "attempts": decision.attempts,
                "attempt_history": decision.attempt_history,
            })
            if decision.blocked:
                record.update(blocked=True, blocked_by={"stage": stage, "guardrail": name})
                return False
        return True

    try:
        if not check_guards(Stage.INPUT, attack.prompt):
            return record
        stage, name = "target", target.name
        response = target.generate(attack.prompt)
        stages.append({
            "stage": stage, "name": name, "status": "completed",
            "provider": response.provider, "latency_ms": response.latency_ms,
            "wall_latency_ms": response.wall_latency_ms,
            "cost_usd": response.cost_usd, "attempts": response.attempts,
            "attempt_history": response.attempt_history,
        })
        record.update(
            provider=response.provider, model_params=response.params, response_text=response.text,
            reasoning_chain=response.reasoning, target_raw=response.raw,
        )

        context.update(response_text=response.text, reasoning_chain=response.reasoning)
        output_text = json.dumps({
            "response_text": response.text, "reasoning_chain": response.reasoning,
        }, ensure_ascii=False)
        if not check_guards(Stage.OUTPUT, output_text):
            return record

        stage, name = "judge", judge.name
        judge_started = perf_counter()
        _judge_into(record, judge, attack, response)
    except GuardrailBlocked as remote_block:
        decision = remote_block.decision
        position = remote_block.stage.value
        stages.append({
            "stage": position, "name": remote_block.name, "status": "completed",
            "blocked": True, "reason": decision.reason, "raw": decision.raw,
            "provider": decision.provider, "latency_ms": decision.latency_ms,
            "wall_latency_ms": decision.wall_latency_ms, "cost_usd": decision.cost_usd,
            "attempts": decision.attempts, "attempt_history": decision.attempt_history,
            "observed_during": stage,
        })
        record.update(blocked=True, blocked_by={"stage": position, "guardrail": remote_block.name})
    except StageError as exc:
        stages.append({
            "stage": stage, "name": name, "status": "error", "reason": exc.code,
            "provider": exc.provider, "latency_ms": exc.latency_ms,
            "wall_latency_ms": exc.wall_latency_ms,
            "cost_usd": exc.cost_usd, "attempts": exc.attempts,
            "attempt_history": exc.attempt_history,
        })
        record.update(error={"stage": stage, "code": exc.code})
        if stage == "target":
            record.update(target_raw=exc.raw, provider=exc.provider)
        elif stage == "judge":
            record["judge_raw"] = exc.raw
        else:
            stages[-1]["raw"] = exc.raw
    finally:
        finished = perf_counter()
        record["total_latency_ms"] = (finished - started) * 1000
        deployment_end = finished if judge_started is None else judge_started
        record["deployment_latency_ms"] = (deployment_end - started) * 1000
        if judge_started is not None:
            record["judge_wall_latency_ms"] = (finished - judge_started) * 1000
        costs = [entry["cost_usd"] for entry in stages]
        if None not in costs:
            record["total_cost_usd"] = sum(costs)
    return record


def _judge_into(record: JsonObject, judge: Judge, attack: AttackPrompt,
                response: TargetResponse) -> None:
    """Arbitra una respuesta y añade la etapa y el veredicto al registro."""
    record["judge_name"] = judge.name
    verdict = judge.evaluate(attack, response)
    record["stages"].append({
        "stage": "judge", "name": judge.name, "status": "completed",
        "provider": verdict.provider, "latency_ms": verdict.latency_ms,
        "wall_latency_ms": verdict.wall_latency_ms,
        "cost_usd": verdict.cost_usd, "attempts": verdict.attempts,
        "attempt_history": verdict.attempt_history,
    })
    record.update(
        judge_raw=verdict.raw,
        judge_verdict={
            "success": verdict.success,
            "confidence": verdict.confidence,
            "rationale_short": verdict.rationale_short,
        },
    )


def rejudge_one(run_id: str, attack: AttackPrompt, judge: Judge, source: JsonObject) -> JsonObject:
    """Repite solo el arbitraje de una generación ya registrada.

    ``source`` es el primer registro del caso cuya generación superó todas las
    defensas y cuyo juez falló sin negativa. La generación, las defensas y sus
    costes se copian marcados con ``reused: true``: ya se contabilizaron en
    ``source``, por lo que ``total_cost_usd`` de este registro solo incluye el
    nuevo arbitraje. ``resumed_from`` enlaza el intento técnico con su origen.
    """
    error = source.get("error")
    if (
        source.get("prompt_id") != attack.prompt_id or source.get("blocked") is not False
        or not isinstance(error, dict) or error.get("stage") != "judge"
    ):
        raise ValueError("Solo se rearbitra una generación entregada cuyo juez falló")
    target_stage = next(
        (item for item in source["stages"]
         if item.get("stage") == "target" and item.get("status") == "completed"),
        None,
    )
    if target_stage is None:
        raise ValueError("El registro de origen no tiene una generación completada")
    response = TargetResponse(
        text=source.get("response_text"), reasoning=source.get("reasoning_chain"),
        provider=source.get("provider"), params=source.get("model_params") or {},
        latency_ms=float(target_stage.get("latency_ms") or 0.0),
        cost_usd=target_stage.get("cost_usd"), raw=source.get("target_raw") or {},
        attempts=int(target_stage.get("attempts") or 1),
        attempt_history=target_stage.get("attempt_history"),
        wall_latency_ms=target_stage.get("wall_latency_ms"),
    )
    reused = [
        {**item, "reused": True} for item in source["stages"] if item.get("stage") != "judge"
    ]
    stages: list[JsonObject] = list(reused)
    record: JsonObject = {
        **{key: value for key, value in source.items() if key not in {"stages"}},
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id,
        "stages": stages,
        "judge_name": None, "judge_verdict": None, "judge_raw": None, "error": None,
        "total_cost_usd": None, "judge_wall_latency_ms": None,
        "resumed_from": {
            "timestamp": source.get("timestamp"),
            "reason": f"judge:{error.get('code')}",
            "reused": "target_and_defences",
        },
    }
    started = perf_counter()
    try:
        _judge_into(record, judge, attack, response)
    except StageError as exc:
        stages.append({
            "stage": "judge", "name": judge.name, "status": "error", "reason": exc.code,
            "provider": exc.provider, "latency_ms": exc.latency_ms,
            "wall_latency_ms": exc.wall_latency_ms, "cost_usd": exc.cost_usd,
            "attempts": exc.attempts, "attempt_history": exc.attempt_history,
        })
        record.update(error={"stage": "judge", "code": exc.code}, judge_raw=exc.raw)
    finally:
        judge_wall = (perf_counter() - started) * 1000
        record["judge_wall_latency_ms"] = judge_wall
        # El despliegue se mide en el registro de origen; aquí se conserva y el
        # total suma el nuevo arbitraje (los registros antiguos no lo tienen).
        deployment = source.get("deployment_latency_ms")
        record["deployment_latency_ms"] = deployment
        record["total_latency_ms"] = None if deployment is None else deployment + judge_wall
        new_costs = [item["cost_usd"] for item in stages if not item.get("reused")]
        if None not in new_costs:
            record["total_cost_usd"] = sum(new_costs)
    return record


def run_batch(
    run_id: str,
    attacks: Iterable[AttackPrompt],
    target_factory: TargetFactory,
    judge: Judge,
    max_concurrency: int,
    *, config_id: str = "C0", guard_factory: GuardFactory | None = None,
) -> Iterator[JsonObject]:
    """Ejecuta casos en paralelo y entrega cada resultado al terminar."""
    if max_concurrency < 1:
        raise ValueError("max_concurrency debe ser al menos 1")
    case_list = list(attacks)
    if not case_list:
        raise ValueError("La ejecución requiere al menos un ataque")
    # Todas las fábricas se validan antes de enviar el primer trabajo pagado.
    # Su tiempo se registra aparte como preparación de cada caso.
    prepared = []
    for attack in case_list:
        prep_started = perf_counter()
        target = target_factory(attack)
        guards = guard_factory(attack) if guard_factory else ()
        prepared.append((attack, target, guards, (perf_counter() - prep_started) * 1000))
    with ThreadPoolExecutor(max_workers=max_concurrency) as executor:
        futures = {
            executor.submit(
                run_one, run_id, attack, target, judge,
                config_id=config_id,
                guardrails=guards,
                preparation_latency_ms=preparation,
            ): attack
            for attack, target, guards, preparation in prepared
        }
        for future in as_completed(futures):
            yield future.result()
