"""Nivel 1 de eval_v2: pasa cada prompt solo por los filtros de entrada.

Filtros (independientes; cada prompt se envía a todos, no se detiene en el primero):
- nemo_input: raíl de entrada de NeMo con su moderador (política tfg_nemo_input_output_v1);
- llama_guard_input: Llama Guard 4 con su política nativa, solo la entrada;
- openrouter_native: filtro nativo de OpenRouter (C1). Se hace una llamada real al
  objetivo con la clave nativa y max_tokens muy bajo. Un 403 del detector es un
  bloqueo (coste 0); cualquier respuesta, completa o truncada por max_tokens,
  significa que la petición pasó el filtro. Solo mide la detección de entrada:
  la respuesta truncada no se evalúa.

Las especificaciones de NeMo, Llama Guard 4 y del objetivo se leen del YAML de
C4 (configs/c4_combined.yaml) para usar exactamente las mismas políticas que en
el nivel 2. Registro JSONL con cabecera, identidad del código y reanudación.

Uso:
    PYTHONPATH=src .venv/bin/python scripts/run_input_screening.py \
        --input data/attacks/screen_v2.jsonl --part 1 --run-id sc2-p1 --dry-run
"""

import argparse
import fcntl
import json
import os
import sys
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bench.core.schema import AttackPrompt, GuardrailBlocked, JsonObject, Stage, StageError  # noqa: E402
from scripts.run_config import (  # noqa: E402
    RUN_ID_PATTERN, _canonical_hash, _code_fingerprint, _git_state, load_attacks, write_jsonl_line,
)

DEFAULT_INPUT = ROOT / "data/attacks/screen_v2.jsonl"
DEFAULT_MANIFEST = ROOT / "data/attacks/screen_v2_manifest.json"
DEFAULT_GUARDS_CONFIG = ROOT / "configs/c4_combined.yaml"
FILTERS = ("nemo_input", "llama_guard_input", "openrouter_native")
NATIVE_MAX_TOKENS = 16
SCHEMA_VERSION = 1


@dataclass(frozen=True)
class FilterResult:
    """Decisión de un filtro de entrada sobre un prompt."""

    status: str  # blocked | passed | error
    reason: str | None
    error_code: str | None
    cost_usd: float | None
    latency_ms: float | None
    provider: str | None
    attempts: int
    raw: JsonObject | None


FilterFn = Callable[[AttackPrompt], FilterResult]


def guard_filter(guard: Any) -> FilterFn:
    """Adapta una salvaguarda del banco (Guardrail) a un filtro de entrada aislado."""
    def run(attack: AttackPrompt) -> FilterResult:
        try:
            decision = guard.check(attack.prompt, Stage.INPUT, {"input_text": attack.prompt})
        except StageError as exc:
            return FilterResult("error", None, exc.code, exc.cost_usd, exc.latency_ms,
                                exc.provider, exc.attempts, exc.raw)
        return FilterResult("blocked" if decision.blocked else "passed", decision.reason, None,
                            decision.cost_usd, decision.latency_ms, decision.provider,
                            decision.attempts, decision.raw)
    return run


def native_filter(make_target: Callable[[AttackPrompt], Any]) -> FilterFn:
    """Llamada mínima al objetivo con la clave nativa: 403 del detector = bloqueo."""
    def run(attack: AttackPrompt) -> FilterResult:
        target = make_target(attack)
        try:
            response = target.generate(attack.prompt)
        except GuardrailBlocked as block:
            decision = block.decision
            return FilterResult("blocked", decision.reason, None, decision.cost_usd,
                                decision.latency_ms, decision.provider, decision.attempts, None)
        except StageError as exc:
            if exc.code == "target_incomplete":
                # Truncada por max_tokens: la petición atravesó el filtro.
                return FilterResult("passed", "truncada_por_max_tokens", None, exc.cost_usd,
                                    exc.latency_ms, exc.provider, exc.attempts, None)
            return FilterResult("error", None, exc.code, exc.cost_usd, exc.latency_ms,
                                exc.provider, exc.attempts, exc.raw)
        return FilterResult("passed", "respuesta_recibida", None, response.cost_usd,
                            response.latency_ms, response.provider, response.attempts, None)
    return run


def result_record(run_id: str, attack: AttackPrompt, name: str, result: FilterResult,
                  wall_ms: float) -> JsonObject:
    return {
        "record_type": "result", "run_id": run_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "prompt_id": attack.prompt_id, "filter": name, "is_benign": attack.is_benign,
        "status": result.status, "reason": result.reason, "error_code": result.error_code,
        "cost_usd": result.cost_usd, "latency_ms": result.latency_ms, "wall_ms": wall_ms,
        "provider": result.provider, "attempts": result.attempts, "raw": result.raw,
    }


def completed_pairs(path: Path, header: JsonObject) -> set[tuple[str, str]]:
    """Valida un JSONL reanudable y devuelve los pares (prompt, filtro) terminados."""
    lines = path.read_text(encoding="utf-8").removesuffix("\n").split("\n")
    stored = json.loads(lines[0]) if lines else {}
    if (not isinstance(stored, dict) or stored.get("record_type") != "header"
            or stored.get("run_id") != header["run_id"]
            or stored.get("config_fingerprint") != header["config_fingerprint"]):
        raise ValueError("La configuración no coincide con la ejecución que se quiere reanudar")
    done: set[tuple[str, str]] = set()
    for number, line in enumerate(lines[1:], start=2):
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"JSONL dañado en la línea {number}") from exc
        if record.get("run_id") != header["run_id"] or record.get("record_type") != "result":
            raise ValueError(f"Registro ajeno en la línea {number}")
        if record.get("status") in ("blocked", "passed"):
            done.add((record["prompt_id"], record["filter"]))
    return done


def run_screening(attacks: Sequence[AttackPrompt], filters: dict[str, FilterFn],
                  header: JsonObject, output_dir: Path, max_concurrency: int) -> JsonObject:
    """Crea o reanuda la ejecución; solo repite los pares sin resultado terminal."""
    if max_concurrency < 1:
        raise ValueError("max_concurrency debe ser al menos 1")
    run_id = header["run_id"]
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{run_id}.jsonl"
    lock = open(output_dir / f"{run_id}.lock", "a+", encoding="utf-8")
    try:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        lock.close()
        raise RuntimeError(f"Ya hay un proceso usando la ejecución {run_id}") from exc
    try:
        if path.exists():
            done = completed_pairs(path, header)
        else:
            done = set()
            with path.open("x", encoding="utf-8") as stream:
                write_jsonl_line(stream, header)
        tasks = [(a, name) for a in attacks for name in filters if (a.prompt_id, name) not in done]
        counts: dict[str, int] = {"blocked": 0, "passed": 0, "error": 0}
        cost = 0.0
        unknown = 0
        with path.open("a", encoding="utf-8") as stream, \
                ThreadPoolExecutor(max_workers=max_concurrency) as pool:
            def job(attack: AttackPrompt, name: str) -> JsonObject:
                started = perf_counter()
                result = filters[name](attack)
                return result_record(run_id, attack, name, result, (perf_counter() - started) * 1000)
            futures = [pool.submit(job, attack, name) for attack, name in tasks]
            for future in as_completed(futures):
                record = future.result()
                write_jsonl_line(stream, record)
                counts[record["status"]] += 1
                if record["cost_usd"] is None:
                    unknown += 1
                else:
                    cost += float(record["cost_usd"])
        return {"run_id": run_id, "path": str(path), "already_done": len(done),
                "new": len(tasks), "counts": counts, "known_cost_usd": cost,
                "records_with_unknown_cost": unknown}
    finally:
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        lock.close()


def select_part(attacks: list[AttackPrompt], manifest: JsonObject, part: int | None) -> list[AttackPrompt]:
    if part is None:
        return attacks
    ids = {row["prompt_id"] for row in manifest["rows"] if int(row["part"]) == part}
    return [attack for attack in attacks if attack.prompt_id in ids]


def build_header(run_id: str, corpus_sha256: str, attacks: Sequence[AttackPrompt],
                 part: int | None, filters: Sequence[str], declaration: JsonObject,
                 native_max_tokens: int, git_state: tuple[str, bool]) -> JsonObject:
    config: JsonObject = {
        "dataset": {"corpus_sha256": corpus_sha256, "part": part, "prompt_count": len(attacks),
                    "prompt_ids": [a.prompt_id for a in attacks]},
        "filters": list(filters),
        "guards_declaration": declaration,
        "native_max_tokens": native_max_tokens,
        "git_commit": git_state[0], "git_tracked_dirty": git_state[1],
        "code": _code_fingerprint(),
        "measures": "solo_deteccion_de_entrada",
    }
    return {"record_type": "header", "schema_version": SCHEMA_VERSION, "run_id": run_id,
            "timestamp": datetime.now(timezone.utc).isoformat(), "config_id": "SCREEN-v2",
            "config_fingerprint": _canonical_hash(config), "config": config}


def build_real_filters(declaration_path: Path, names: Sequence[str], native_max_tokens: int
                       ) -> tuple[dict[str, FilterFn], Any, Any]:  # pragma: no cover - red real
    """Construye los filtros con los adaptadores y políticas del YAML de C4."""
    import httpx
    from dotenv import load_dotenv

    from bench.bootstrap import default_adapters
    from bench.core.config import load_config
    from bench.openrouter import OpenRouterClient
    from bench.targets.openrouter_native import native_target

    experiment = load_config(declaration_path)
    load_dotenv(ROOT / ".env")
    api_key = os.getenv("OPENROUTER_API_KEY", "").strip()
    if not api_key:
        raise ValueError("Falta OPENROUTER_API_KEY")
    settings = experiment.execution
    http = httpx.Client(timeout=settings.timeout_seconds)
    client = OpenRouterClient(http, api_key, max_retries=settings.max_retries,
                              retry_base_delay=settings.retry_base_delay_seconds,
                              requests_per_second=settings.requests_per_second)
    adapters = default_adapters()
    filters: dict[str, FilterFn] = {}
    for spec in experiment.guardrails:
        name = {"nemo": "nemo_input", "llama_guard": "llama_guard_input"}.get(spec.adapter, "")
        if name in names and "input" in spec.stages:
            guard = adapters.guards.resolve(spec.adapter)(spec, client, experiment.seed)
            filters[name] = guard_filter(guard)
    if "openrouter_native" in names:
        def make(attack: AttackPrompt) -> Any:
            target = native_target(client, experiment.target.model, experiment.target.provider,
                                   attack.system_prompt, experiment.seed)
            target.params = {**target.params, "max_tokens": native_max_tokens}
            return target
        filters["openrouter_native"] = native_filter(make)
    return filters, http, experiment


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--guards-config", type=Path, default=DEFAULT_GUARDS_CONFIG)
    parser.add_argument("--filters", default=",".join(FILTERS))
    parser.add_argument("--part", type=int)
    parser.add_argument("--limit", type=int, help="Solo prueba de compatibilidad sc2-probe-.")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--native-max-tokens", type=int, default=NATIVE_MAX_TOKENS)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    names = [name.strip() for name in args.filters.split(",") if name.strip()]
    if not names or len(set(names)) != len(names) or any(name not in FILTERS for name in names):
        parser.exit(2, f"Filtros válidos: {', '.join(FILTERS)}\n")
    if not RUN_ID_PATTERN.fullmatch(args.run_id) or not args.run_id.startswith("sc2-"):
        parser.exit(2, "run_id debe empezar por sc2- y usar letras, números, punto o guion\n")
    if args.part is not None and args.part not in (1, 2, 3, 4):
        parser.exit(2, "La parte debe estar entre 1 y 4\n")
    if args.native_max_tokens < 1:
        parser.exit(2, "native-max-tokens debe ser positivo\n")
    attacks, digest = load_attacks(args.input)
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    if manifest["corpus_sha256"] != digest:
        parser.exit(2, "El corpus no coincide con el manifiesto congelado\n")
    selected = select_part(attacks, manifest, args.part)
    if args.limit is not None:
        if args.limit < 1 or not args.run_id.startswith("sc2-probe-"):
            parser.exit(2, "limit requiere un valor positivo y un run_id sc2-probe-\n")
        selected = selected[:args.limit]
    from bench.core.config import load_config
    declaration = load_config(args.guards_config).to_dict()
    benign = sum(1 for a in selected if a.is_benign)
    print(f"Nivel 1 · {len(selected)} prompts ({len(selected) - benign} ataques, {benign} benignos)"
          f" · parte {args.part or 'todas'} · corpus SHA-256 {digest}")
    print(f"Filtros: {', '.join(names)} · políticas de {args.guards_config.name}; "
          f"llamada nativa con max_tokens={args.native_max_tokens}")
    print(f"Peticiones previstas: {len(selected) * len(names)}; concurrencia "
          f"{declaration['execution']['max_concurrency']}, "
          f"{declaration['execution']['requests_per_second']:g} peticiones/s")
    if args.dry_run:
        print("Modo sin red. No se ha generado ningún resultado experimental.")
        return 0
    git_state = _git_state()  # pragma: no cover - ejecución real
    if git_state[1]:
        parser.exit(2, "Guarda primero los cambios en Git: la ejecución real requiere árbol limpio.\n")
    filters, http, _ = build_real_filters(args.guards_config, names, args.native_max_tokens)
    try:
        header = build_header(args.run_id, digest, selected, args.part, names, declaration,
                              args.native_max_tokens, git_state)
        summary = run_screening(selected, filters, header, ROOT / "results/raw",
                                int(declaration["execution"]["max_concurrency"]))
    finally:
        http.close()
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0 if summary["counts"]["error"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
