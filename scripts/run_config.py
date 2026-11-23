"""Niveles 2 y 3: ejecuta una configuración C0-C5 declarada en YAML sobre un corpus y
registra cada etapa.
"""

import argparse
import fcntl
import hashlib
import json
import os
import platform
import re
import socket
import subprocess
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from importlib.metadata import version
from typing import TextIO

import httpx
from dotenv import load_dotenv

from bench.bootstrap import Adapters, build_runtime, default_adapters, remote_model_routes
from bench.core.config import ExperimentConfig, ExecutionConfig, ModelSpec, load_config, parse_config
from bench.core.runner import rejudge_one, run_batch as execute_batch
from bench.core.schema import AttackPrompt, JsonObject, StageError
from bench.openrouter import API_URL, METADATA_HEADER, OpenRouterClient, available_providers

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = ROOT / "data/attacks/pilot_llm07.json"
DEFAULT_CONFIG = ROOT / "configs/c0_baseline.yaml"
TARGET_MODEL = "deepseek/deepseek-r1-0528"
JUDGE_MODEL = "openai/gpt-4.1-mini"
JUDGE_PROVIDER = "openai"
SEED = 42
TIMEOUT_SECONDS = 180.0
DEFAULT_CONCURRENCY = 2
DEFAULT_REQUESTS_PER_SECOND = 1.0
DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_BASE_DELAY = 1.0
REQUIRED_CAMPAIGN_SIZE = 20
RUN_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


def write_jsonl_line(stream: TextIO, value: JsonObject) -> None:
    """Escribe y sincroniza una línea completa sin modificar las anteriores."""
    stream.write(json.dumps(value, ensure_ascii=False, allow_nan=False) + "\n")
    stream.flush()
    os.fsync(stream.fileno())


def _repair_incomplete_tail(path: Path) -> bool:
    """Conserva líneas completas y elimina o cierra solo una cola sin salto final."""
    content = path.read_bytes()
    if not content or content.endswith(b"\n"):
        return False
    boundary = content.rfind(b"\n") + 1
    tail = content[boundary:]
    try:
        last_record = json.loads(tail)
    except (UnicodeDecodeError, json.JSONDecodeError):
        with path.open("r+b") as stream:
            stream.truncate(boundary)
            stream.flush()
            os.fsync(stream.fileno())
        return True
    if isinstance(last_record, dict) and last_record.get("record_type") in {"header", "result"}:
        with path.open("ab") as stream:
            stream.write(b"\n")
            stream.flush()
            os.fsync(stream.fileno())
    else:
        with path.open("r+b") as stream:
            stream.truncate(boundary)
            stream.flush()
            os.fsync(stream.fileno())
    return True


def load_attacks(path: Path) -> tuple[list[AttackPrompt], str]:
    """Carga objetos JSON, una lista JSON o JSONL y devuelve su huella SHA-256."""
    content = path.read_bytes()
    try:
        decoded = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("El corpus debe estar codificado en UTF-8") from exc
    try:
        parsed = json.loads(decoded)
        raw_items = parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        raw_items = []
        for line_number, line in enumerate(decoded.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                raw_items.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"JSONL no válido en la línea {line_number}") from exc

    if not raw_items:
        raise ValueError("El corpus no contiene casos")
    attacks: list[AttackPrompt] = []
    seen_ids: set[str] = set()
    for index, raw in enumerate(raw_items, start=1):
        if not isinstance(raw, dict):
            raise ValueError(f"El caso {index} no es un objeto JSON")
        try:
            attack = AttackPrompt(**raw)
        except TypeError as exc:
            raise ValueError(f"El caso {index} no cumple el esquema AttackPrompt") from exc
        if (
            not isinstance(attack.prompt_id, str)
            or not attack.prompt_id.strip()
            or not isinstance(attack.prompt, str)
            or not attack.prompt.strip()
            or not isinstance(attack.system_prompt, str)
            or not isinstance(attack.objective, str)
            or not isinstance(attack.prompt_source, str)
            or not isinstance(attack.owasp_category, str)
            or not isinstance(attack.nist_category, str)
            or not isinstance(attack.is_benign, bool)
        ):
            raise ValueError(f"El caso {index} contiene campos vacíos o tipos no válidos")
        if attack.prompt_id in seen_ids:
            raise ValueError(f"prompt_id duplicado: {attack.prompt_id}")
        seen_ids.add(attack.prompt_id)
        attacks.append(attack)
    return attacks, hashlib.sha256(content).hexdigest()


def _canonical_hash(value: JsonObject) -> str:
    """Calcula una huella estable para estructuras JSON."""
    canonical = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _git_state() -> tuple[str, bool]:
    """Recoge la revisión y si hay cambios versionados sin incluir datos locales."""
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    tracked_changes = subprocess.check_output(
        ["git", "status", "--porcelain"], cwd=ROOT, text=True
    )
    return commit, bool(tracked_changes)


def _code_fingerprint() -> JsonObject:
    """Identifica fuentes y dependencias ejecutadas sin leer secretos ni resultados."""
    paths = sorted([
        *ROOT.joinpath("src").rglob("*.py"),
        *ROOT.joinpath("scripts").glob("*.py"),
        ROOT / "pyproject.toml", ROOT / "uv.lock",
    ])
    files = {
        path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in paths
    }
    return {"sha256": _canonical_hash(files), "files": files}


def _is_terminal(record: JsonObject) -> bool:
    """Un resultado con veredicto o una negativa del juez ya está registrado."""
    error = record.get("error")
    if error is None:
        verdict = record.get("judge_verdict")
        return record.get("blocked") is True or (
            isinstance(verdict, dict) and isinstance(verdict.get("success"), bool)
        )
    return (
        isinstance(error, dict)
        and error.get("stage") == "judge"
        and error.get("code") == "judge_refused"
    )


def _validate_header(path: Path, header: JsonObject) -> None:
    """Verifica pertenencia antes de permitir cualquier reparación del archivo."""
    try:
        with path.open(encoding="utf-8") as stream:
            stored_header = json.loads(stream.readline())
    except json.JSONDecodeError as exc:
        raise ValueError("La cabecera del JSONL existente está dañada") from exc
    if (
        not isinstance(stored_header, dict)
        or stored_header.get("record_type") != "header"
        or stored_header.get("run_id") != header["run_id"]
        or stored_header.get("config_fingerprint") != header["config_fingerprint"]
        or stored_header.get("schema_version") != header["schema_version"]
    ):
        raise ValueError("La configuración no coincide con la ejecución que se quiere reanudar")


def _rejudge_source(record: JsonObject) -> bool:
    """Generación entregada (sin bloqueo) cuyo juez falló sin negarse.

    Solo cuentan registros con generación propia, no los de rearbitraje, que
    copian la de su origen.
    """
    error = record.get("error")
    return (
        isinstance(error, dict) and error.get("stage") == "judge"
        and error.get("code") != "judge_refused" and record.get("blocked") is False
        and "resumed_from" not in record
        and any(item.get("stage") == "target" and item.get("status") == "completed"
                for item in record.get("stages", []))
    )


def _scan_existing(
    path: Path, header: JsonObject, expected_ids: set[str],
) -> tuple[set[str], dict[str, JsonObject]]:
    """Devuelve los casos terminales y, para los demás, la generación a rearbitrar.

    Si un caso tiene una generación cuyo juez falló, al reanudar se conserva la
    primera de ellas y solo se repite el juez. Los JSONL históricos que ya
    repitieron la cadena completa se leen igual: se toma la primera generación.
    """
    _validate_header(path, header)
    lines = path.read_text(encoding="utf-8").removesuffix("\n").split("\n")
    completed: set[str] = set()
    sources: dict[str, JsonObject] = {}
    for line_number, line in enumerate(lines[1:], start=2):
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"JSONL dañado en la línea {line_number}; no se añadieron datos") from exc
        if not isinstance(record, dict) or record.get("record_type") != "result":
            raise ValueError(f"Registro no válido en la línea {line_number}")
        required = {"error", "blocked", "judge_verdict", "stages", "config_id", "target_model", "timestamp"}
        if (not required.issubset(record) or type(record["blocked"]) is not bool
            or not isinstance(record["stages"], list)
            or record["config_id"] != header["config_id"]
            or (record["error"] is None and not _is_terminal(record))):
            raise ValueError(f"Registro incompleto en la línea {line_number}")
        prompt_id = record.get("prompt_id")
        if prompt_id not in expected_ids or record.get("run_id") != header["run_id"]:
            raise ValueError(f"Resultado ajeno al corpus o a la ejecución en línea {line_number}")
        if _is_terminal(record):
            completed.add(prompt_id)
        elif _rejudge_source(record) and prompt_id not in sources:
            sources[prompt_id] = record
    return completed, {pid: rec for pid, rec in sources.items() if pid not in completed}


def run_campaign(
    http: httpx.Client,
    attacks: list[AttackPrompt],
    dataset_sha256: str,
    provider: str,
    api_key: str,
    output_dir: Path,
    *,
    target_model: str = TARGET_MODEL,
    run_id: str | None = None,
    max_concurrency: int = DEFAULT_CONCURRENCY,
    requests_per_second: float = DEFAULT_REQUESTS_PER_SECOND,
    max_retries: int = DEFAULT_MAX_RETRIES,
    retry_base_delay: float = DEFAULT_RETRY_BASE_DELAY,
    git_state: tuple[str, bool] | None = None,
    experiment: ExperimentConfig | None = None,
    adapters: Adapters | None = None,
    yaml_sha256: str | None = None,
    yaml_source: str | None = None,
) -> int:
    """Crea o reanuda una campaña con una configuración inmutable."""
    if not attacks:
        raise ValueError("La ejecución requiere al menos un ataque")
    if len({attack.prompt_id for attack in attacks}) != len(attacks):
        raise ValueError("El corpus contiene prompt_id duplicados")
    if max_concurrency < 1:
        raise ValueError("max_concurrency debe ser al menos 1")
    if requests_per_second <= 0:
        raise ValueError("requests_per_second debe ser mayor que cero")
    if max_retries < 0 or retry_base_delay < 0:
        raise ValueError("Los reintentos y su demora deben ser no negativos")
    if experiment is None:
        # Compatibilidad de la API usada por las comprobaciones de Hito 2.
        experiment = ExperimentConfig(
            schema_version=1, config_id="C0", dataset=str(DEFAULT_INPUT), seed=SEED,
            target=ModelSpec("openrouter", target_model, provider),
            judge=ModelSpec("openrouter_llm", JUDGE_MODEL, JUDGE_PROVIDER),
            guardrails=(), execution=ExecutionConfig(
                timeout_seconds=TIMEOUT_SECONDS, max_concurrency=max_concurrency,
                requests_per_second=requests_per_second, max_retries=max_retries,
                retry_base_delay_seconds=retry_base_delay,
            ),
        )
    experiment = parse_config(experiment.to_dict())
    settings = experiment.execution
    max_concurrency = settings.max_concurrency
    if git_state is None:
        git_state = _git_state()
    commit, tracked_dirty = git_state
    if tracked_dirty:
        raise ValueError("La campaña requiere una revisión Git limpia; guarda los cambios antes de ejecutarla")

    router = OpenRouterClient(
        http,
        api_key,
        max_retries=settings.max_retries,
        retry_base_delay=settings.retry_base_delay_seconds,
        requests_per_second=settings.requests_per_second,
    )
    runtime = build_runtime(experiment, router, adapters)
    target_template = runtime.target(attacks[0])
    judge = runtime.judge
    config: JsonObject = {
        "api_base_url": API_URL,
        "api_metadata_header": METADATA_HEADER,
        "timeout_seconds": settings.timeout_seconds,
        "seed": experiment.seed,
        "guardrails": experiment.to_dict()["guardrails"],
        "declaration": experiment.to_dict(),
        "yaml_sha256": yaml_sha256,
        "yaml_source": yaml_source,
        "dataset": {
            "sha256": dataset_sha256,
            "prompt_count": len(attacks),
            "prompt_ids": [attack.prompt_id for attack in attacks],
            "cases": [asdict(attack) for attack in attacks],
        },
        "target": {
            "model": target_template.name,
            "provider": experiment.target.provider,
            "adapter": experiment.target.adapter,
            "params": target_template.params,
        },
        "judge": {
            "model": judge.name,
            "adapter": experiment.judge.adapter,
            "provider": experiment.judge.provider,
            "params": getattr(judge, "params", {}),
            "instructions": getattr(judge, "instructions", None),
        },
        "execution": {
            "max_concurrency": max_concurrency,
            "requests_per_second": settings.requests_per_second,
            "max_retries": settings.max_retries,
            "retry_base_delay_seconds": settings.retry_base_delay_seconds,
        },
        "git_commit": commit,
        "git_tracked_dirty": tracked_dirty,
        "code": _code_fingerprint(),
        "runtime": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
            "dependencies": {package: version(package) for package in (
                "httpx", "PyYAML", "python-dotenv", "nemoguardrails", "guardrails-ai",
                "onnxruntime", "jsonschema",
            )},
        },
        "remote_guardrail_policy_verification": "not_performed_by_cli",
        "native_policy_attestation": getattr(target_template, "native_policy", None),
    }
    fingerprint = _canonical_hash(config)
    if run_id is None:
        run_id = f"{experiment.config_id.lower()}-{fingerprint}"
    elif not RUN_ID_PATTERN.fullmatch(run_id):
        raise ValueError("run_id solo puede contener letras, números, punto, guion y guion bajo")

    header: JsonObject = {
        "record_type": "header",
        "schema_version": 3,
        "run_id": run_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "config_id": experiment.config_id,
        "config_fingerprint": fingerprint,
        "config": config,
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{run_id}.jsonl"
    lock_path = output_dir / f"{run_id}.lock"
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    lock = os.fdopen(lock_fd, "r+", encoding="utf-8")
    try:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        lock.close()
        raise RuntimeError(f"Ya hay un proceso usando la ejecución {run_id}") from exc
    lock.seek(0)
    lock.truncate()
    lock.write(json.dumps({
        "pid": os.getpid(), "host": socket.gethostname(), "run_id": run_id,
    }) + "\n")
    lock.flush()
    os.fsync(lock.fileno())

    new_records: list[JsonObject] = []
    try:
        if path.exists():
            _validate_header(path, header)
            if _repair_incomplete_tail(path):
                print("Recuperación: se conservó el JSONL completo y se saneó su cola incompleta.")
            completed, rejudge_sources = _scan_existing(path, header, {a.prompt_id for a in attacks})
        else:
            completed, rejudge_sources = set(), {}
            output_fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(output_fd, "w", encoding="utf-8") as stream:
                write_jsonl_line(stream, header)

        pending = [
            attack for attack in attacks
            if attack.prompt_id not in completed and attack.prompt_id not in rejudge_sources
        ]
        rejudge = [attack for attack in attacks if attack.prompt_id in rejudge_sources]
        if rejudge:
            # La generación ya observada se conserva; solo se repite el arbitraje.
            with path.open("a", encoding="utf-8") as stream:
                for attack in rejudge:
                    record = rejudge_one(run_id, attack, judge, rejudge_sources[attack.prompt_id])
                    write_jsonl_line(stream, record)
                    new_records.append(record)
        if pending:
            with path.open("a", encoding="utf-8") as stream:
                for record in execute_batch(
                    run_id, pending, runtime.target, judge, max_concurrency,
                    config_id=experiment.config_id, guard_factory=runtime.guards,
                ):
                    write_jsonl_line(stream, record)
                    new_records.append(record)
        errors = [record["error"] for record in new_records if record["error"] is not None]
        costs = [record["total_cost_usd"] for record in new_records]
        observed_cost = sum(cost for cost in costs if cost is not None)
        unknown_costs = sum(cost is None for cost in costs)
        print(f"run_id: {run_id}")
        print(f"JSONL: {path}")
        print(f"Casos nuevos: {len(new_records)} (rearbitrajes: {len(rejudge)}); "
              f"ya completos: {len(completed)}")
        print(f"Errores registrados: {len(errors)}")
        print(
            f"Coste de nuevos registros con total conocido: ${observed_cost:.8f}; "
            f"total desconocido en {unknown_costs} registro(s)"
        )
        if len(completed) + sum(1 for record in new_records if _is_terminal(record)) == len(attacks):
            return 0
        return 1
    finally:
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        lock.close()


COMPARATIVE_CONFIG_IDS = ("C0", "C1", "C2", "C3", "C4", "C5")
COMPARATIVE_CONFIG_FILES = (
    "c0_baseline.yaml", "c1_native.yaml", "c2_nemo.yaml",
    "c3_llama_guard.yaml", "c4_combined.yaml", "c5_combined.yaml",
)


def default_dataset_warning(config_id: str, input_given: bool) -> str | None:
    """Avisa si una configuración comparativa usaría su corpus por defecto.

    Los YAML de C0–C5 declaran corpus por defecto distintos (c0_20 frente a
    development12). No se unifican porque el YAML entra en la huella de la
    configuración y cambiarlo impediría reanudar los run_id ya registrados.
    Una ejecución comparativa debe fijar el mismo corpus con --input.
    """
    if input_given or config_id not in COMPARATIVE_CONFIG_IDS:
        return None
    defaults: dict[str, str] = {}
    for name in COMPARATIVE_CONFIG_FILES:
        path = ROOT / "configs" / name
        try:
            declared = load_config(path)
        except (OSError, ValueError):
            continue
        if declared.config_id in COMPARATIVE_CONFIG_IDS:
            defaults[declared.config_id] = declared.dataset
    if len(set(defaults.values())) <= 1:
        return None
    detail = "; ".join(f"{cid}={dataset}" for cid, dataset in sorted(defaults.items()))
    return (
        "AVISO: ejecución de " + config_id + " sin --input. Los corpus por defecto de C0–C5 "
        f"difieren ({detail}). Sus resultados NO son comparables entre configuraciones: "
        "para una comparación usa --input con el mismo corpus en todas."
    )


def main() -> int:
    """Valida el YAML y el corpus antes de construir o ejecutar servicios."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--input", type=Path, help="Sustituye el corpus declarado en YAML.")
    parser.add_argument("--dry-run", action="store_true", help="Valida y muestra el plan sin red.")
    parser.add_argument("--target-model")
    parser.add_argument("--provider")
    parser.add_argument("--run-id", help="Identificador para una campaña nueva o reanudable.")
    parser.add_argument("--max-concurrency", type=int)
    parser.add_argument("--requests-per-second", type=float)
    parser.add_argument("--max-retries", type=int)
    parser.add_argument("--retry-base-delay", type=float)
    parser.add_argument("--allow-partial", action="store_true", help="Autoriza un piloto de menos de 20 casos.")
    args = parser.parse_args()
    try:
        declaration = load_config(args.config).to_dict()
        if args.target_model is not None:
            declaration["target"]["model"] = args.target_model
        if args.provider is not None:
            declaration["target"]["provider"] = args.provider
        if args.input is not None:
            declaration["dataset"] = str(args.input)
        for argument, field in (
            (args.max_concurrency, "max_concurrency"),
            (args.requests_per_second, "requests_per_second"),
            (args.max_retries, "max_retries"),
            (args.retry_base_delay, "retry_base_delay_seconds"),
        ):
            if argument is not None:
                declaration["execution"][field] = argument
        experiment = parse_config(declaration)
        adapters = default_adapters()
        adapters.validate(experiment)
        dataset = Path(experiment.dataset)
        if not dataset.is_absolute():
            dataset = ROOT / dataset
        attacks, dataset_sha256 = load_attacks(dataset)
        yaml_bytes = args.config.read_bytes()
        yaml_sha256 = hashlib.sha256(yaml_bytes).hexdigest()
        yaml_source = yaml_bytes.decode("utf-8")
        if args.run_id is not None and not RUN_ID_PATTERN.fullmatch(args.run_id):
            raise ValueError("run_id solo puede contener letras, números, punto, guion y guion bajo")
    except (OSError, ValueError) as exc:
        parser.exit(2, f"Configuración/corpus: {exc}\n")

    warning = default_dataset_warning(experiment.config_id, args.input is not None)
    if warning is not None:
        banner = "!" * 78
        print(f"{banner}\n{warning}\n{banner}", file=sys.stderr)
    settings = experiment.execution
    if args.dry_run:
        print(f"{experiment.config_id} · {len(attacks)} casos · SHA-256 {dataset_sha256}")
        print(f"Declaración YAML: {args.config} · SHA-256 {yaml_sha256}")
        labels = ["corpus"]
        labels.extend(g.name + " [entrada]" for g in experiment.guardrails if "input" in g.stages)
        labels.append(f"{experiment.target.model} ({experiment.target.provider})")
        labels.extend(g.name + " [salida]" for g in experiment.guardrails if "output" in g.stages)
        labels.extend([experiment.judge.model, "JSONL reanudable"])
        print("Flujo: " + " → ".join(labels))
        print(f"Adaptador objetivo: {experiment.target.adapter}")
        if experiment.target.adapter == "openrouter_native_guarded":
            print("La política nativa actúa al enviar al objetivo; requiere clave aislada y controles verificados.")
        print(f"Semilla: {experiment.seed}; concurrencia: {settings.max_concurrency}; "
              f"máximo: {settings.requests_per_second:g} peticiones/s; reintentos: {settings.max_retries}")
        if len(attacks) < REQUIRED_CAMPAIGN_SIZE:
            print("Aviso: corpus pequeño de desarrollo; no es una evaluación final.")
        print("Modo sin red. No se ha generado ningún resultado experimental.")
        return 0

    if len(attacks) < REQUIRED_CAMPAIGN_SIZE and not args.allow_partial:
        parser.exit(2, f"Para menos de {REQUIRED_CAMPAIGN_SIZE} casos usa --allow-partial como piloto explícito.\n")
    git_state = _git_state()
    if git_state[1]:
        parser.exit(2, "Guarda primero los cambios en Git: la ejecución real requiere una revisión limpia.\n")
    load_dotenv(ROOT / ".env")
    api_key = os.getenv("OPENROUTER_API_KEY", "").strip()
    if not api_key:
        parser.exit(1, "Falta OPENROUTER_API_KEY en el entorno o en .env.\n")
    with httpx.Client(timeout=settings.timeout_seconds) as http:
        for role, spec in remote_model_routes(experiment):
            try:
                providers = available_providers(http, spec.model)
            except StageError as exc:
                parser.exit(1, f"OpenRouter ({role}): {exc.code}\n")
            if spec.provider not in providers:
                parser.exit(1, f"Proveedor {spec.provider} no disponible para {role} {spec.model}; "
                            f"disponibles: {', '.join(providers) or '(ninguno)'}.\n")
        try:
            return run_campaign(
                http, attacks, dataset_sha256, experiment.target.provider, api_key,
                ROOT / "results/raw", experiment=experiment, adapters=adapters,
                yaml_sha256=yaml_sha256, yaml_source=yaml_source,
                run_id=args.run_id, git_state=git_state,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            parser.exit(1, f"Ejecución: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
