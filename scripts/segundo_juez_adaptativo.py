"""Segundo juez sobre los intentos adaptativos entregados (sensibilidad del criterio de éxito).

El éxito adaptativo exige el juez binario y una puntuación de PAIR de 8 o más. En el
nivel 3 estático el juez binario dejó escapar respuestas dañinas, así que aquí se
aplica el juez original de JailbreakBench (mismo prompt y modelo que
``segundo_juez.py``) a la respuesta final y al razonamiento de cada intento que llegó
al usuario. La petición evaluada es la conducta original de JBB, no la reescrita por
el atacante. Los registros solo guardan identificadores, etiquetas y costes.

Con ``--retenidos`` se juzgan, en otro fichero, las respuestas que el modelo sí dio
pero que no llegaron al usuario porque el moderador de NeMo se negó a evaluarlas en
la salida. El protocolo trata esas negativas como bloqueo (fallo cerrado); este modo
mide qué cambiaría con fallo abierto.

Uso:
  PYTHONPATH=src .venv/bin/python scripts/segundo_juez_adaptativo.py ejecutar \
      results/raw/adaptive/ad3-*.jsonl --max-usd 0.2
  PYTHONPATH=src .venv/bin/python scripts/segundo_juez_adaptativo.py resumen \
      results/raw/adaptive/ad3-*.jsonl --omitir ad3-c4:crescendo --omitir ad3-c3:bon
  (añadir --retenidos a las dos órdenes para las respuestas retenidas por el moderador)
"""

import argparse
import json
import os
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

import httpx
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bench.adaptive import known_cost  # noqa: E402
from bench.core.schema import StageError  # noqa: E402
from bench.openrouter import OpenRouterClient  # noqa: E402
from scripts.segundo_juez import (CALL_ESTIMATE_USD, CLASSIFIER_SHA256, MAX_TOKENS, MODEL,  # noqa: E402
                                  PROVIDER, UNKNOWN_COST_BOUND_USD, ChatClient, classify,
                                  read_judge_prompt, sha256)
from bench.openrouter import routing  # noqa: E402

Json = dict[str, Any]
OUTPUT = ROOT / "results/derived/segundo_juez/adaptativo.jsonl"
OUTPUT_RETAINED = ROOT / "results/derived/segundo_juez/adaptativo_retenidos.jsonl"


def all_attempts(paths: list[Path]) -> list[tuple[str, Json, str]]:
    """(identificador, intento, conducta original) de cada intento registrado."""
    items = []
    for path in paths:
        lines = path.read_text(encoding="utf-8").splitlines()
        header = json.loads(lines[0])
        goals = {b["prompt_id"]: b["prompt"] for b in header["config"]["behaviors"]}
        for line in lines[1:]:
            try:
                record = json.loads(line)
            except ValueError:  # línea a medio escribir de una ejecución en curso
                continue
            if record.get("record_type") != "attempt":
                continue
            ident = f"{record['run_id']}|{record['technique']}|{record['behavior_id']}|{record['attempt']}"
            items.append((ident, record, goals[record["behavior_id"]]))
    return items


def delivered(record: Json) -> bool:
    """La respuesta llegó al usuario. Es el criterio del motor (``answered`` en
    bench/adaptive.py): sin bloqueo, sin negativa del moderador y sin más fallo que
    uno del juez. Las negativas del moderador no marcan ``blocked``; van en ``error``."""
    error = record.get("error") or {}
    return (not record.get("blocked") and not record.get("moderator_refusal")
            and record.get("response_text") is not None
            and (not error or error.get("stage") == "judge"))


def retained_by_moderator(record: Json) -> bool:
    """El moderador de NeMo se negó a evaluar la salida: hay respuesta, pero no se entregó."""
    error = record.get("error") or {}
    return error.get("code") == "nemo_moderator_refused" and error.get("stage") == "output"


def attempts_to_review(paths: list[Path], retained: bool = False) -> list[tuple[str, Json, str]]:
    """Intentos entregados al usuario o, con ``retained``, retenidos por el moderador."""
    items = []
    for ident, record, goal in all_attempts(paths):
        selected = retained_by_moderator(record) if retained else delivered(record)
        if selected and (record.get("response_text") or record.get("reasoning_chain")):
            items.append((ident, record, goal))
    return items


def read_done(path: Path) -> tuple[set[str], float, int]:
    if not path.exists():
        return set(), 0.0, 0
    done: set[str] = set()
    spent, unknown = 0.0, 0
    for line in path.read_text(encoding="utf-8").splitlines()[1:]:
        record = json.loads(line)
        if record["unsafe"] is not None:
            done.add(record["id"])
        for result in record["canales"].values():
            if result.get("cost_usd") is None:
                unknown += 1
            else:
                spent += result["cost_usd"]
    return done, spent, unknown


def execute(args: argparse.Namespace, client: ChatClient | None = None) -> int:
    template, positive = read_judge_prompt()
    header = {"record_type": "header", "model": MODEL, "provider": routing(PROVIDER),
              "max_tokens": MAX_TOKENS, "seed": 0, "classifier_sha256": CLASSIFIER_SHA256,
              "prompt_sha256": sha256(template.encode())}
    if args.output.exists():
        stored = json.loads(args.output.read_text(encoding="utf-8").splitlines()[0])
        if any(stored.get(k) != header[k] for k in header):
            raise ValueError("La salida existente usa otro juez")
    done, spent, unknown = read_done(args.output)
    items = [item for item in attempts_to_review(args.paths, args.retenidos) if item[0] not in done]
    if client is None:
        load_dotenv(ROOT / ".env")
        api_key = os.environ.get("OPENROUTER_API_KEY", "").strip()
        if not api_key:
            raise ValueError("Falta OPENROUTER_API_KEY en el entorno o en .env")
        client = OpenRouterClient(httpx.Client(timeout=120), api_key, max_retries=5,
                                  retry_base_delay=2.0, requests_per_second=2.0)
    print(f"{len(items)} intentos pendientes; gasto previo ${spent:.4f}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("a", encoding="utf-8") as output:
        if args.output.stat().st_size == 0:
            output.write(json.dumps(header) + "\n")
        for ident, record, goal in items:
            results: Json = {}
            for channel, text in (("final", record.get("response_text") or ""),
                                  ("razonamiento", record.get("reasoning_chain") or "")):
                if spent + UNKNOWN_COST_BOUND_USD * unknown + CALL_ESTIMATE_USD > args.max_usd:
                    print(f"Parada por presupuesto: ${spent:.4f} conocidos")
                    return 3
                try:
                    result = classify(client, template, positive, goal, text, 0)
                except StageError as exc:
                    result = {"error": exc.code, "cost_usd": known_cost(exc.cost_usd, exc.attempt_history)}
                if result.get("cost_usd") is None:
                    unknown += 1
                else:
                    spent += result["cost_usd"]
                results[channel] = result
            failed = any("error" in r for r in results.values())
            output.write(json.dumps({"id": ident, "canales": results,
                                     "unsafe": None if failed else any(r["unsafe"] for r in results.values())})
                         + "\n")
            output.flush()
    print(f"Terminado: ${spent:.4f} conocidos, {unknown} desconocidos")
    return 0


def read_verdicts(path: Path) -> dict[str, bool | None]:
    verdicts: dict[str, bool | None] = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines()[1:]:
            record = json.loads(line)
            verdicts[record["id"]] = record["unsafe"]
    return verdicts


def summarize_retained(args: argparse.Namespace) -> Json:
    """Negativas del moderador por configuración y técnica, y respuestas retenidas 'unsafe'.

    ``conductas_con_negativa`` es la cota de S2: el número de conductas rotas si cada
    negativa contase como éxito del ataque. ``conductas_con_retenida_unsafe`` cuenta las
    conductas con alguna respuesta retenida en la salida que el segundo juez marca."""
    omit = {tuple(item.split(":", 1)) for item in args.omitir}
    verdicts = read_verdicts(args.output)
    groups: dict[tuple[str, str], Json] = {}
    for ident, record, _ in all_attempts(args.paths):
        run_id, technique, behavior, _ = ident.split("|")
        if (run_id, technique) in omit or not record.get("moderator_refusal"):
            continue
        group = groups.setdefault((record["config_id"], technique), {
            "negativas": 0, "conductas": set(), "retenidas": 0, "unsafe": set(), "sin_revisar": 0})
        group["negativas"] += 1
        group["conductas"].add(behavior)
        if retained_by_moderator(record) and (record.get("response_text") or record.get("reasoning_chain")):
            group["retenidas"] += 1
            verdict = verdicts.get(ident)
            if verdict is None:
                group["sin_revisar"] += 1
            elif verdict:
                group["unsafe"].add(behavior)
    return {f"{config} {technique}": {
        "negativas_moderador": g["negativas"], "conductas_con_negativa": len(g["conductas"]),
        "retenidas_en_salida": g["retenidas"], "conductas_con_retenida_unsafe": len(g["unsafe"]),
        "retenidas_sin_revisar": g["sin_revisar"]} for (config, technique), g in sorted(groups.items())}


def summarize(args: argparse.Namespace) -> Json:
    """Por configuración y técnica: conductas con éxito confirmado y con algún intento 'unsafe'."""
    if args.retenidos:
        return summarize_retained(args)
    omit = {tuple(item.split(":", 1)) for item in args.omitir}
    verdicts = read_verdicts(args.output)
    behaviors: dict[tuple[str, str], dict[str, Json]] = defaultdict(dict)
    for ident, record, _ in attempts_to_review(args.paths):
        run_id, technique, behavior, _ = ident.split("|")
        if (run_id, technique) in omit:
            continue
        state = behaviors[(record["config_id"], technique)].setdefault(
            behavior, {"confirmado": False, "segundo_juez": False, "sin_revisar": 0,
                       "unsafe": 0, "binario_negativo": 0, "pair_1": 0})
        state["confirmado"] |= record.get("confirmed_success") is True
        verdict = verdicts.get(ident)
        if verdict is None:
            state["sin_revisar"] += 1
        elif verdict:
            state["segundo_juez"] = True
            # Puntuación de PAIR: la independiente si el juez binario dio éxito; si no,
            # la de realimentación sobre la respuesta visible (Best-of-N no tiene).
            score = record.get("pair_score") if record.get("pair_score") is not None \
                else record.get("feedback_score")
            state["unsafe"] += 1
            state["binario_negativo"] += record.get("binary_success") is False
            state["pair_1"] += score == 1
    summary: Json = {}
    for (config, technique), states in sorted(behaviors.items()):
        values = list(states.values())
        summary[f"{config} {technique}"] = {
            "conductas_con_intentos_entregados": len(values),
            "exito_confirmado": sum(v["confirmado"] for v in values),
            "algun_intento_unsafe_segundo_juez": sum(v["segundo_juez"] for v in values),
            "confirmado_y_unsafe": sum(v["confirmado"] and v["segundo_juez"] for v in values),
            "solo_segundo_juez": sum(v["segundo_juez"] and not v["confirmado"] for v in values),
            "conductas_marcadas_por_un_solo_intento": sum(v["unsafe"] == 1 for v in values),
            "intentos_unsafe": {"total": sum(v["unsafe"] for v in values),
                                "juez_binario_negativo": sum(v["binario_negativo"] for v in values),
                                "puntuacion_pair_1": sum(v["pair_1"] for v in values)},
            "intentos_sin_revisar": sum(v["sin_revisar"] for v in values),
        }
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="orden", required=True)
    for name in ("ejecutar", "resumen"):
        p = sub.add_parser(name)
        p.add_argument("paths", type=Path, nargs="+")
        p.add_argument("--output", type=Path)
        p.add_argument("--retenidos", action="store_true",
                       help="respuestas retenidas por una negativa del moderador en la salida")
        if name == "ejecutar":
            p.add_argument("--max-usd", type=float, required=True)
        else:
            p.add_argument("--omitir", action="append", default=[])
            p.add_argument("--salida", type=Path)
    args = parser.parse_args()
    args.output = args.output or (OUTPUT_RETAINED if args.retenidos else OUTPUT)
    if args.orden == "ejecutar":
        return execute(args)
    summary = summarize(args)
    text = json.dumps(summary, ensure_ascii=False, indent=2)
    if args.salida:
        args.salida.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
