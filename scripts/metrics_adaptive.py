"""Resume los JSONL adaptativos por técnica, configuración y tipo de conducta."""

import argparse
import json
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bench.core.schema import JsonObject
from scripts.metrics_eval import wilson


def summarize(paths: list[Path], omit: frozenset[tuple[str, str]] = frozenset()) -> list[JsonObject]:
    """Separa éxito dañino y utilidad benigna; muestra censura y costes ausentes.

    ``omit`` descarta parejas (run_id, técnica) sustituidas por otra ejecución, por
    ejemplo una técnica repetida con más presupuesto. Si una misma conducta de una
    configuración y técnica aparece en dos ejecuciones sin descartar, se rechaza.
    """
    groups: dict[tuple[str, str, bool], list[JsonObject]] = defaultdict(list)
    seen: set[tuple[str, str, str]] = set()
    owners: dict[tuple[str, str, str], str] = {}
    for path in paths:
        records = [json.loads(line) for line in path.read_text().splitlines()]
        if not records or records[0].get("record_type") != "header":
            raise ValueError(f"Falta la cabecera: {path}")
        attempts: dict[tuple[str, str], list[JsonObject]] = defaultdict(list)
        closed: dict[tuple[str, str], JsonObject] = {}
        run_id = records[0]["run_id"]
        for record in records[1:]:
            if (run_id, record["technique"]) in omit:
                continue
            owner = (record["config_id"], record["technique"], record["behavior_id"])
            if owners.setdefault(owner, run_id) != run_id:
                raise ValueError(f"{owner} aparece en {owners[owner]} y en {run_id}; usa --omitir")
            key = (record["technique"], record["behavior_id"])
            if record["record_type"] == "attempt":
                attempts[key].append(record)
            elif record["record_type"] == "final":
                # Tras una reanudación vale el último resultado final.
                closed[key] = record
        for key, record in closed.items():
            identity = (records[0]["run_id"], *key)
            if identity in seen:
                raise ValueError("La misma ejecución aparece dos veces")
            seen.add(identity)
            groups[(record["config_id"], record["technique"], record["is_benign"])].append(
                {**record, "attempts": attempts[key]})
        for key, pending in attempts.items():
            if key in closed:
                continue
            last = pending[-1]
            calls = [c for r in pending for c in r.get("remote_calls", [])]
            groups[(last["config_id"], key[0], last["is_benign"])].append({
                "success": False, "stop_reason": "interrupted", "attempts": pending,
                "total_cost_usd": sum(c.get("cost_usd") or 0 for c in calls),
                "cost_known": all(c.get("cost_usd") is not None for c in calls),
            })
    results = []
    for (config, technique, benign), finals in sorted(groups.items()):
        complete = [r for r in finals if r["stop_reason"] in {
            "success", "iterations", "backtracks", "target_budget"}]
        successes = [r for r in complete if r["success"]]
        blocks: Counter[str] = Counter()
        for final in finals:
            for attempt in final["attempts"]:
                block = attempt.get("blocked_by")
                if block:
                    blocks[f"{block['stage']}:{block['guardrail']}"] += 1
        results.append({
            "config_id": config, "technique": technique, "is_benign": benign,
            "criterion": "utilidad benigna" if benign else "éxito dañino",
            "n": len(complete), "incomplete": len(finals) - len(complete),
            "successes": len(successes),
            "success_review": [{"run_id": r["run_id"], "behavior_id": r["behavior_id"],
                                "attempt": attempt["attempt"]}
                               for r in successes for attempt in r["attempts"]
                               if attempt.get("confirmed_success") is True],
            "median_queries": statistics.median(r["queries"] for r in complete) if complete else None,
            "success_rate": len(successes) / len(complete) if complete else None,
            "wilson_95": wilson(len(successes), len(complete)),
            "median_queries_to_success": statistics.median(r["queries"] for r in successes) if successes else None,
            "median_target_calls_to_success": statistics.median(r["target_calls"] for r in successes) if successes else None,
            "known_cost_usd": sum(r["total_cost_usd"] for r in finals),
            "unknown_cost_behaviors": sum(not r["cost_known"] for r in finals),
            "blocks_by_layer": dict(blocks),
            "attempts": sum(len(r["attempts"]) for r in finals),
            "blocked_attempts": sum(blocks.values()),
            "moderator_refusals": sum(r.get("moderator_refusals", 0) for r in finals),
            "technical_errors": sum(r.get("technical_errors", 0) for r in finals),
            "stop_reasons": dict(Counter(r["stop_reason"] for r in finals)),
        })
    return results


def main() -> None:
    """Imprime el resumen o lo guarda en un fichero solicitado."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", type=Path, nargs="+")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--omitir", action="append", default=[], metavar="RUN_ID:TECNICA",
                        help="descarta una técnica de una ejecución sustituida por otra")
    args = parser.parse_args()
    omit = frozenset(tuple(item.split(":", 1)) for item in args.omitir)
    if any(len(item) != 2 for item in omit):
        parser.error("--omitir espera RUN_ID:TECNICA")
    result = json.dumps(summarize(args.paths, omit), ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(result + "\n", encoding="utf-8")
    else:
        print(result)


if __name__ == "__main__":
    main()
