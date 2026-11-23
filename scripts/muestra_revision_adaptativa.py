"""Nivel 3: saca una muestra ciega de intentos adaptativos para resolver a mano el
desacuerdo entre jueces.

En el adaptativo, el juez de JailbreakBench marca como dañinos intentos que el juez
binario y el juez de PAIR dan por fallidos. Esta muestra, estratificada y con semilla
fija, sirve para comprobarlo con etiquetas del autor. Mezcla intentos en disputa con
controles (éxitos confirmados e intentos que ningún juez marca) y no muestra veredictos.

Uso:
  PYTHONPATH=src .venv/bin/python scripts/muestra_revision_adaptativa.py preparar
  PYTHONPATH=src .venv/bin/python scripts/muestra_revision_adaptativa.py resumen

La salida queda en results/local/revision_adaptativo/ (fuera del control de versiones,
porque contiene las respuestas). El resumen se guarda en results/derived.

La muestra se generó con el filtro de entonces, que no excluía las respuestas
retenidas por una negativa del moderador de NeMo en la salida (no llevan ``blocked``).
Una de ellas entró en el estrato de C4. Sirve igual para medir el acuerdo entre jueces;
el resumen la lista en ``no_entregadas``. ``preparar`` se deja como estaba para que
siga reproduciendo la misma muestra.
"""

import argparse
import csv
import glob
import json
import random
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from scripts.segundo_juez import kappa  # noqa: E402
from scripts.segundo_juez_adaptativo import delivered  # noqa: E402

Json = dict[str, Any]
OUT = ROOT / "results/local/revision_adaptativo"
OMIT = {("ad3-c4", "crescendo"), ("ad3-c3", "bon")}
SEED = 20261123
# Estratos: (nombre, condición, tamaño)
PLAN = (("disputa C4 PAIR", 6), ("disputa C3 PAIR", 3), ("disputa C0 PAIR", 3),
        ("disputa Crescendo", 2), ("confirmado", 1), ("ningún juez", 1))


def attempts() -> list[tuple[Json, Json, Json]]:
    """(intento, conducta, veredicto del segundo juez) de cada intento entregado y revisado."""
    verdicts = {}
    for line in (ROOT / "results/derived/segundo_juez/adaptativo.jsonl").read_text().splitlines()[1:]:
        record = json.loads(line)
        verdicts[record["id"]] = record
    rows = []
    for name in sorted(glob.glob(str(ROOT / "results/raw/adaptive/ad3-*.jsonl"))):
        lines = Path(name).read_text(encoding="utf-8").splitlines()
        behaviors = {b["prompt_id"]: b for b in json.loads(lines[0])["config"]["behaviors"]}
        for line in lines[1:]:
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if record.get("record_type") != "attempt" or (record["run_id"], record["technique"]) in OMIT:
                continue
            ident = f"{record['run_id']}|{record['technique']}|{record['behavior_id']}|{record['attempt']}"
            verdict = verdicts.get(ident)
            if verdict and verdict["unsafe"] is not None:
                rows.append((record, behaviors[record["behavior_id"]], verdict))
    return rows


def stratum(record: Json, verdict: Json) -> str | None:
    confirmed = record.get("confirmed_success") is True
    if confirmed:
        return "confirmado"
    if not verdict["unsafe"]:
        return "ningún juez" if not record.get("binary_success") else None
    if record["technique"] == "pair":
        return f"disputa {record['config_id']} PAIR"
    if record["technique"] == "crescendo":
        return "disputa Crescendo"
    return None


def prepare() -> None:
    if (OUT / "clave.json").exists():
        raise SystemExit(f"Ya existe {OUT}/clave.json: la muestra no se regenera")
    rng = random.Random(SEED)
    pools: dict[str, list[tuple[Json, Json, Json]]] = {name: [] for name, _ in PLAN}
    for record, behavior, verdict in attempts():
        name = stratum(record, verdict)
        if name in pools:
            pools[name].append((record, behavior, verdict))
    chosen = []
    for name, size in PLAN:
        pool = sorted(pools[name], key=lambda item: f"{item[0]['run_id']}|{item[0]['behavior_id']}|{item[0]['attempt']}")
        chosen += [(name, item) for item in rng.sample(pool, min(size, len(pool)))]
    rng.shuffle(chosen)
    OUT.mkdir(parents=True, exist_ok=True)
    key = {}
    with (OUT / "formulario.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["muestra", "conducta", "respuesta_final", "razonamiento",
                                                     "etiqueta_humana", "notas"])
        writer.writeheader()
        for index, (name, (record, behavior, _)) in enumerate(chosen, 1):
            sample = f"a{index:02d}"
            key[sample] = {"run_id": record["run_id"], "technique": record["technique"],
                           "behavior_id": record["behavior_id"], "attempt": record["attempt"], "estrato": name}
            writer.writerow({"muestra": sample, "conducta": behavior["objective"],
                             "respuesta_final": record.get("response_text") or "",
                             "razonamiento": record.get("reasoning_chain") or "",
                             "etiqueta_humana": "", "notas": ""})
    (OUT / "clave.json").write_text(json.dumps({"seed": SEED, "samples": key}, ensure_ascii=False, indent=1),
                                    encoding="utf-8")
    print(f"{len(chosen)} intentos en {OUT}/formulario.csv;", dict(Counter(name for name, _ in chosen)))


def summarize() -> Json:
    key = json.loads((OUT / "clave.json").read_text(encoding="utf-8"))["samples"]
    labels = {}
    with (OUT / "formulario.csv").open(encoding="utf-8") as stream:
        for row in csv.DictReader(stream):
            if row["etiqueta_humana"] in {"danino", "no_danino"}:
                labels[row["muestra"]] = row["etiqueta_humana"] == "danino"
    index = {f"{r['run_id']}|{r['technique']}|{r['behavior_id']}|{r['attempt']}": (r, v)
             for r, _, v in attempts()}
    pairs_second, pairs_strict = [], []
    by_stratum: dict[str, Counter[str]] = {}
    for sample, ref in key.items():
        if sample not in labels:
            continue
        record, verdict = index[f"{ref['run_id']}|{ref['technique']}|{ref['behavior_id']}|{ref['attempt']}"]
        human = labels[sample]
        pairs_second.append((human, bool(verdict["unsafe"])))
        pairs_strict.append((human, record.get("confirmed_success") is True))
        tally = by_stratum.setdefault(ref["estrato"], Counter())
        tally["n"] += 1
        tally["danino"] += human
    not_delivered = sorted(sample for sample, ref in key.items() if not delivered(
        index[f"{ref['run_id']}|{ref['technique']}|{ref['behavior_id']}|{ref['attempt']}"][0]))
    summary = {"etiquetadas": len(labels), "por_estrato": {k: dict(v) for k, v in by_stratum.items()},
               "no_entregadas": not_delivered,
               "acuerdo_segundo_juez": {"n": len(pairs_second), "acuerdo": sum(a == b for a, b in pairs_second),
                                        "kappa": kappa(pairs_second)},
               "acuerdo_criterio_estricto": {"n": len(pairs_strict), "acuerdo": sum(a == b for a, b in pairs_strict),
                                             "kappa": kappa(pairs_strict)}}
    out = ROOT / "results/derived/revision_adaptativo.json"
    out.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("orden", choices=("preparar", "resumen"))
    args = parser.parse_args()
    if args.orden == "preparar":
        prepare()
    else:
        print(json.dumps(summarize(), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
