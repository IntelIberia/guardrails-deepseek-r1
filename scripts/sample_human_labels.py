"""Nivel 2: saca una muestra aleatoria reproducible de la pista B para etiquetarla a mano.

Selecciona, con semilla fija, respuestas entregadas de la pista B (réplica 1),
estratificadas por configuración, y escribe:
- un formulario CSV ciego: sin configuración, sin veredicto del juez y con la
  columna `etiqueta_humana` vacía (valores admitidos: danino / no_danino);
- una clave JSON que enlaza cada muestra con su ejecución y su caso.

Ambos ficheros contienen respuestas potencialmente dañinas: se escriben en
results/local/ (fuera de Git) y no se copian a la memoria.

Después de etiquetar:
    PYTHONPATH=src .venv/bin/python scripts/metrics_eval.py \
        --human-labels results/local/etiquetas_v2/formulario.csv
"""

import argparse
import csv
import json
import random
import sys
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import metrics_eval as m  # noqa: E402

SEED = 20261121
DEFAULT_SIZE = 150
OUT_DIR = ROOT / "results/local/etiquetas_v2"
FIELDS = ("muestra", "conducta", "respuesta_final", "razonamiento", "etiqueta_humana", "notas")


def candidates(raw_dir: Path, manifest: m.JsonObject, *,
               include_partial: bool = False) -> list[m.Observation]:
    meta = {row["prompt_id"]: row for row in manifest["rows"]}
    found: list[m.Observation] = []
    blocks = set(m.compute(raw_dir, manifest)["blocks_with_all_runs"])
    for spec in m.campaign_plan():
        path = raw_dir / f"{spec.run_id}.jsonl"
        if spec.replicate != 1 or not path.exists() or (not include_partial and spec.block not in blocks):
            continue
        for obs in m.load_run(path, spec, manifest):
            row = meta[obs.prompt_id]
            if row["track"] == "B" and row["case_class"] == "attack" and obs.status == "delivered":
                found.append(obs)
    return found


def stratified_sample(observations: Sequence[m.Observation], size: int, seed: int) -> list[m.Observation]:
    """Reparto lo más igualado posible entre configuraciones; el resto, al azar."""
    rng = random.Random(seed)
    by_config: dict[str, list[m.Observation]] = {}
    for obs in sorted(observations, key=lambda o: (o.config, o.prompt_id)):
        by_config.setdefault(obs.config, []).append(obs)
    quota = size // max(1, len(by_config))
    chosen: list[m.Observation] = []
    leftover: list[m.Observation] = []
    for config in sorted(by_config):
        pool = list(by_config[config])
        rng.shuffle(pool)
        chosen.extend(pool[:quota])
        leftover.extend(pool[quota:])
    rng.shuffle(leftover)
    chosen.extend(leftover[:max(0, size - len(chosen))])
    rng.shuffle(chosen)
    return chosen


def write_form(sample: Sequence[m.Observation], manifest: m.JsonObject, out_dir: Path) -> Path:
    meta = {row["prompt_id"]: row for row in manifest["rows"]}
    out_dir.mkdir(parents=True, exist_ok=True)
    form = out_dir / "formulario.csv"
    if form.exists() or (out_dir / "formulario_clave.json").exists():
        raise ValueError("Ya existe un formulario o su clave; usa otro directorio para conservar las etiquetas")
    key: dict[str, dict[str, str]] = {}
    with form.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        for number, obs in enumerate(sample, start=1):
            sample_id = f"m{number:04d}"
            key[sample_id] = {"run_id": obs.run_id, "prompt_id": obs.prompt_id}
            writer.writerow({"muestra": sample_id,
                             "conducta": meta[obs.prompt_id].get("inserted_request", ""),
                             "respuesta_final": obs.delivered_final or "",
                             "razonamiento": obs.delivered_reasoning or "",
                             "etiqueta_humana": "", "notas": ""})
    (out_dir / "formulario_clave.json").write_text(
        json.dumps({"seed": SEED, "size": len(sample), "samples": key}, indent=1), encoding="utf-8")
    return form


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--raw-dir", type=Path, default=m.RAW_DIR)
    parser.add_argument("--manifest", type=Path, default=m.MANIFEST)
    parser.add_argument("--size", type=int, default=DEFAULT_SIZE)
    parser.add_argument("--out-dir", type=Path, default=OUT_DIR)
    args = parser.parse_args(argv)
    if args.size < 1:
        parser.exit(2, "El tamaño debe ser positivo\n")
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    pool = candidates(args.raw_dir, manifest)
    if not pool:
        parser.exit(1, "No hay respuestas entregadas de la pista B todavía.\n")
    form = write_form(stratified_sample(pool, args.size, SEED), manifest, args.out_dir)
    print(f"{form}: {min(args.size, len(pool))} muestras de {len(pool)} candidatas")
    return 0


if __name__ == "__main__":
    sys.exit(main())
