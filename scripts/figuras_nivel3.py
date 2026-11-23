"""Dibuja las figuras del nivel 3 (fase 3) con el mismo estilo que las del nivel 2.

Uso: PYTHONPATH=src .venv/bin/python scripts/figuras_nivel3.py
Lee results/derived/metricas_nivel3.json y, si existen, revision_nivel3.json y
metricas_nivel3_adaptativo.json. Las figuras cuyos datos faltan se omiten y se avisa.
"""

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from scripts import metrics_eval as m  # noqa: E402
from scripts.figuras_resultados import PATTERNS, matrix_plot, pyplot  # noqa: E402

Json = dict[str, Any]
CONFIGS = ("C0", "C1", "C2", "C3", "C4", "C5")
FAMILIES = (("hcot", "H-CoT"), ("hcot_base", "Petición H-CoT sin cadena"),
            ("flipattack", "FlipAttack"), ("cot_hijacking", "CoT Hijacking"),
            ("policy_puppetry", "Policy Puppetry"))
TECHNIQUES = (("pair", "PAIR"), ("crescendo", "Crescendo"), ("bon", "Best-of-N"))
GRAYS = ("0.92", "0.62", "0.32")


def save(fig: Any, out: Path, name: str) -> None:
    fig.tight_layout()
    # Sin fecha de creación en el PDF: regenerar la misma figura no cambia el fichero.
    fig.savefig(out / f"{name}.pdf", metadata={"CreationDate": None})
    fig.savefig(out / f"{name}.png", dpi=200)
    print(f"{name}: generada")


def grouped_bars(ax: Any, groups: list[str],
                 series: Sequence[tuple[str, Sequence[tuple[int, int] | None]]], ylabel: str, *,
                 ymax: float = 125, ticks: Sequence[int] = (0, 25, 50, 75, 100),
                 label_bars: bool = False) -> None:
    """Barras agrupadas con IC de Wilson; trama y gris distintos por serie, k/n encima.

    Con ``label_bars`` cada barra lleva el nombre de su serie debajo del eje, para que
    una barra en cero siga identificándose.
    """
    width = 0.8 / len(series)
    for s, (label, items) in enumerate(series):
        for g, item in enumerate(items):
            x = g - 0.4 + width * (s + 0.5)
            if label_bars:
                ax.text(x, -0.02, label, ha="center", va="top", fontsize=7,
                        transform=ax.get_xaxis_transform())
            if item is None or item[1] == 0:
                ax.text(x, 3, "s/d", ha="center", fontsize=7)
                continue
            k, n = item
            interval = m.wilson(k, n)
            if interval is None:
                continue
            low, high = interval
            p = k / n
            ax.bar(x, 100 * p, width=width * 0.92, color=GRAYS[s % 3], edgecolor="black",
                   hatch=PATTERNS[s % 6], label=label if g == 0 else None, linewidth=0.6)
            ax.errorbar(x, 100 * p, yerr=[[max(0., 100 * (p - low))], [max(0., 100 * (high - p))]],
                        fmt="none", ecolor="black", capsize=2, linewidth=0.8)
            ax.text(x, min(100 * high, 100) + 2, f"{k}/{n}", ha="center", fontsize=6.5, rotation=90,
                    va="bottom")
    ax.set_xticks(range(len(groups)), groups)
    if label_bars:
        ax.tick_params(axis="x", length=0, pad=14)
    ax.set_ylim(0, ymax)
    ax.set_yticks(list(ticks))
    ax.set_ylabel(ylabel)
    ax.legend(frameon=False, fontsize=8, loc="upper right", ncols=len(series))


def bipia_channels(raw_dir: Path, manifest: Path) -> dict[str, tuple[int, int, int]]:
    """Por configuración (réplica 1): (marcador en la respuesta final, en la unión, evaluables).

    Las métricas del protocolo dan la unión; aquí se separa el canal final, que es el
    que indica que el modelo obedeció la instrucción inyectada y no solo la citó.
    """
    rows = {r["prompt_id"]: r for r in json.loads(manifest.read_text(encoding="utf-8"))["rows"]}
    result = {}
    for c in CONFIGS:
        final = union = n = 0
        for path in sorted(raw_dir.glob(f"ev3-b*-{c.lower()}-r1.jsonl")):
            last: dict[str, Json] = {}
            for line in path.read_text(encoding="utf-8").removesuffix("\n").split("\n")[1:]:
                record = json.loads(line)
                last[record["prompt_id"]] = record
            for pid, record in last.items():
                row = rows[pid]
                if row["family"] != "bipia" or row["case_class"] != "attack" or record.get("error"):
                    continue
                n += 1
                if record.get("blocked"):
                    continue
                marker = row["oracle"]["value"]
                in_final = marker in (record.get("response_text") or "")
                final += in_final
                union += in_final or marker in (record.get("reasoning_chain") or "")
        result[c] = (final, union, n)
    return result


def track_a(plt: Any, metrics: Json, out: Path, raw_dir: Path, manifest: Path) -> None:
    channels = bipia_channels(raw_dir, manifest)
    for c in CONFIGS:
        if channels[c][1:] != (metrics["asr"][c]["A"]["union"]["k"], metrics["asr"][c]["A"]["union"]["n"]):
            raise ValueError(f"{c}: la unión no coincide con metricas_nivel3.json")
    fig, ax = plt.subplots(figsize=(6.4, 3.4))
    series = [("Marcador en la respuesta final", [(f, n) for f, _, n in channels.values()]),
              ("En la respuesta o en el razonamiento", [(u, n) for _, u, n in channels.values()])]
    grouped_bars(ax, list(CONFIGS), series, "Inyecciones con éxito (%)\nIC de Wilson del 95 %")
    save(fig, out, "nivel3_pista_a")
    plt.close(fig)
    print("  BIPIA (final, unión, n):", channels)


def benign(plt: Any, metrics: Json, out: Path) -> None:
    fig, ax = plt.subplots(figsize=(6.4, 3.4))
    series = []
    for track, label in (("A", "Documentos benignos (BIPIA)"), ("B", "Peticiones benignas transformadas")):
        items = []
        for c in CONFIGS:
            entry = metrics["benign"][track][c]["defence_fpr"]
            items.append((entry["k"], entry["n"]))
        series.append((label, items))
    grouped_bars(ax, list(CONFIGS), series, "Benignas bloqueadas (%)\nIC de Wilson del 95 %")
    save(fig, out, "nivel3_benignos")
    plt.close(fig)


def families_b(plt: Any, revision: Json, out: Path) -> None:
    """Tasa revisada (confirmados / casos evaluables) por familia y configuración."""
    table = revision["por_familia"]
    values = []
    for key, _ in FAMILIES:
        row = []
        for c in CONFIGS:
            cell = table.get(c, {}).get(key)
            row.append(None if not cell or not cell["n"] else cell["confirmados"] / cell["n"])
        values.append(row)
    fig, ax = matrix_plot(plt, [label for _, label in FAMILIES], list(CONFIGS), values)
    ax.set_xlabel("Configuración")
    fig.axes[-1].set_ylabel("ASR revisado (%)")
    save(fig, out, "nivel3_familias_b")
    plt.close(fig)


def adaptive(plt: Any, rows: list[Json], out: Path) -> None:
    configs = sorted({r["config_id"] for r in rows if not r["is_benign"]})
    index = {(r["config_id"], r["technique"]): r for r in rows if not r["is_benign"]}
    fig, ax = plt.subplots(figsize=(6.4, 3.4))
    series = []
    for c in configs:
        items: list[tuple[int, int] | None] = []
        for key, _ in TECHNIQUES:
            r = index.get((c, key))
            items.append((r["successes"], r["n"]) if r and r["n"] else None)
        series.append((c, items))
    grouped_bars(ax, [label for _, label in TECHNIQUES], series,
                 "Conductas con jailbreak confirmado (%)\nIC de Wilson del 95 %",
                 ymax=65, ticks=(0, 20, 40, 60), label_bars=True)
    save(fig, out, "adaptativo_exito")
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--metrics", type=Path, default=ROOT / "results/derived/metricas_nivel3.json")
    parser.add_argument("--revision", type=Path, default=ROOT / "results/derived/revision_nivel3.json")
    parser.add_argument("--adaptive", type=Path, default=ROOT / "results/derived/metricas_nivel3_adaptativo.json")
    parser.add_argument("--out", type=Path, default=ROOT / "results/figuras/nivel3")
    args = parser.parse_args()
    plt = pyplot()
    args.out.mkdir(parents=True, exist_ok=True)
    metrics = json.loads(args.metrics.read_text(encoding="utf-8"))
    track_a(plt, metrics, args.out, ROOT / "results/raw", ROOT / "data/attacks/nivel3_manifest.json")
    benign(plt, metrics, args.out)
    if args.revision.exists():
        families_b(plt, json.loads(args.revision.read_text(encoding="utf-8")), args.out)
    else:
        print("nivel3_familias_b: falta la revisión de la pista B")
    if args.adaptive.exists():
        adaptive(plt, json.loads(args.adaptive.read_text(encoding="utf-8")), args.out)
    else:
        print("adaptativo_exito: faltan las métricas adaptativas")


if __name__ == "__main__":
    main()
