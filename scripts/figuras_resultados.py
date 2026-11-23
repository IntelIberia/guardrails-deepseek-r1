"""Dibuja las figuras de los niveles 1 y 2 a partir de las métricas, sin llamar a ningún modelo.

Uso: PYTHONPATH=src .venv/bin/python scripts/figuras_resultados.py
Entradas auxiliares: --screening, --screen-manifest y --agreement (JSON del
script formulario_etiquetado.py). --synthetic usa exclusivamente un temporal.
Los datos ausentes se omiten y se registran en figuras_generadas.json.
"""

import argparse
import json
import math
import os
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from scripts import metrics_eval as m  # noqa: E402

Json = dict[str, Any]
PATTERNS = ("", "//", "\\\\", "xx", "..", "++")


def pyplot() -> Any:
    os.environ.setdefault("MPLCONFIGDIR", str(Path(tempfile.gettempdir()) / "tfg-figuras-mpl"))
    os.environ.setdefault("XDG_CACHE_HOME", str(Path(tempfile.gettempdir()) / "tfg-figuras-cache"))
    try:
        import matplotlib
    except ImportError as exc:
        raise RuntimeError("Falta matplotlib en .venv; no se ha instalado ninguna dependencia.") from exc
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({"font.family": "serif", "font.size": 10, "pdf.fonttype": 42,
                         "axes.spines.top": False, "axes.spines.right": False})
    return plt


def interval_bars(ax: Any, labels: Sequence[str], items: Sequence[Json]) -> None:
    """No convierte una proporción sin denominador en un cero observado."""
    for i, (label, item) in enumerate(zip(labels, items, strict=True)):
        n, k = item["n"], item["k"]
        interval = m.wilson(k, n)
        if interval is None:
            ax.text(i, 3, "s/d", ha="center")
            continue
        p = k / n
        ax.bar(i, 100 * p, color="0.85", edgecolor="black", hatch=PATTERNS[i % 6], width=.6)
        ax.errorbar(i, 100 * p, yerr=[[max(0., 100 * (p - interval[0]))],
                                    [max(0., 100 * (interval[1] - p))]],
                    fmt="none", ecolor="black", capsize=3)
        ax.text(i, 104, f"{k}/{n}" + ("†" if n < 20 else ""), ha="center", fontsize=8)
    ax.set_xticks(range(len(labels)), labels)
    ax.set_ylim(0, 114)
    ax.set_yticks([0, 25, 50, 75, 100])
    ax.set_ylabel("Proporción (%); IC de Wilson del 95 %")


def matrix_plot(plt: Any, rows: Sequence[str], cols: Sequence[str], values: list[list[Any]],
                *, percent: bool = True) -> tuple[Any, Any]:
    import numpy as np
    data = np.array([[np.nan if x is None else x for x in row] for row in values], dtype=float)
    if percent:
        data *= 100
    fig, ax = plt.subplots(figsize=(max(5.8, len(cols) * .9), max(3., len(rows) * .4 + 1.3)))
    mesh = ax.pcolormesh(np.ma.masked_invalid(data), cmap="Greys", edgecolors="0.6",
                         linewidth=.4, vmin=0, vmax=100 if percent else max(1., float(np.nanmax(data))),
                         rasterized=False)
    ax.set_xticks([x + .5 for x in range(len(cols))], cols)
    ax.set_yticks([y + .5 for y in range(len(rows))], rows)
    ax.invert_yaxis()
    for i, row in enumerate(data):
        for j, value in enumerate(row):
            maximum = 100 if percent else max(1., float(np.nanmax(data)))
            ax.text(j + .5, i + .5, "s/d" if math.isnan(value) else f"{value:.0f}",
                    ha="center", va="center", fontsize=8,
                    color="white" if value > .55 * maximum else "black")
    fig.colorbar(mesh, ax=ax, label="ASR (%)" if percent else "Respuestas (n)")
    return fig, ax


def funnel_counts(entry: Json) -> tuple[list[str], list[int]]:
    """Cohorte de éxitos C0 evaluables; solo bloqueos observados por etapa.

    El JSON no permite reconstruir el paso por cada filtro individual. Se
    agregan entrada (incluido el filtro nativo) y salida, sin contrafactuales.
    """
    total = entry["dsr_blocked"]["n"]
    layers = entry["dsr_blocked_by_layer"]
    output = sum(v for key, v in layers.items() if key.startswith("output:"))
    input_blocks = sum(v for key, v in layers.items() if not key.startswith("output:"))
    if input_blocks + output != entry["dsr_blocked"]["k"]:
        raise ValueError("El desglose de capas no coincide con DSR")
    return ["Evaluables", "Tras entrada y filtro nativo", "Tras salida"], [
        total, total - input_blocks, total - input_blocks - output]


def generate(metrics: Json, out: Path, *, screening: Json | None = None,
             attack_families: set[str] | None = None, agreement: Json | None = None) -> Json:
    synthetic = bool(metrics.get("synthetic"))
    if synthetic and (out.resolve().is_relative_to((ROOT / "results").resolve())
                      or not out.resolve().is_relative_to(Path(tempfile.gettempdir()).resolve())):
        raise ValueError("Las figuras sintéticas solo pueden escribirse en un directorio temporal")
    plt = pyplot()
    out.mkdir(parents=True, exist_ok=True)
    report: Json = {"synthetic": synthetic, "campaign_complete": metrics.get("campaign_complete"),
                    "blocks_with_all_runs": metrics.get("blocks_with_all_runs"),
                    "generated": [], "pending": [],
                    "cost_latency_coverage": metrics["cost_latency"],
                    "notes": ["†: n < 20, solo descriptivo; s/d: sin datos.",
                              "Pistas A y B separadas; intervalos nominales por caso.",
                              "Embudo: éxitos de C0 evaluables, sin simular capas posteriores.",
                              "Coste: media solo sobre casos completos, puede incluir bloques parciales.",
                              "Latencia: bloques del análisis principal, sin juez."]}

    def save(fig: Any, name: str) -> None:
        if synthetic:
            fig.canvas.draw()
            bounds = fig.get_tightbbox(fig.canvas.get_renderer())
            fig.text(.5, (bounds.y0 - .25) / fig.get_figheight(),
                     "DATOS SINTÉTICOS · SOLO PRUEBAS", ha="center", fontsize=9)
        fig.savefig(out / f"{name}.pdf", bbox_inches="tight", pad_inches=.18)
        plt.close(fig)
        report["generated"].append(f"{name}.pdf")

    for track in ("A", "B"):
        for name, configs, items in (
            ("asr", m.CONFIGS, [metrics["asr"][c][track]["union"] for c in m.CONFIGS]),
            ("dsr", m.CONFIGS[1:], [metrics["dsr"]["by_scope"][track]["configs"][c]["dsr_blocked"]
                                    for c in m.CONFIGS[1:]])):
            fig, ax = plt.subplots(figsize=(6.5, 3.6))
            interval_bars(ax, configs, items)
            ax.set_xlabel(f"Configuración · pista {track} · {name.upper()}")
            save(fig, f"{name}_{track}")
        families = sorted({s for c in m.CONFIGS for s in metrics["asr"][c]
                           if s.startswith(f"fam:{track}:")})
        if families:
            values = [[metrics["asr"][c].get(s, {}).get("union", {}).get("p")
                       for c in m.CONFIGS] for s in families]
            labels = [s.split(":", 2)[2].replace("_", " ") for s in families]
            fig, ax = matrix_plot(plt, labels, m.CONFIGS, values)
            # El denominador varía entre configuraciones: se anota por celda.
            for text in ax.texts:
                x, y = text.get_position()
                item = metrics["asr"][m.CONFIGS[int(x)]].get(families[int(y)], {}).get("union", {})
                if item.get("n", 0):
                    text.set_text(text.get_text() + f"\n(n={item['n']})" + ("†" if item["n"] < 20 else ""))
            ax.set_xlabel(f"Configuración · pista {track}")
            save(fig, f"familias_{track}")
        fig, ax = plt.subplots(figsize=(6.3, 3.8))
        for i, c in enumerate(m.CONFIGS):
            asr = metrics["asr"][c][track]["union"]["p"]
            fpr = metrics["benign"][track][c]["defence_fpr"]["p"]
            if asr is not None and fpr is not None:
                ax.scatter(100 * fpr, 100 * (1 - asr), marker=["o", "s", "^", "D", "v", "P"][i],
                           facecolor="white", edgecolor="black", label=c)
        ax.set(xlabel=f"FPR de defensa (%) · pista {track}", ylabel="Ataques sin éxito: 100 − ASR (%)",
               xlim=(-2, 102), ylim=(-2, 102))
        if ax.get_legend_handles_labels()[0]:
            ax.legend(ncol=3)
        save(fig, f"seguridad_fpr_{track}")
        fig, ax = plt.subplots(figsize=(7, 4))
        for c in m.CONFIGS[1:]:
            labels, counts = funnel_counts(metrics["dsr"]["by_scope"][track]["configs"][c])
            ax.plot(range(3), counts, marker="o", color=str(.12 * int(c[1])),
                    linestyle=["-", "--", ":", "-.", "-"][int(c[1]) - 1], label=c)
        ax.set_xticks(range(3), labels, fontsize=9)
        ax.set_ylabel(f"Casos restantes de la cohorte C0 · pista {track}")
        ax.set_ylim(bottom=0)
        ax.legend(ncol=5)
        save(fig, f"embudo_{track}")
    fig, axes = plt.subplots(1, 2, figsize=(10, 3.8))
    cost = metrics["cost_latency"]
    base = cost["C0"]["mean_deployment_over_complete_cases_usd"]
    for i, c in enumerate(m.CONFIGS):
        value = cost[c]["mean_deployment_over_complete_cases_usd"]
        delta = None if value is None or base is None else value - base
        latency = cost[c]["added_median_latency_vs_c0_ms"]
        for ax, val in ((axes[0], delta), (axes[1], None if latency is None else latency / 1000)):
            if val is None:
                ax.text(i, 0, "s/d", ha="center")
            else:
                ax.bar(i, val, color="0.85", edgecolor="black", hatch=PATTERNS[i])
        axes[0].text(i, 1.02, f"aus.: {cost[c]['cases_with_any_missing_cost']}",
                     transform=axes[0].get_xaxis_transform(), ha="center", fontsize=7)
    for ax in axes:
        ax.set_xticks(range(6), m.CONFIGS)
        ax.axhline(0, color="black", linewidth=.6)
        ax.set_xlabel("Configuración")
    axes[0].set_ylabel("Diferencia de coste medio frente a C0 (USD/caso)")
    axes[1].set_ylabel("Diferencia de medianas frente a C0 (s)")
    fig.tight_layout()
    save(fig, "coste_latencia")
    fig, axes = plt.subplots(1, 2, figsize=(10, 3.8))
    for ax, channel, label in zip(axes, ("final", "reasoning"), ("Respuesta final", "Razonamiento"), strict=True):
        interval_bars(ax, m.CONFIGS, [metrics["asr"][c]["A:LLM07"][channel] for c in m.CONFIGS])
        ax.set_xlabel(f"{label} · canaria entregada (LLM07)")
    fig.tight_layout()
    save(fig, "fuga_canaria")
    if screening is not None and attack_families is not None:
        for track in ("A", "B"):
            families = sorted(f for f in attack_families if f.startswith(f"{track}:"))
            if not families:
                continue
            fig, ax = plt.subplots(figsize=(8, max(3.5, len(families) * .55 + 1.3)))
            for j, (key, label) in enumerate(zip(m.SCREEN_FILTERS, ("NeMo", "Llama Guard 4", "OpenRouter"), strict=True)):
                for i, family in enumerate(families):
                    item = screening["by_filter"][key]["family"].get(family)
                    if not item or not item["n"]:
                        ax.text(1, i + (j - 1) * .22, "s/d", fontsize=7)
                        continue
                    p = item["k"] / item["n"]
                    low, high = m.wilson(item["k"], item["n"]) or (p, p)
                    ax.errorbar(100 * p, i + (j - 1) * .22,
                                xerr=[[max(0., 100 * (p - low))], [max(0., 100 * (high - p))]],
                                fmt=("o", "s", "^")[j], color=str(j * .3), capsize=2,
                                label=label if i == 0 else None)
                    ax.text(103, i + (j - 1) * .22, f"{item['k']}/{item['n']}" + ("†" if item['n'] < 20 else ""), fontsize=7, va="center")
            ax.set_yticks(range(len(families)), [f.split(":", 1)[1].replace("_", " ") for f in families])
            ax.set(xlim=(-2, 125), xlabel=f"Detección (%); IC de Wilson del 95 % · pista {track}")
            ax.set_xticks([0, 25, 50, 75, 100])
            ax.legend(loc="upper center", bbox_to_anchor=(.5, 1.15), ncol=3)
            save(fig, f"deteccion_{track}")
    else:
        report["pending"].append("Detección: faltan métricas del nivel 1 o manifiesto de familias de ataque")
    if agreement is not None and agreement.get("n", 0):
        confusion = agreement["confusion"]
        values = [[confusion.get(f"humano_{h}_juez_{j}", 0) for j in (False, True)] for h in (False, True)]
        fig, ax = matrix_plot(plt, ("No dañino", "Dañino"), ("No dañino", "Dañino"), values, percent=False)
        ax.set(xlabel="Etiqueta del juez", ylabel="Etiqueta humana")
        save(fig, "confusion_juez_humano")
    else:
        report["pending"].append("Matriz de confusión: faltan pares juez-humano")
    (out / "figuras_generadas.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return report


def synthetic_data() -> tuple[Json, Json, set[str], Json]:
    """Fixture determinista, explícitamente ajena a los resultados de la campaña."""
    metrics: Json = {"synthetic": True, "campaign_complete": False, "blocks_with_all_runs": [],
                     "asr": {}, "dsr": {"by_scope": {}}, "benign": {"A": {}, "B": {}}, "cost_latency": {}}
    for track in ("A", "B"):
        metrics["dsr"]["by_scope"][track] = {"A_size": 40, "configs": {}}
    for i, c in enumerate(m.CONFIGS):
        metrics["asr"][c] = {t: {"union": m.proportion(40 - 5 * i, 60)} for t in ("A", "B")}
        metrics["asr"][c]["A:LLM07"] = {ch: m.proportion(20 - 2 * i, 30) for ch in m.CHANNELS}
        for t in ("A", "B"):
            metrics["asr"][c][f"fam:{t}:familia_prueba"] = {"union": m.proportion(10 - i, 15)}
            metrics["benign"][t][c] = {"defence_fpr": m.proportion(i, 30)}
            if i:
                metrics["dsr"]["by_scope"][t]["configs"][c] = {
                    "dsr_blocked": m.proportion(3 * i, 40),
                    "dsr_blocked_by_layer": {"input:filtro": 2 * i, "output:filtro": i}}
        metrics["cost_latency"][c] = {"mean_deployment_over_complete_cases_usd": .001 + i * .0002,
                                      "added_median_latency_vs_c0_ms": i * 200,
                                      "cases_with_any_missing_cost": i}
    screening = {"by_filter": {f: {"family": {f"{t}:familia_prueba": m.proportion(5 + j, 15)
                                             for t in ("A", "B")}} for j, f in enumerate(m.SCREEN_FILTERS)}}
    agreement = {"n": 150, "confusion": {"humano_False_juez_False": 70, "humano_False_juez_True": 5,
                                          "humano_True_juez_False": 10, "humano_True_juez_True": 65}}
    return metrics, screening, {"A:familia_prueba", "B:familia_prueba"}, agreement


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metrics", type=Path, default=m.OUTPUT)
    parser.add_argument("--screening", type=Path, default=m.SCREEN_OUTPUT)
    parser.add_argument("--screen-manifest", type=Path, default=m.SCREEN_MANIFEST)
    parser.add_argument("--agreement", type=Path)
    parser.add_argument("--out-dir", type=Path, default=ROOT / "results/figuras/nivel2")
    parser.add_argument("--synthetic", action="store_true")
    args = parser.parse_args(argv)
    screen: Json | None
    agreement: Json | None
    if args.synthetic or not args.metrics.exists():
        out = Path(tempfile.mkdtemp(prefix="resultados-sinteticos-"))
        metrics, screen, families, agreement = synthetic_data()
        (out / "metricas_nivel2_SINTETICO.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
        print("DATOS SINTÉTICOS: prueba; no son resultados experimentales.")
    else:
        out = args.out_dir
        metrics = json.loads(args.metrics.read_text(encoding="utf-8"))
        screen = json.loads(args.screening.read_text(encoding="utf-8")) if args.screening.exists() else None
        families = None
        if args.screen_manifest.exists():
            manifest = json.loads(args.screen_manifest.read_text(encoding="utf-8"))
            families = {f"{r['track']}:{r['family']}" for r in manifest["rows"] if r["case_class"] == "attack"}
        agreement = json.loads(args.agreement.read_text(encoding="utf-8")) if args.agreement else None
    report = generate(metrics, out, screening=screen, attack_families=families, agreement=agreement)
    print(f"{out}: {len(report['generated'])} PDF vectoriales")
    for pending in report["pending"]:
        print(f"PENDIENTE: {pending}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
