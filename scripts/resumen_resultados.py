"""Imprime la tabla resumen de la evaluación completa por configuración.

Uso:
    .venv/bin/python scripts/resumen_resultados.py

Lee results/derived/eval_v2_metrics.json (lo genera scripts/metrics_eval.py).
Entre corchetes, el intervalo de confianza de Wilson al 95 %.
"""

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
METRICS = ROOT / "results/derived/eval_v2_metrics.json"
CONFIGS = ("C0", "C1", "C2", "C3", "C4", "C5")


def pct(cell: dict[str, Any] | None) -> str:
    if not cell or not cell.get("n"):
        return "-"
    low, high = cell["wilson95"]
    return f"{100 * cell['p']:5.1f} % [{100 * low:2.0f}-{100 * high:2.0f}]"


def main() -> int:
    if not METRICS.exists():
        sys.exit("Falta results/derived/eval_v2_metrics.json: ejecuta antes scripts/metrics_eval.py")
    m = json.loads(METRICS.read_text(encoding="utf-8"))
    print(f"Evaluación completa: {m['observations']} observaciones, "
          f"bloques completos {len(m['blocks_with_all_runs'])} de 8\n")
    header = f"{'':4}{'Éxito ataques A':>22}{'Éxito ataques B':>22}{'Benignos bloq. A':>22}{'Benignos bloq. B':>22}{'Errores':>9}"
    print(header)
    print("-" * len(header))
    for config in CONFIGS:
        asr = m["asr"][config]
        benign = m["benign"]
        errors = m["errors"][config]["excluded_technical_errors"]
        print(f"{config:4}{pct(asr['A']['union']):>22}{pct(asr['B']['union']):>22}"
              f"{pct(benign['A'][config]['defence_fpr']):>22}"
              f"{pct(benign['B'][config]['defence_fpr']):>22}{errors:>9}")
    print("\nA: fuga del secreto, secuestro de instrucciones y salida insegura.")
    print("B: peticiones dañinas de JailbreakBench (juez).")
    print("Errores: casos que NeMo no llegó a evaluar; no cuentan como bloqueo.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
