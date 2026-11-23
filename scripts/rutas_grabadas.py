"""Correspondencia entre las rutas grabadas en los datos y los nombres actuales.

Los manifiestos de los corpus, la auditoría del nivel 2, las cabeceras de
results/raw y las métricas de results/derived guardan las rutas con las que se
generaron. Esos ficheros son la evidencia y no se modifican; los ficheros sí se
renombraron para que el nombre diga a qué nivel pertenecen. Esta tabla es el
único sitio que relaciona una cosa con la otra:

- ``actual`` traduce una ruta leída de un manifiesto al fichero de hoy;
- ``grabada`` hace lo contrario, para que los preparadores y las métricas
  escriban exactamente los mismos bytes que se congelaron.

Los identificadores internos (``corpus_id`` y los prefijos de ``prompt_id`` y
``run_id``) no son rutas y no cambian.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Ruta grabada en los datos -> ruta actual del fichero (relativas a la raíz).
RENOMBRADOS: dict[str, str] = {
    "data/attacks/screen_v2.jsonl": "data/attacks/nivel1_cribado.jsonl",
    "data/attacks/screen_v2_manifest.json": "data/attacks/nivel1_cribado_manifest.json",
    "data/attacks/eval_v2.jsonl": "data/attacks/nivel2.jsonl",
    **{f"data/attacks/eval_v2_b{i}.jsonl": f"data/attacks/nivel2_b{i}.jsonl" for i in range(1, 9)},
    "data/attacks/eval_v2_manifest.json": "data/attacks/nivel2_manifest.json",
    "data/attacks/eval_v2_audit.json": "data/attacks/nivel2_audit.json",
    "data/attacks/eval_v2_budget.json": "data/attacks/nivel2_budget.json",
    "data/attacks/eval_v2_source_files.json": "data/attacks/nivel2_source_files.json",
    "data/attacks/eval_v3.jsonl": "data/attacks/nivel3.jsonl",
    **{f"data/attacks/eval_v3_b{i}.jsonl": f"data/attacks/nivel3_b{i}.jsonl" for i in range(1, 5)},
    "data/attacks/eval_v3_manifest.json": "data/attacks/nivel3_manifest.json",
    "data/attacks/licenses/eval_v3_templates_MIT.txt": "data/attacks/licenses/nivel3_templates_MIT.txt",
    "scripts/prepare_eval_v2.py": "scripts/prepare_niveles_1_y_2.py",
    "scripts/prepare_eval_v3.py": "scripts/prepare_nivel3.py",
    "docs/protocolo_evaluacion_v2.md": "docs/protocolo_niveles_1_y_2.md",
    "docs/protocolo_evaluacion_v3.md": "docs/protocolo_nivel3.md",
}
_INVERSA = {nueva: vieja for vieja, nueva in RENOMBRADOS.items()}


def actual(ruta: str) -> str:
    """Ruta actual de un fichero a partir de la ruta grabada en los datos."""
    return RENOMBRADOS.get(ruta, ruta)


def grabada(ruta: str) -> str:
    """Ruta con la que el fichero quedó grabado en manifiestos y métricas."""
    return _INVERSA.get(ruta, ruta)


def fichero(ruta: str) -> Path:
    """Fichero actual (absoluto) que corresponde a una ruta grabada."""
    return ROOT / actual(ruta)
