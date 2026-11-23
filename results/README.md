# results: los resultados

| Carpeta | Qué hay |
|---|---|
| `raw/` | Registros originales de cada ejecución, un fichero JSONL por `run_id`. Son la evidencia y no se modifican nunca. |
| `raw/adaptive/` | Registros de los ataques adaptativos del nivel 3 (`ad3-*.jsonl`): un intento por línea y un registro `final` por conducta. |
| `derived/` | Resúmenes calculados a partir de `raw/` con scripts que solo leen: métricas de cada nivel (`screen_v2_metrics.json`, `eval_v2_metrics.json`, `eval_v3_metrics.json`, `adaptive_metrics.json`), revisiones (`revision_*.json`, `segundo_juez/`) y el resumen general. |
| `figuras/`, `tablas/` | Figuras y tablas que generan `metrics_eval.py`, `figuras_resultados.py` y `figuras_nivel3.py`. Se pueden borrar y regenerar. |
| `local/` | Ficha de verificación de la política nativa de OpenRouter (huellas de las claves, nunca su valor). |

Mira primero `derived/runs_summary.json`: resume todas las ejecuciones (casos,
bloqueos, canarias, coste y latencia). La explicación de cada ejecución, en
lenguaje humano, está en
[../docs/registro_ejecuciones.md](../docs/registro_ejecuciones.md).

## Cómo leer un JSONL de `raw/`

- La primera línea es la cabecera: configuración efectiva, commit de Git,
  huellas del corpus y del código, versiones de las librerías.
- Cada línea siguiente es un caso, con todas sus etapas: decisión de cada
  salvaguarda, respuesta final, razonamiento, veredicto del juez, intentos,
  latencias y coste.
- Los ficheros `.lock` solo impiden que dos procesos escriban a la vez en la
  misma ejecución.
- `c1-verificacion-nativa-20261119.json` es la verificación de las dos claves
  de OpenRouter antes de los pilotos de C1, C4 y C5.

Para comprobar que una copia es la original:
`shasum -a 256 results/raw/*.jsonl` y comparar con las huellas del registro.

Para regenerar el resumen:
`PYTHONPATH=src .venv/bin/python scripts/summarize_runs.py`.
