# results: los resultados

| Carpeta | Qué hay |
|---|---|
| `raw/` | Registros originales de cada ejecución, un fichero JSONL por `run_id`. Son la evidencia y no se modifican nunca. |
| `raw/adaptive/` | Registros de los ataques adaptativos del nivel 3 (`ad3-*.jsonl`): un intento por línea y un registro `final` por conducta. |
| `derived/` | Resúmenes calculados a partir de `raw/` con scripts que solo leen. |

`derived/` contiene:

| Fichero | Qué resume | Lo genera |
|---|---|---|
| `screen_v2_metrics.json` | Nivel 1, cribado de entrada | `metrics_eval.py --screening` |
| `eval_v2_metrics.json` | Nivel 2, evaluación completa | `metrics_eval.py` |
| `revision_pista_b.json` | Revisión de los positivos del juez en el nivel 2 | Sin script; ver el protocolo v2 |
| `eval_v3_metrics.json` | Nivel 3, corpus estático | `metrics_eval.py --corpus eval_v3 …` |
| `revision_nivel3.json` | Nivel 3 revisado con el segundo juez y análisis de H-CoT | `revision_nivel3.py` |
| `adaptive_metrics.json` | Nivel 3, ataques adaptativos | `metrics_adaptive.py` |
| `segundo_juez/` | Veredictos del segundo juez (solo identificadores y etiquetas) | `segundo_juez.py`, `segundo_juez_adaptativo.py` |
| `runs_summary.json` | Los pilotos del 17 al 19-11-2026 | `summarize_runs.py` |
| `jbh-c0-transfer-20261118.json` | El piloto de JailbreakHub | `summarize_jbh_probe.py` |
| `jbh-c0-transfer-20261118_credits.json` | Saldo de OpenRouter antes y después de ese piloto, para cuadrar el coste | Consulta manual de solo lectura |

`runs_summary.json` se generó antes de la evaluación y solo recoge los once
pilotos; las cifras de la evaluación están en los ficheros de métricas. La
explicación de cada piloto está en
[../docs/registro_ejecuciones.md](../docs/registro_ejecuciones.md).

Los scripts de figuras y tablas (`metrics_eval.py`, `figuras_resultados.py`,
`figuras_nivel3.py`) escriben en `figuras/` y `tablas/`, que no están en el
repositorio porque se regeneran. La ficha de verificación de la política nativa de
OpenRouter va a `local/`, también fuera de Git.

## Cómo leer un JSONL de `raw/`

- La primera línea es la cabecera: configuración efectiva, commit de Git,
  huellas del corpus y del código, versiones de las librerías.
- Cada línea siguiente es un caso, con todas sus etapas: decisión de cada
  salvaguarda, respuesta final, razonamiento, veredicto del juez, intentos,
  latencias y coste.
- `c1-verificacion-nativa-20261119.json` es la comprobación de las dos claves
  de OpenRouter antes de los pilotos de C1, C4 y C5.

Para comprobar que una copia es la original:
`shasum -a 256 results/raw/*.jsonl` y comparar con las huellas del registro.
