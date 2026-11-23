# Órdenes de trabajo

Ejecuta las órdenes desde la raíz del proyecto. Cada una explica sus opciones con
`PYTHONPATH=src .venv/bin/python scripts/<archivo>.py --help`.

Hay tres tipos de orden, y conviene no mezclarlos:

- **Preparar** escribe corpus nuevos. No se usa sobre corpus ya ejecutados.
- **Ejecutar** llama a los modelos y **consume créditos**. Exige un árbol Git
  limpio y guarda una huella para poder reanudar sin mezclar resultados.
- **Analizar** solo lee `results/raw/` y escribe en `results/derived/`,
  `results/figuras/` o `results/tablas/`. No hace llamadas de pago, salvo las dos revisiones indicadas.

## Para enseñar el proyecto (sin gasto)

| Archivo | Qué muestra |
|---|---|
| `resumen_nivel3.py` | La tabla del nivel 3: inyección en documentos, ataques de un mensaje, peticiones inocentes bloqueadas y ataques adaptativos. |
| `resumen_resultados.py` | La tabla resumen de la evaluación completa del nivel 2. |
| `ver_caso.py` | Qué le pasó a un mismo caso en cada configuración C0–C5. Ejemplo: `ver_caso.py ev3-bipia-attack-1076`. |

## Niveles 1 y 2

| Archivo | Tipo | Para qué sirve |
|---|---|---|
| `prepare_development_suite.py` | Preparar | Los doce casos de desarrollo. |
| `prepare_jbh_probe.py` | Preparar | El piloto de JailbreakHub, desde una copia de la revisión fijada. |
| `prepare_eval_v1.py`, `prepare_eval_v2.py` | Preparar | Los corpus reservados de evaluación y sus manifiestos. |
| `verify_native_policy.py` | Ejecutar | Comprueba que el filtro remoto de C1, C4 y C5 está activo. |
| `run_input_screening.py` | Ejecutar | Nivel 1: pasa cada ataque solo por los filtros de entrada. |
| `run_config.py` | Ejecutar | Nivel 2: una configuración C0–C5 completa; `--dry-run` comprueba el plan sin gasto. |
| `summarize_runs.py`, `summarize_jbh_probe.py` | Analizar | Resumen general de las ejecuciones y del piloto de JailbreakHub. |
| `metrics_eval.py` | Analizar | Métricas, tablas y contrastes de la evaluación. |
| `figuras_resultados.py` | Analizar | Figuras del nivel 2 (en `results/figuras/nivel2/`). |
| `sample_human_labels.py`, `formulario_etiquetado.py` | Analizar | Muestra ciega de respuestas para etiquetar a mano y acuerdo con el juez. |

## Nivel 3

| Archivo | Tipo | Para qué sirve |
|---|---|---|
| `prepare_eval_v3.py` | Preparar | Corpus de ataques actuales (BIPIA, H-CoT, FlipAttack, Policy Puppetry, CoT Hijacking), sin red. |
| `run_config.py` | Ejecutar | El mismo ejecutor del nivel 2, con el corpus `eval_v3`. |
| `run_adaptive.py` | Ejecutar | Ataques adaptativos PAIR, Crescendo y Best-of-N con la defensa dentro del bucle. Reanudable. |
| `metrics_adaptive.py` | Analizar | Éxito por técnica y configuración, con intervalo de Wilson. Rechaza conductas duplicadas salvo `--omitir`. |
| `segundo_juez.py`, `segundo_juez_adaptativo.py` | Revisión (pago pequeño) | Aplican el juez publicado por JailbreakBench a casos ya registrados, como contraste del juez principal. |
| `revision_nivel3.py` | Analizar | Cifras revisadas de la pista B del nivel 3 y análisis emparejado de H-CoT. |
| `muestra_revision_adaptativa.py` | Analizar | Muestra ciega de intentos adaptativos para resolver el desacuerdo entre jueces. |
| `figuras_nivel3.py` | Analizar | Figuras del nivel 3 (en `results/figuras/nivel3/`). |

Los protocolos de cada nivel, con las órdenes exactas usadas en la campaña, están
en [../docs/README.md](../docs/README.md).
