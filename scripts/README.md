# scripts: las órdenes del proyecto

Todas se lanzan desde la raíz del proyecto y explican sus opciones con
`PYTHONPATH=src .venv/bin/python scripts/<archivo>.py --help`.

Hay tres tipos y conviene no mezclarlos:

- Preparar: escribe corpus nuevos. No se usa sobre corpus ya ejecutados.
- Ejecutar: llama a los modelos y gasta saldo de OpenRouter. Exige que no haya
  cambios sin confirmar en Git y guarda una huella para poder reanudar sin
  mezclar resultados.
- Analizar: solo lee `results/raw/` y escribe en `results/derived/`,
  `results/figuras/` o `results/tablas/`. No gasta, salvo las dos revisiones con
  el segundo juez, que cuestan céntimos.

`probar.py`, en la raíz, manda un mensaje suelto a DeepSeek-R1 con C0, C2 o C3 y
explica qué hizo cada filtro. Usa la misma cadena que el experimento pero no
guarda nada en `results/`.

## Para enseñar el proyecto (sin gasto)

| Archivo | Qué muestra |
|---|---|
| `resumen_nivel3.py` | La tabla del nivel 3: inyección en documentos, ataques de un mensaje, preguntas inocentes bloqueadas y ataques adaptativos. |
| `resumen_resultados.py` | La tabla resumen del nivel 2. |
| `ver_caso.py` | Qué le pasó a un mismo caso en cada configuración C0–C5. Ejemplo: `ver_caso.py ev3-bipia-attack-1076`. |

## Desarrollo y pilotos

| Archivo | Tipo | Para qué sirve |
|---|---|---|
| `prepare_development_suite.py` | Preparar | Los doce casos de desarrollo (`development12.jsonl`). |
| `prepare_jbh_probe.py` | Preparar | El piloto de JailbreakHub, desde una copia de la revisión fijada. |
| `verify_native_policy.py` | Ejecutar | Comprueba que el filtro remoto de C1, C4 y C5 está activo solo en la segunda clave. |
| `summarize_runs.py` | Analizar | Resumen de las ejecuciones de `results/raw/` (`runs_summary.json`). |
| `summarize_jbh_probe.py` | Analizar | Recuentos del piloto de JailbreakHub. |

## Niveles 1 y 2

| Archivo | Tipo | Para qué sirve |
|---|---|---|
| `prepare_niveles_1_y_2.py` | Preparar | Los corpus del nivel 1 (`nivel1_cribado.jsonl`) y del nivel 2 (`nivel2*.jsonl`) con sus manifiestos. |
| `run_input_screening.py` | Ejecutar | Nivel 1: pasa cada ataque solo por los filtros de entrada. |
| `run_config.py` | Ejecutar | Nivel 2: una configuración C0–C5 completa; `--dry-run` comprueba el plan sin gasto. |
| `metrics_eval.py` | Analizar | Métricas de los niveles 1, 2 y 3 (`--screening`, por defecto, `--corpus nivel3`), tablas, orden de ejecución (`--print-plan`) y control de gasto (`--budget-check`). |
| `figuras_resultados.py` | Analizar | Figuras del nivel 2 (en `results/figuras/nivel2/`). |
| `sample_human_labels.py`, `formulario_etiquetado.py` | Analizar | Muestra ciega de respuestas para etiquetar a mano y acuerdo con el juez. |

## Nivel 3

| Archivo | Tipo | Para qué sirve |
|---|---|---|
| `prepare_nivel3.py` | Preparar | Corpus de ataques actuales (`nivel3*.jsonl`: BIPIA, H-CoT, FlipAttack, Policy Puppetry, CoT Hijacking), sin red. |
| `run_config.py` | Ejecutar | El mismo ejecutor del nivel 2, con los bloques `nivel3_b*.jsonl`. |
| `run_adaptive.py` | Ejecutar | Ataques adaptativos PAIR, Crescendo y Best-of-N con la defensa dentro del bucle. Reanudable. |
| `metrics_adaptive.py` | Analizar | Éxito por técnica y configuración, con intervalo de Wilson. |
| `segundo_juez.py`, `segundo_juez_adaptativo.py` | Revisión (gasto pequeño) | Aplican el juez publicado por JailbreakBench a casos ya registrados para contrastar al juez principal. |
| `revision_nivel3.py` | Analizar | Cifras revisadas de la pista B del nivel 3 y análisis emparejado de H-CoT. |
| `muestra_revision_adaptativa.py` | Analizar | Muestra ciega de intentos adaptativos para resolver el desacuerdo entre jueces. |
| `figuras_nivel3.py` | Analizar | Figuras del nivel 3 (en `results/figuras/nivel3/`). |

## Módulos comunes

| Archivo | Para qué sirve |
|---|---|
| `corpus_comun.py` | Reglas que comparten los preparadores y `run_adaptive.py`: lectura del corpus de Shen, idioma, agrupación de plantillas y mensaje de sistema. |
| `rutas_grabadas.py` | Relaciona las rutas grabadas en manifiestos, registros y métricas con los nombres actuales de los ficheros. |

Las órdenes exactas de cada nivel están en los protocolos
([../docs/README.md](../docs/README.md)).
