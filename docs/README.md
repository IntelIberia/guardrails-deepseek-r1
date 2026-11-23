# Documentación

Si es tu primer contacto con el proyecto, empieza por el
[README general](../README.md). Después, en este orden:

| # | Documento | Qué cuenta |
|---|---|---|
| 1 | [glosario.md](glosario.md) | Los términos del proyecto en lenguaje llano. |
| 2 | [arquitectura.md](arquitectura.md) | Cómo recorre un caso el banco y qué hace cada parte del código. |
| 3 | [desviaciones_anteproyecto.md](desviaciones_anteproyecto.md) | En qué me aparto del anteproyecto y por qué. |
| 4 | [protocolo_evaluacion_v2.md](protocolo_evaluacion_v2.md) | Niveles 1 y 2: cribado de entrada (`screen_v2`) y evaluación completa C0–C5 (`eval_v2`). |
| 5 | [protocolo_evaluacion_v3.md](protocolo_evaluacion_v3.md) | Nivel 3 con ataques actuales de un mensaje e inyección en documentos (`eval_v3`), con su ejecución y revisión. |
| 6 | [protocolo_v3_adaptativo.md](protocolo_v3_adaptativo.md) | Nivel 3 con atacantes automáticos (PAIR, Crescendo, Best-of-N): diseño, gasto y resultados. |

Los protocolos se escribieron antes de ejecutar cada fase y no se reescriben
después: los cambios se añaden al final como desviaciones con fecha.

## Para consultar

| Documento | Qué cuenta |
|---|---|
| [criterios_estudio.md](criterios_estudio.md) | Por qué el estudio está diseñado así: escenarios, políticas, corpus, juez y métricas. Los protocolos citan sus secciones. |
| [desarrollo_escenarios.md](desarrollo_escenarios.md) | Los tres escenarios de ataque (LLM01, LLM05, LLM07) y el corpus de desarrollo. |
| [openrouter_native.md](openrouter_native.md) | C1: el filtro de inyección de OpenRouter y cómo activarlo. |
| [nemo.md](nemo.md) | C2: NeMo Guardrails y su política. |
| [salvaguarda_llama_guard.md](salvaguarda_llama_guard.md) | C3: Llama Guard 4. |
| [salvaguarda_guardrails_ai.md](salvaguarda_guardrails_ai.md) | La capa de salida de C5: Guardrails AI y el consumidor simulado. |
| [protocolos.md](protocolos.md) | Los pilotos de integración de cada filtro, antes de la evaluación. |
| [registro_ejecuciones.md](registro_ejecuciones.md) | Los pilotos ejecutados, con sus costes y huellas. |

Los corpus tienen su propio índice en
[../data/attacks/README.md](../data/attacks/README.md) y los resultados en
[../results/README.md](../results/README.md).
