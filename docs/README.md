# Documentación

Si es tu primer contacto con el proyecto, empieza por el
[README general](../README.md). Después, en este orden:

| # | Documento | Qué cuenta |
|---|---|---|
| 1 | [glosario.md](glosario.md) | Los términos del proyecto en lenguaje llano. |
| 2 | [arquitectura.md](arquitectura.md) | Cómo recorre un caso el banco y qué hace cada parte del código. |
| 3 | [desviaciones_anteproyecto.md](desviaciones_anteproyecto.md) | En qué me aparto del anteproyecto y por qué. |
| 4 | [protocolo_niveles_1_y_2.md](protocolo_niveles_1_y_2.md) | Niveles 1 y 2: cribado de entrada y evaluación completa C0–C5. |
| 5 | [protocolo_nivel3.md](protocolo_nivel3.md) | Nivel 3: ataques actuales de un mensaje e inyección en documentos. |
| 6 | [protocolo_nivel3_adaptativo.md](protocolo_nivel3_adaptativo.md) | Nivel 3: atacantes automáticos (PAIR, Crescendo, Best-of-N). |

Cada protocolo dice qué se mide, cómo se calcula y con qué órdenes se
reproduce. Lo que cambió durante la ejecución está al final, con fecha y motivo.

## Para consultar

| Documento | Qué cuenta |
|---|---|
| [criterios_estudio.md](criterios_estudio.md) | Por qué el estudio está diseñado así: escenarios, políticas, corpus, juez y métricas. Los protocolos citan sus secciones. |
| [desarrollo_escenarios.md](desarrollo_escenarios.md) | Los tres escenarios de ataque (LLM01, LLM05, LLM07) y el corpus de desarrollo. |
| [openrouter_native.md](openrouter_native.md) | C1: el filtro de inyección de OpenRouter y cómo activarlo. |
| [nemo.md](nemo.md) | C2: NeMo Guardrails y su política. |
| [salvaguarda_llama_guard.md](salvaguarda_llama_guard.md) | C3: Llama Guard 4. |
| [salvaguarda_guardrails_ai.md](salvaguarda_guardrails_ai.md) | La capa de salida de C5: Guardrails AI y el consumidor simulado. |
| [pilotos_integracion.md](pilotos_integracion.md) | Los pilotos de integración de cada filtro, antes de la evaluación. |
| [registro_ejecuciones.md](registro_ejecuciones.md) | Los pilotos ejecutados, con sus costes y huellas. |

Los corpus tienen su propio índice en
[../data/attacks/README.md](../data/attacks/README.md) y los resultados en
[../results/README.md](../results/README.md).
