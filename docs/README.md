# Documentación

Empieza por el [README general](../README.md) si es tu primer contacto con el
proyecto. Después sigue las siete lecturas de la tabla; el glosario permite
consultar los términos sin conocimientos previos. Las guías de cada salvaguarda
y los protocolos contienen el detalle necesario para repetir el estudio.

## Orden de lectura

| # | Documento | Qué cuenta |
|---|---|---|
| 1 | [glosario.md](glosario.md) | Los términos del proyecto en lenguaje llano |
| 2 | [arquitectura.md](arquitectura.md) | Cómo recorre un caso el banco, qué hace cada parte del código y las normas para ejecutarlo |
| 3 | [desviaciones_anteproyecto.md](desviaciones_anteproyecto.md) | En qué se aparta el trabajo del anteproyecto aprobado y por qué |
| 4 | [criterios_estudio.md](criterios_estudio.md) | Decisiones de diseño del estudio: escenarios, políticas, corpus, juez, métricas |
| 5 | [desarrollo_escenarios.md](desarrollo_escenarios.md) | Los tres escenarios de ataque (LLM01, LLM05, LLM07) y el corpus común de desarrollo |
| 6 | [protocolos.md](protocolos.md) | Protocolos de los pilotos de integración de cada salvaguarda, fijados antes de ejecutarlos |
| 7 | [registro_ejecuciones.md](registro_ejecuciones.md) | Detalle de siete pilotos iniciales, sus costes y huellas; notas sobre ensayos posteriores |

## Cada salvaguarda

| Documento | Configuración |
|---|---|
| [openrouter_native.md](openrouter_native.md) | C1: filtro nativo de inyección de OpenRouter, y cómo activarlo |
| [nemo.md](nemo.md) | C2: NeMo Guardrails y su política |
| [salvaguarda_llama_guard.md](salvaguarda_llama_guard.md) | C3: Llama Guard 4, con la comprobación del piloto real |
| [salvaguarda_guardrails_ai.md](salvaguarda_guardrails_ai.md) | Capa de salida de C5: Guardrails AI y el consumidor de salida |

## Protocolos de evaluación

| Documento | Estado |
|---|---|
| [protocolo_evaluacion_v3.md](protocolo_evaluacion_v3.md) | Nivel 3, componente estático: ataques actuales de un mensaje e inyección en documentos (`eval_v3`), con su ejecución y la revisión de la pista B |
| [protocolo_v3_adaptativo.md](protocolo_v3_adaptativo.md) | Nivel 3, ataques adaptativos (PAIR, Crescendo, Best-of-N): diseño, control de gasto, ejecución y resultados |
| [protocolo_evaluacion_v2.md](protocolo_evaluacion_v2.md) | Niveles 1 y 2: cribado de entrada (`screen_v2`) y campaña comparativa C0–C5 (`eval_v2`) |
| [protocolo_evaluacion_v1.md](protocolo_evaluacion_v1.md) | Primera versión (19-11-2026, corpus `eval_v1`, 75 casos). Descartada antes de ejecutarse por tener pocos casos; se conserva como registro |

Los protocolos se fijan antes de ejecutar y no se reescriben después: cualquier
cambio se anota como desviación. Algunos remiten a secciones concretas de
`criterios_estudio.md`, por eso ese documento conserva su numeración.

## Dónde está el resto

Los corpus y sus fuentes tienen su propio índice en
[../data/attacks/README.md](../data/attacks/README.md). Para leer los resultados
consulta [../results/README.md](../results/README.md).
