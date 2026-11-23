# Colecciones de mensajes de prueba

Un *corpus* es una colección de mensajes. Los de desarrollo sirven para poner a
punto el programa; los de evaluación se reservan para medirlo después. Los
recuentos siguientes son líneas de casos, sin sumar dos veces los bloques.

| Archivo | Qué es | Casos | Cuándo se usó o se preparó | Uso |
|---|---|---:|---|---|
| `pilot_llm07.json` | Primer intento de extraer un código ficticio oculto | 1 | Ejecutado el 17 y el 18-11-2026 en C0 | Desarrollo |
| `c0_20.jsonl` | 12 ataques propios de extracción y 8 preguntas inocentes de XSTest | 20 | Ejecutado el 17-11-2026 en C0 | Desarrollo |
| `jailbreakhub_probe16.jsonl` | 4 prefijos públicos, 4 sondas emparejadas sin prefijo y 8 controles | 16 | Ejecutado el 18-11-2026 en C0 | Desarrollo |
| `h4_smoke3.jsonl` | Extracción, pregunta inocente y control de violencia | 3 | C2 y C3 el 18-11; pilotos C1, C4 y C5 documentados el 19-11-2026 | Desarrollo / integración |
| `h5_c4_smoke2.jsonl` | Respuesta de formato válido y respuesta incompatible | 2 | Piloto de Guardrails AI documentado el 19-11-2026 | Desarrollo / integración |
| `development12.jsonl` | 9 ataques en tres escenarios y 3 controles inocentes | 12 | Preparado para el desarrollo común de C0–C5, noviembre de 2026; no es una campaña reservada | Desarrollo |
| `eval_v1.jsonl` | Primera propuesta de evaluación: ataques y controles separados del desarrollo | 75 | Preparado el 19-11-2026; descartado antes de ejecutarse por tamaño insuficiente | Evaluación descartada; registro histórico |
| `eval_v1_b1.jsonl` | Primer bloque de `eval_v1` | 27 | Parte de la propuesta del 19-11-2026 | Evaluación descartada |
| `eval_v1_b2.jsonl` | Segundo bloque de `eval_v1` | 24 | Parte de la propuesta del 19-11-2026 | Evaluación descartada |
| `eval_v1_b3.jsonl` | Tercer bloque de `eval_v1` | 24 | Parte de la propuesta del 19-11-2026 | Evaluación descartada |
| `screen_v2.jsonl` | Mensajes para probar solo los filtros de entrada | 5995 | Preparado el 20-11-2026; ejecución según protocolo v2 | Evaluación, nivel 1 |
| `eval_v2.jsonl` | Pruebas completas con objetivos de aplicación y de contenido | 1075 | Preparado el 20-11-2026; campaña según protocolo v2 | Evaluación, nivel 2 |
| `eval_v2_b1.jsonl` | Bloque 1 de `eval_v2` | 135 | Parte de la campaña v2 | Evaluación |
| `eval_v2_b2.jsonl` | Bloque 2 de `eval_v2` | 135 | Parte de la campaña v2 | Evaluación |
| `eval_v2_b3.jsonl` | Bloque 3 de `eval_v2` | 135 | Parte de la campaña v2 | Evaluación |
| `eval_v2_b4.jsonl` | Bloque 4 de `eval_v2` | 134 | Parte de la campaña v2 | Evaluación |
| `eval_v2_b5.jsonl` | Bloque 5 de `eval_v2` | 134 | Parte de la campaña v2 | Evaluación |
| `eval_v2_b6.jsonl` | Bloque 6 de `eval_v2` | 134 | Parte de la campaña v2 | Evaluación |
| `eval_v2_b7.jsonl` | Bloque 7 de `eval_v2` | 134 | Parte de la campaña v2 | Evaluación |
| `eval_v2_b8.jsonl` | Bloque 8 de `eval_v2` | 134 | Parte de la campaña v2 | Evaluación |

Los bloques contienen los mismos casos del corpus completo. Los 1075 casos de
`eval_v2` también están en `screen_v2`, con el mismo identificador y texto.
«Preparado» no significa «ejecutado»: consulta el
[registro de ejecuciones](../../docs/registro_ejecuciones.md) y los registros
originales para acreditar un ensayo.

Los `*_manifest.json` conservan procedencia, selección y huellas. Las fichas
[eval_v1.md](eval_v1.md), [eval_v2.md](eval_v2.md),
[jailbreakhub_probe16.md](jailbreakhub_probe16.md) y
[source_assessment.md](source_assessment.md) explican las decisiones.
`licenses/` contiene las licencias de evaluación; los dos archivos `*LICENSE.txt`
de esta carpeta acompañan a las fuentes de los pilotos.

`jailbreakhub_seleccion.json` conserva la plantilla del mensaje de sistema y
las exclusiones del piloto de 16 casos, separadas del código de preparación.
Los textos experimentales y los nombres de sus fuentes se conservan literalmente.
No regeneres ni renombres corpus usados para reanudar una ejecución.
