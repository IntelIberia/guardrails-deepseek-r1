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
| `nivel1_cribado.jsonl` | Nivel 1: mensajes para probar solo los filtros de entrada | 5995 | Preparado el 20-11-2026; ejecutado el 21-11-2026 | Evaluación, nivel 1 |
| `nivel2.jsonl` | Nivel 2: pruebas completas con objetivos de aplicación y de contenido | 1075 | Preparado el 20-11-2026; ejecutado el 21 y 22-11-2026 | Evaluación, nivel 2 |
| `nivel2_b1.jsonl` … `nivel2_b8.jsonl` | Los ocho bloques del nivel 2 | 135 o 134 | Igual que `nivel2.jsonl` | Evaluación, nivel 2 |
| `nivel3.jsonl` | Nivel 3: inyección en documentos (BIPIA), H-CoT, FlipAttack, Policy Puppetry, CoT Hijacking y benignos | 320 | Preparado el 22-11-2026; ejecutado el 22 y 23-11-2026 | Evaluación, nivel 3 |
| `nivel3_b1.jsonl` … `nivel3_b4.jsonl` | Los cuatro bloques del nivel 3 | 80 cada uno | Igual que `nivel3.jsonl` | Evaluación, nivel 3 |

Los bloques contienen los mismos casos del corpus completo. Los 1075 casos del
nivel 2 también están en el nivel 1, con el mismo identificador y texto.
«Preparado» no significa «ejecutado»: consulta el
[registro de ejecuciones](../../docs/registro_ejecuciones.md) y los registros
originales para acreditar un ensayo.

Los `*_manifest.json` conservan procedencia, selección y huellas. Las fichas
[nivel2.md](nivel2.md) (corpus de los niveles 1 y 2),
[jailbreakhub_probe16.md](jailbreakhub_probe16.md) y
[source_assessment.md](source_assessment.md) explican las decisiones.
`licenses/` contiene las licencias de evaluación; los dos archivos `*LICENSE.txt`
de esta carpeta acompañan a las fuentes de los pilotos.

`external/` guarda copias fijadas de las fuentes del nivel 3: BIPIA, H-CoT,
las conductas de JBB-Behaviors que usan los ataques adaptativos, el juez de
JailbreakBench y los prompts originales del atacante de PAIR y PyRIT
(Crescendo). No se modifican: el código comprueba sus huellas.

`jailbreakhub_seleccion.json` conserva la plantilla del mensaje de sistema y
las exclusiones del piloto de 16 casos, separadas del código de preparación.
Los textos experimentales y los nombres de sus fuentes se conservan literalmente.
Los bytes de los corpus no se tocan: sus huellas identifican las ejecuciones.
Los manifiestos guardan las rutas con las que se generaron;
[`scripts/rutas_grabadas.py`](../../scripts/rutas_grabadas.py) las relaciona con
los nombres actuales.
