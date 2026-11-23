# configs: las configuraciones del experimento

Cada fichero YAML describe una configuración: qué modelo se ataca, qué juez
valora las respuestas, qué salvaguardas («porteros») se ponen delante y
detrás del modelo, en qué orden, y qué corpus se usa por defecto.

Mira primero `c0_baseline.yaml` (sin salvaguardas) y después
`c5_combined.yaml` (todas).

| Fichero | Id. | Salvaguardas | Corpus por defecto |
|---|---|---|---|
| `c0_baseline.yaml` | C0 | Ninguna (línea base) | `c0_20.jsonl` |
| `c1_native.yaml` | C1 | Filtro nativo de inyección de OpenRouter | `development12.jsonl` |
| `c2_nemo.yaml` | C2 | NeMo Guardrails, entrada y salida | `development12.jsonl` |
| `c3_llama_guard.yaml` | C3 | Llama Guard 4, entrada y salida | `c0_20.jsonl` |
| `c4_combined.yaml` | C4 | C1 + C2 + C3 | `development12.jsonl` |
| `c5_combined.yaml` | C5 | C4 + Guardrails AI en la salida | `development12.jsonl` |
| `adaptativo.yaml` | Nivel 3 | Parámetros de los ataques adaptativos (atacante, PAIR, Crescendo, Best-of-N); se combina con C0, C3 o C4 | Selección de JBB-Behaviors |
| `integracion_guardrails_ai.yaml` | GAI-integracion | Solo Guardrails AI; perfil auxiliar, no es una de las seis | `h5_c4_smoke2.jsonl` |
| `c0_jailbreakhub_probe.yaml` | C0 | Ninguna; versión de C0 para el piloto de JailbreakHub | `jailbreakhub_probe16.jsonl` |

Para comparar configuraciones hay que pasarles el mismo corpus con `--input`;
el corpus por defecto no es el mismo en todas.

**No se editan.** La huella de configuración que guarda cada ejecución
incluye los bytes del YAML, comentarios incluidos, así que cambiar una coma
impide reconocer y reanudar las ejecuciones existentes. Los nombres de los
ficheros se mantienen por el mismo motivo. Detalle en
[../docs/arquitectura.md](../docs/arquitectura.md).
