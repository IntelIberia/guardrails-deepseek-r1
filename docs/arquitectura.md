# Arquitectura del banco y normas de ejecución

## Recorrido de un caso

Cada caso del corpus pasa por la misma cadena:

```text
salvaguardas de entrada → modelo objetivo → salvaguardas de salida → juez
```

La cadena se detiene en el primer bloqueo: las capas que quedan detrás y el
juez no se ejecutan y no se les atribuye acierto ni fallo. Un fallo técnico
(tiempo agotado, formato inválido, error HTTP) se registra como error de la
etapa, nunca como bloqueo.

Las salvaguardas no reciben el mensaje de sistema privado, la canaria, las
etiquetas ni el criterio de éxito. El juez sí recibe el criterio, porque
tiene que compararlo con la respuesta.

## Código

| Ruta | Qué hace |
|---|---|
| `src/bench/core/config.py` | Lee el YAML de una configuración y rechaza cualquier campo desconocido o mal tipado |
| `src/bench/core/schema.py` | Estructuras de datos comunes: caso, respuesta, decisión de una capa, veredicto, error |
| `src/bench/core/registry.py` | Registro de adaptadores por nombre |
| `src/bench/core/runner.py` | Motor genérico: recorre la cadena para cada caso y escribe el resultado |
| `src/bench/bootstrap.py` | Da de alta los adaptadores disponibles |
| `src/bench/openrouter.py` | Cliente HTTP de OpenRouter: limitador, reintentos, coste y retirada de la clave de los registros |
| `src/bench/targets/` | Modelo objetivo: `openrouter` (C0, C2, C3) y `openrouter_native_guarded` (C1, C4, C5) |
| `src/bench/guards/` | Salvaguardas: `nemo` (C2), `llama_guard` (C3) y `structured` (Guardrails AI, salida de C5) |
| `src/bench/judges/` | Juez LLM `openrouter_llm` |
| `scripts/run_config.py` | Ejecuta una configuración (`--dry-run` para validarla sin red) |
| `scripts/summarize_runs.py` | Resume todos los JSONL de `results/raw/` en `results/derived/runs_summary.json` |

Para añadir una salvaguarda nueva se implementa el contrato de
`src/bench/guards/base.py`, se registra su fábrica en `src/bench/bootstrap.py`
y se declara en un YAML. Las fábricas no hacen llamadas de red.

## Configuraciones

| Id. | Fichero | Salvaguardas |
|---|---|---|
| C0 | `configs/c0_baseline.yaml` | Ninguna |
| C1 | `configs/c1_native.yaml` | Filtro nativo de inyección de OpenRouter |
| C2 | `configs/c2_nemo.yaml` | NeMo Guardrails, entrada y salida |
| C3 | `configs/c3_llama_guard.yaml` | Llama Guard 4, entrada y salida |
| C4 | `configs/c4_combined.yaml` | C1 + C2 + C3 |
| C5 | `configs/c5_combined.yaml` | C4 + Guardrails AI en la salida |

`configs/integracion_guardrails_ai.yaml` (`config_id: GAI-integracion`) es un
perfil auxiliar para probar Guardrails AI por separado; no es una de las seis.
`configs/c0_jailbreakhub_probe.yaml` es el C0 del piloto de JailbreakHub.

## Normas de ejecución

- **Sin gasto por accidente.** Las pruebas automáticas no usan la red:
  `tests/conftest.py` bloquea sockets y DNS. Para validar una configuración se
  usa `--dry-run`.
- **Árbol Git limpio.** Una ejecución real se niega a empezar si hay cambios
  sin confirmar, porque guarda el commit y la huella de cada fichero de código.
  Para corpus de menos de 20 casos hace falta `--allow-partial`.
- **Dos claves.** C1, C4 y C5 usan `OPENROUTER_NATIVE_API_KEY`, una segunda
  clave con la política nativa asignada solo a ella, y la ficha de
  verificación descrita en [openrouter_native.md](openrouter_native.md). El
  juez y los moderadores usan siempre la clave base, sin política.
- **Las claves no salen de `.env`.** Ese fichero está excluido de Git y el
  cliente retira la clave de cualquier texto que se registre.
- **Origen de las cifras.** Toda cifra de la memoria sale de un JSONL de
  `results/raw/`, de `results/derived/` o del código. Las conclusiones, la
  discusión y las etiquetas humanas del juez son del autor.
- **Reanudación.** Repetir la orden con el mismo `--run-id` continúa la
  ejecución: omite los casos terminados. Si cambian el corpus, el YAML o el
  código, la huella de la configuración cambia y la reanudación se rechaza.

## Huella de la configuración

La cabecera de cada JSONL guarda `config_fingerprint`, un SHA-256 de la
configuración efectiva. Entran en ella, entre otras cosas, los bytes del YAML
(incluidos sus comentarios), la ruta y el contenido del corpus y la huella de
todos los `.py` de `src/` y `scripts/`, `pyproject.toml` y `uv.lock`
(`scripts/run_config.py`, funciones `_code_fingerprint` y `run_campaign`). Por eso los
corpus ya ejecutados y los YAML no se renombran ni se editan.

## Entorno en macOS

Si el repositorio está en una carpeta sincronizada con iCloud, conviene
excluir `.venv` de la sincronización
(`xattr -w 'com.apple.fileprovider.ignore#P' 1 .venv`); si no, iCloud puede
vaciar ficheros del entorno y las pruebas parecen colgarse.
