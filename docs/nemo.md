# C2: NeMo Guardrails

El adaptador `nemo` ejecuta NeMo Guardrails 0.24.1 de verdad: flujos Colang
1.0 y acciones registradas. NeMo es programable, así que lo que se evalúa es
la política propia `tfg_nemo_input_output_v1`, no todas las políticas posibles
del framework.

## Política

**Entrada.** Una acción del flujo aplica cuatro heurísticas, en español e
inglés, para intentos explícitos de anular instrucciones o extraer el mensaje
de sistema. Si alguna coincide, NeMo bloquea sin llamar al moderador. Si no,
consulta a `openai/gpt-4.1-nano` en Azure a través del cliente OpenRouter del
banco.

**Salida.** Sin heurísticas. El moderador revisa la respuesta final y el
razonamiento por separado, con la petición del usuario como contexto; se
evalúan los dos canales aunque el primero se bloquee y sus costes se suman. Un
canal ausente no se juzga.

El moderador es distinto del objetivo, del juez y de Llama Guard 4. Usa
temperatura 0, semilla, proveedor fijo sin alternativas y JSON estricto con
`blocked` y `reason`. En la entrada busca manipulación de instrucciones y
peticiones de ayuda dañina; en la salida, ayuda dañina y divulgación aparente
de información interna o privada. No conoce la canaria, de modo que no puede
reconocer cualquier identificador filtrado. Las heurísticas pueden bloquear
citas benignas; eso se medirá como falsos positivos.

## Flujos

Las constantes `NEMO_CONFIG`, `COLANG_FLOWS`, `INPUT_POLICY`, `OUTPUT_POLICY`
y `HEURISTICS` de [nemo.py](../src/bench/guards/nemo.py) definen el perfil. Se
copian en `policy_sources` de cada decisión con su huella `policy_sha256`.

```text
define subflow tfg input policy
  $allowed = execute tfg_check_input
  if not $allowed
    bot refuse to respond
    stop

define subflow tfg output policy
  $allowed = execute tfg_check_output
  if not $allowed
    bot refuse to respond
    stop
```

La configuración declara `models: []`, los dos flujos como raíles y trazas y
métricas desactivadas; no hay modelo principal, diálogos, ejemplos semánticos
ni recuperación. `LLMRails.check_async(..., rail_types=[INPUT/OUTPUT])`
ejecuta solo el raíl pedido, y el banco sigue controlando las llamadas al
objetivo y al juez. Se crea un motor nuevo por canal para no compartir estado
entre casos concurrentes.

```yaml
adapter: nemo
name: NeMo
stages: [input, output]
options:
  model: openai/gpt-4.1-nano
  provider: azure
  policy: tfg_nemo_input_output_v1
```

Validar las opciones no importa NeMo ni abre conexiones. El adaptador fija
`NEMO_GUARDRAILS_NO_USAGE_STATS=1` y el modo offline de Hugging Face, no
escribe preferencias del usuario ni descarga modelos. La única inferencia es
la petición al moderador. Verificado con Python 3.12 en macOS Intel y
`onnxruntime==1.23.2`.

## Bloqueos, errores y costes

NeMo puede devolver `BLOCKED` tras un error interno. Por eso el adaptador
comprueba que la acción se ejecutó una sola vez, que dio una clasificación
válida y que el estado y el raíl coinciden con ella. Si no, o si el moderador
responde en un formato inválido, se niega o se trunca, se devuelve un
`StageError` y no una decisión inventada. Si falla el segundo canal se
conservan las llamadas y el gasto del primero.

El coste viene de `usage.cost`; si falta en alguna llamada, el total es
`null`. Un bloqueo por heurística cuesta 0 USD y no hace intentos remotos.
`calls` distingue `heuristic` y `moderator`; `framework_checks` guarda canal,
estado, raíl e invocaciones. `latency_ms` suma petición y cómputo local (sin
esperas del limitador ni reintentos) y `wall_latency_ms` la duración completa;
no deben mezclarse.

## Verificación

`tests/test_nemo.py` ejecuta el framework instalado con la red bloqueada y
solo simula las respuestas HTTP del moderador: permiso y bloqueo en entrada y
salida, ausencia de datos del oráculo, dos canales, costes parciales y
desconocidos, errores, ausencia de credenciales en los registros y aislamiento
concurrente.

```sh
PYTHONPATH=src uv run --locked pytest -q tests/test_nemo.py
```

La ejecución real es `h5-c2-nemo-20261118` ([registro](registro_ejecuciones.md)).

Fuentes:
[NeMo Guardrails 0.24.1 en PyPI](https://pypi.org/project/nemoguardrails/0.24.1/),
[comprobación de mensajes sin generación](https://docs.nvidia.com/nemo/guardrails/v0.24.1/run-guardrailed-inference/using-python-apis/check-messages),
[acciones en Colang](https://docs.nvidia.com/nemo/guardrails/v0.24.1/configure-guardrails/actions/creating-actions),
[LLMRails 0.24.1](https://github.com/NVIDIA-NeMo/Guardrails/blob/v0.24.1/nemoguardrails/rails/llm/llmrails.py),
[proveedores de GPT-4.1-nano](https://openrouter.ai/api/v1/models/openai/gpt-4.1-nano/endpoints).
