# C1, C4 y C5: filtro nativo de inyección de OpenRouter

El detector de OpenRouter es una política remota: escribirlo en el YAML no lo
activa. El adaptador `openrouter_native_guarded` hace la petición real al
objetivo con una clave que tiene la política asignada, sin imitar el filtro
localmente. Solo un HTTP 403 con el mensaje específico de inyección se
convierte en bloqueo de entrada; cualquier otro 403 es un error. Se guardan el
mensaje, `metadata.patterns` y la respuesta completa (con
`openrouter_metadata` si existe). Un coste no informado queda como
desconocido.

El filtro actúa en el salto al objetivo. En C4 y C5 los raíles locales de entrada
van antes, así que si uno de ellos bloquea no se afirma que el filtro remoto
llegara a ejecutarse. El núcleo solo ve una excepción genérica de bloqueo. Si
una respuesta no trae metadatos de la política, no se inventa una decisión.

## Cómo activarlo

1. `OPENROUTER_API_KEY` (C0, juez y moderadores) se queda sin la política.
2. Crea otra clave de inferencia para `OPENROUTER_NATIVE_API_KEY`, usada solo
   por el objetivo de C1, C4 y C5. Una clave de administración no sirve.
3. En OpenRouter, crea una política de *Content moderation* con
   `regex-prompt-injection`, acción `block` y ámbito `user_only`, para que
   inspeccione al atacante y no las instrucciones del sistema.
4. Asígnala solo a la segunda clave y revisa las políticas heredadas de
   miembro, espacio y cuenta. Asignarla al espacio o al miembro afectaría al
   juez y contaminaría el experimento.
5. Con el ID de la política y el árbol limpio:

```sh
PYTHONPATH=src uv run --locked python -m scripts.verify_native_policy \
  --policy-id ID_REAL --confirm-key-only-scope
```

El script no cambia la cuenta. Envía, con cada clave, una petición benigna y
una frase de inyección inocua, y exige que la clave base deje pasar ambas y
que la nativa bloquee solo la inyección. Guarda las cuatro respuestas en un
registro nuevo y, solo si todo concuerda, escribe una ficha en
`results/local/` con el hash de cada clave (nunca su valor). Sin esa ficha, C1,
C4 y C5 se detienen antes de la primera inferencia.

La asignación y el ámbito siguen siendo una declaración del operador: los
controles no equivalen a leer toda la configuración de la cuenta ni impiden
cambios posteriores. Repite la verificación si cambias políticas. La cabecera
del JSONL conserva esta distinción.

## Estado

El 18-11-2026 la única clave permitía inferencia y no era de administración
(la consulta de guardrails devolvió 401), y el espacio por defecto no tenía
políticas. El 19-11-2026 se creó la segunda clave con la política, la
verificación de los cuatro controles se superó
(`results/raw/c1-verificacion-nativa-20261119.json`) y se ejecutaron los
pilotos de C1, C4 y C5 (ver [registro_ejecuciones.md](registro_ejecuciones.md)
y `results/derived/runs_summary.json`).

Fuentes:
[políticas y herencia](https://openrouter.ai/docs/guides/features/guardrails/policies),
[detector y ámbitos](https://openrouter.ai/docs/guides/features/guardrails/prompt-injection),
[respuesta de bloqueo](https://openrouter.ai/docs/guides/features/guardrails).
