# El banco de pruebas por dentro

Este código hace recorrer a cada mensaje la misma cadena: filtros de entrada,
DeepSeek, filtros de salida y valoración del juez. Guarda lo que ocurre en cada
paso. Un bloqueo detiene el recorrido; un error técnico se registra aparte.

| Carpeta o archivo | Responsabilidad |
|---|---|
| `core/` | Lee configuraciones, define los datos y ejecuta la cadena. |
| `targets/` | Conecta con el modelo que recibe el ataque. |
| `guards/` | Aplica NeMo, Llama Guard y la comprobación de formato de Guardrails AI. |
| `judges/` | Pide la valoración secundaria de las respuestas. |
| `adaptive.py` | Motor del nivel 3: un atacante propone mensajes, la cadena de salvaguardas los filtra y el atacante solo ve lo entregado. Incluye PAIR, Crescendo y Best-of-N. |
| `openrouter.py` | Envía peticiones, limita el ritmo, reintenta y registra coste y tiempo. |
| `bootstrap.py` | Conecta los nombres de la configuración con cada implementación. |

Para mantener o ampliar el código, consulta
[la arquitectura](../../docs/arquitectura.md). Para ejecutarlo utiliza
`scripts/run_config.py` (un mensaje por caso) o `scripts/run_adaptive.py`
(ataques adaptativos), desde la raíz del proyecto.
