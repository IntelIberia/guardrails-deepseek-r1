# data: los mensajes de prueba

| Carpeta | Para qué sirve |
|---|---|
| [`attacks/`](attacks/README.md) | Los corpus de desarrollo y de evaluación (niveles 1, 2 y 3), sus manifiestos, fichas y licencias. Incluye preguntas inocentes para ver si las protecciones bloquean de más. |
| `attacks/external/` | Copias fijadas de fuentes públicas que el código lee y verifica por huella. |
| `attacks/licenses/` | Licencias y notas de atribución de cada fuente. |

Los ficheros de evaluación se nombran por nivel (`nivel1_*`, `nivel2_*`,
`nivel3_*`), igual que los protocolos de `docs/`, los preparadores de
`scripts/`, las pruebas de `tests/` y las métricas de `results/derived/`. Los
bytes de los corpus ejecutados no se tocan: sus huellas identifican las
ejecuciones.
