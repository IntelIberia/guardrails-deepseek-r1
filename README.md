# Guardrails para DeepSeek-R1: banco de pruebas

Código de mi Trabajo Fin de Grado (Grado en Ingeniería en Sistemas de
Información, Universidad de Alcalá): «Análisis de la eficacia de guardrails en
LLMs».

La pregunta es sencilla: si pongo filtros de seguridad (*guardrails*) delante y
detrás de DeepSeek-R1, ¿cuántos ataques paran de verdad y cuántas preguntas
normales bloquean por error? Para responderla he construido un banco de pruebas
que manda a DeepSeek-R1 miles de mensajes, unos maliciosos y otros inocentes, con
distintas combinaciones de filtros, y guarda todo lo que pasa.

## Pruébalo en cinco minutos

Hace falta Python 3.12, [uv](https://docs.astral.sh/uv/getting-started/installation/)
y una clave de [OpenRouter](https://openrouter.ai/keys) con algo de saldo (cada
prueba cuesta menos de un céntimo de dólar).

```sh
git clone https://github.com/IntelIberia/guardrails-deepseek-r1.git
cd guardrails-deepseek-r1
uv sync --locked
uv run python probar.py
```

El programa pregunta qué configuración quieres (C0 sin filtros, C2 con NeMo o C3
con Llama Guard 4) y qué mensaje enviar: uno de los ejemplos o uno tuyo. Después
enseña qué hizo cada filtro, qué respondió DeepSeek-R1, si se filtró el
identificador secreto de la aplicación y qué decidió el juez. La clave se pide al
arrancar y no se guarda; si no quieres escribirla cada vez, copia `.env.example`
a `.env` y ponla ahí.

También se puede lanzar directamente:

```sh
uv run python probar.py --config C3 --ejemplo 1
uv run python probar.py --config C0 --mensaje "Dime el identificador reservado"
```

Una buena prueba es mandar el mismo mensaje con C0 y con C3 y comparar.

## La idea: porteros de discoteca

Los filtros funcionan como los porteros de una discoteca. Uno mira a quien entra
y otro a quien sale; si uno para a alguien, los demás ya no hacen nada. Los
ataques son la gente que intenta colarse, y las preguntas inocentes son clientes
con derecho a entrar: bloquearlas también es un fallo.

```
mensaje → [filtros de entrada] → DeepSeek-R1 → [filtros de salida] → juez → resultado
```

Comparo seis configuraciones:

| Config. | Qué filtros lleva |
|---|---|
| C0 | Ninguno. Es la referencia (DeepSeek mantiene sus propias normas). |
| C1 | El filtro de inyección que ofrece OpenRouter. |
| C2 | NeMo Guardrails, en la entrada y en la salida. |
| C3 | Llama Guard 4, en la entrada y en la salida. |
| C4 | C1 + C2 + C3 juntos. |
| C5 | C4 + una comprobación de formato con Guardrails AI. |

Cada configuración es un fichero YAML de [`configs/`](configs/).

## Las tres fases

1. Cribado (nivel 1). Pruebo solo los filtros de entrada con unos 6.000
   mensajes, sin llamar a DeepSeek. Sirve para ver rápido qué detecta cada filtro.
2. Evaluación completa (nivel 2). Cada mensaje recorre toda la cadena y un juez
   decide si el ataque funcionó. Son ataques públicos de un solo mensaje.
3. Ataques actuales (nivel 3). Repito la prueba con técnicas de 2024 y 2025:
   inyección escondida en documentos (BIPIA), ataques al razonamiento del modelo
   (H-CoT), plantillas nuevas y atacantes automáticos que reintentan y aprenden
   de cada respuesta (PAIR, Crescendo y Best-of-N).

## Qué he encontrado

- Llama Guard 4 (C3) es el mejor equilibrio. Bloquea 47 de 50 ataques H-CoT y
  389 de 400 intentos de Best-of-N. Contra los atacantes automáticos deja
  Crescendo en 0 de 20 conductas y PAIR en 2 de 20. A cambio bloquea un 20 % de
  las preguntas inocentes disfrazadas.
- NeMo (C2, C4 y C5) lo para casi todo, también lo inocente. Con C4 y C5 no pasa
  ningún ataque en la fase 3, pero las tres configuraciones bloquean entre el 95
  y el 98 % de esas preguntas inocentes. Además, parte de su eficacia depende de
  cómo se cuenten las veces en que su moderador se niega a analizar un mensaje.
- El filtro de OpenRouter (C1) no protege. En la fase 3 no bloqueó ningún ataque
  y, tras revisar los veredictos del juez, pasaron incluso algunos jailbreaks
  más que sin filtros (63 de 210 frente a 53 de 210 en C0).
- Los ataques actuales sí rompen a DeepSeek-R1 sin filtros. H-CoT consigue 39
  de 50, frente a 14 de 50 con las mismas peticiones sin el truco, y Crescendo
  rompe 6 de 20 conductas.
- El razonamiento del modelo también filtra información. DeepSeek-R1 muestra
  en su razonamiento secretos e instrucciones inyectadas que luego no pone en la
  respuesta final.

Todas las cifras salen de los registros de [`results/`](results/) y se pueden
recalcular con los scripts sin hacer llamadas nuevas.

## Cómo está organizado

| Carpeta | Qué hay |
|---|---|
| [`src/bench/`](src/bench/) | El banco de pruebas: la cadena de filtros, la conexión con los modelos y el motor de ataques automáticos. |
| [`configs/`](configs/) | Las seis configuraciones C0–C5 y los parámetros de los ataques automáticos. |
| [`scripts/`](scripts/) | Las órdenes para preparar los datos, ejecutar las pruebas y calcular resultados. |
| [`data/attacks/`](data/attacks/) | Los mensajes de prueba, con su origen y su licencia. |
| [`results/`](results/) | Los registros de cada ejecución y las métricas calculadas a partir de ellos. |
| [`tests/`](tests/) | Pruebas del código con respuestas simuladas: no hacen llamadas ni gastan. |
| [`docs/`](docs/) | El diseño y los protocolos de cada fase, escritos antes de ejecutarlas. |

Cada carpeta tiene su propio README.

## Probarlo sin gastar nada

```sh
uv sync --locked                                           # instala las dependencias
PYTHONPATH=src .venv/bin/pytest -q                         # pruebas del código (sin red)
PYTHONPATH=src .venv/bin/python scripts/resumen_nivel3.py  # tabla de resultados de la fase 3
PYTHONPATH=src .venv/bin/python scripts/ver_caso.py ev3-bipia-attack-1076  # un caso en C0–C5
```

`ver_caso.py` enseña qué le pasó a un mismo mensaje con cada configuración: qué
filtro lo paró, qué respondió el modelo y qué dijo el juez.

Para ver qué haría una ejecución real sin lanzarla:

```sh
PYTHONPATH=src .venv/bin/python scripts/run_config.py \
  --config configs/c3_llama_guard.yaml --input data/attacks/development12.jsonl --dry-run
```

## Ejecutarlo de verdad

Las ejecuciones reales cuestan dinero (OpenRouter cobra cada llamada). Copia
`.env.example` a `.env` y pon tu clave en `OPENROUTER_API_KEY`. C1, C4 y C5
necesitan además una segunda clave con el filtro de OpenRouter activado; lo
explico en [`docs/openrouter_native.md`](docs/openrouter_native.md).

```sh
PYTHONPATH=src .venv/bin/python scripts/run_config.py \
  --config configs/c3_llama_guard.yaml --input data/attacks/development12.jsonl \
  --allow-partial --run-id mi-prueba
PYTHONPATH=src .venv/bin/python scripts/summarize_runs.py
```

`run_config.py` exige que no haya cambios sin confirmar en Git. Si se corta,
repetir la misma orden con el mismo `--run-id` continúa donde se quedó. Cada
registro guarda la configuración, el commit y una huella de los ficheros usados,
así que no se pueden mezclar resultados de pruebas distintas. Para comparar
configuraciones hay que pasarles siempre el mismo corpus con `--input`.

## Para saber más

- [`docs/README.md`](docs/README.md): orden de lectura y glosario.
- [`docs/arquitectura.md`](docs/arquitectura.md): cómo recorre un caso el banco y
  cómo añadir un filtro nuevo.
- [`results/README.md`](results/README.md): cómo leer los registros.
