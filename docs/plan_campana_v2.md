# Plan de campaña v2

Preparado el 20 de noviembre de 2026. Estos comandos quedan escritos para el
autor; no se ha lanzado ninguna ejecución experimental durante la auditoría.
Se ejecutan desde la raíz del proyecto, de uno en uno y en el orden indicado.

## 1. Revisión antes de empezar

El autor debe leer las traducciones de XSTest y las plantillas largas,
confirmar las atribuciones y completar las citas pendientes. Debe guardar los
cambios en una revisión Git limpia antes de la primera llamada real: ambos
runners lo exigen y guardan la identidad del código. Este cierre no hace commits.
La revisión debe incluir también `eval_v2_source_files.json`, los manifiestos,
el protocolo, las métricas y este plan. No se cambia código entre tandas.

Consultar en la cuenta el saldo real, el gasto acumulado y el remanente de la
clave nativa, sin copiar credenciales a la memoria. Los 19,80 USD son saldo
aproximado; los 5 USD son un límite de clave que puede tener consumo anterior.
Los pilotos C1/C4/C5 tienen 0,00338455 USD conocidos en el objetivo; la prueba de
activación añade 0,00006210 USD conocidos con la clave nativa. El 403 de esa
prueba y cuatro etapas de defensa de los pilotos no informan coste: se deben
conciliar con el proveedor. No se interpretan como cero por falta del campo.
La estimación presupone 5 USD disponibles: si el remanente es menor, ajustar
`NATIVE_KEY_CAP_USD` y volver a congelar antes de empezar. El saldo global ya
incluye el gasto previo; no se le resta otra vez.

Comprobar sin red:

```sh
PYTHONPATH=src .venv/bin/pytest -q
PYTHONPATH=src .venv/bin/mypy src scripts tests
PYTHONPATH=src .venv/bin/python scripts/metrics_eval.py --estimate-budget
PYTHONPATH=src .venv/bin/python scripts/metrics_eval.py --print-plan
```

Huellas del corpus completo:

- Nivel 2: `fcef43319af88d7a9cf66d2118b1ee5f3d58d5c3d7b9cdf4c32ac7225136cfec`.
- Nivel 1 corregido: `5d33bbc356cbda3f93bd34e60643578a3b557e7802fde1bf0a1473b7d32477ea`.

Las credenciales y la ficha nativa deben estar configuradas según los YAML y
`docs/openrouter_native.md`. Los runners reales cargan sus credenciales; los
dry-run no leen `.env`. No se cambian concurrencia, tasa ni reintentos.

## 2. Regla de parada y reanudación

Antes de cada comando real se ejecuta `--budget-check` con la reserva indicada.
El código 3 detiene el plan: gasto conocido más reserva ≥17,82 USD, nativo
≥4,50 USD o algún coste de campaña desconocido. No se continúa con el siguiente
comando después de ese código. Las reservas llevan margen 1,5 y se redondean
hacia arriba a 0,001 USD. Al empezar un bloque se comprueba también la reserva
del bloque entero. No son un límite garantizado de facturación: los runners
solo comprueban entre ejecuciones y el objetivo no tiene tope de salida.
Consultar el saldo real tras cada tanda y parar si deja de corresponder al
modelo. Los errores y las reanudaciones también cuestan.

Si falla una tanda, esperar 60 s y repetir exactamente su comando y su run_id,
con otro control de presupuesto antes. Como máximo se hacen dos reanudaciones
además del intento inicial. Para una reanudación, usar la reserva de la tanda
completa es conservador. Si aún quedan errores, registrar sus IDs y seguir
solo si el control de gasto lo permite. No crear otro run_id para arreglar un
error: se perdería el emparejamiento. Una parada presupuestaria termina la
campaña; un bloque a medias no entra en el análisis principal. No se decide el
tamaño mirando los éxitos ni los valores p.

## 3. Opción prevista con los límites actuales

Nivel 1: NeMo y Llama Guard sobre los 5995 prompts, por cuatro partes. Nivel 2:
bloques 1–2, 270 casos con las seis configuraciones, más dos réplicas adicionales
de C0 en el bloque 1. Presupuesto con margen: **11,287392 USD**, de ellos
**3,122901 nativos**, y **14,463 h**. Las reanudaciones y las pausas no están
sumadas como ejecuciones completas. No se ejecuta el cribado nativo en esta
opción. Tampoco hace falta su prueba de cinco prompts.

### Nivel 1: cuatro partes, dos filtros independientes

Parte 1, 1499 prompts, run_id `sc2-p1-nemo-llama`:

```sh
PYTHONPATH=src .venv/bin/python scripts/metrics_eval.py --budget-check --reserve-usd 0.257 --reserve-native-usd 0
PYTHONPATH=src .venv/bin/python scripts/run_input_screening.py --input data/attacks/screen_v2.jsonl --part 1 --filters nemo_input,llama_guard_input --run-id sc2-p1-nemo-llama
```

Parte 2, 1499 prompts, run_id `sc2-p2-nemo-llama`:

```sh
PYTHONPATH=src .venv/bin/python scripts/metrics_eval.py --budget-check --reserve-usd 0.263 --reserve-native-usd 0
PYTHONPATH=src .venv/bin/python scripts/run_input_screening.py --input data/attacks/screen_v2.jsonl --part 2 --filters nemo_input,llama_guard_input --run-id sc2-p2-nemo-llama
```

Parte 3, 1499 prompts, run_id `sc2-p3-nemo-llama`:

```sh
PYTHONPATH=src .venv/bin/python scripts/metrics_eval.py --budget-check --reserve-usd 0.268 --reserve-native-usd 0
PYTHONPATH=src .venv/bin/python scripts/run_input_screening.py --input data/attacks/screen_v2.jsonl --part 3 --filters nemo_input,llama_guard_input --run-id sc2-p3-nemo-llama
```

Parte 4, 1498 prompts, run_id `sc2-p4-nemo-llama`:

```sh
PYTHONPATH=src .venv/bin/python scripts/metrics_eval.py --budget-check --reserve-usd 0.262 --reserve-native-usd 0
PYTHONPATH=src .venv/bin/python scripts/run_input_screening.py --input data/attacks/screen_v2.jsonl --part 4 --filters nemo_input,llama_guard_input --run-id sc2-p4-nemo-llama
```

### Nivel 2: bloques en orden Williams

No pasar al bloque 2 hasta haber registrado todos los casos previstos en el 1,
con sus seis configuraciones y sus réplicas; los errores persistentes tras las
reanudaciones quedan anotados y excluidos según el protocolo.

Reserva del bloque 1 completo:

```sh
PYTHONPATH=src .venv/bin/python scripts/metrics_eval.py --budget-check --reserve-usd 5.792 --reserve-native-usd 1.562
```

`ev2-b1-c0-r1`:

```sh
PYTHONPATH=src .venv/bin/python scripts/metrics_eval.py --budget-check --reserve-usd 0.670 --reserve-native-usd 0.000
PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c0_baseline.yaml --input data/attacks/eval_v2_b1.jsonl --allow-partial --run-id ev2-b1-c0-r1
```

`ev2-b1-c1-r1`:

```sh
PYTHONPATH=src .venv/bin/python scripts/metrics_eval.py --budget-check --reserve-usd 0.670 --reserve-native-usd 0.521
PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c1_native.yaml --input data/attacks/eval_v2_b1.jsonl --allow-partial --run-id ev2-b1-c1-r1
```

`ev2-b1-c5-r1`:

```sh
PYTHONPATH=src .venv/bin/python scripts/metrics_eval.py --budget-check --reserve-usd 0.815 --reserve-native-usd 0.521
PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c5_combined.yaml --input data/attacks/eval_v2_b1.jsonl --allow-partial --run-id ev2-b1-c5-r1
```

`ev2-b1-c0-r2`:

```sh
PYTHONPATH=src .venv/bin/python scripts/metrics_eval.py --budget-check --reserve-usd 0.670 --reserve-native-usd 0.000
PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c0_baseline.yaml --input data/attacks/eval_v2_b1.jsonl --allow-partial --run-id ev2-b1-c0-r2
```

`ev2-b1-c2-r1`:

```sh
PYTHONPATH=src .venv/bin/python scripts/metrics_eval.py --budget-check --reserve-usd 0.718 --reserve-native-usd 0.000
PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c2_nemo.yaml --input data/attacks/eval_v2_b1.jsonl --allow-partial --run-id ev2-b1-c2-r1
```

`ev2-b1-c4-r1`:

```sh
PYTHONPATH=src .venv/bin/python scripts/metrics_eval.py --budget-check --reserve-usd 0.815 --reserve-native-usd 0.521
PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c4_combined.yaml --input data/attacks/eval_v2_b1.jsonl --allow-partial --run-id ev2-b1-c4-r1
```

`ev2-b1-c3-r1`:

```sh
PYTHONPATH=src .venv/bin/python scripts/metrics_eval.py --budget-check --reserve-usd 0.767 --reserve-native-usd 0.000
PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c3_llama_guard.yaml --input data/attacks/eval_v2_b1.jsonl --allow-partial --run-id ev2-b1-c3-r1
```

`ev2-b1-c0-r3`:

```sh
PYTHONPATH=src .venv/bin/python scripts/metrics_eval.py --budget-check --reserve-usd 0.670 --reserve-native-usd 0.000
PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c0_baseline.yaml --input data/attacks/eval_v2_b1.jsonl --allow-partial --run-id ev2-b1-c0-r3
```

Reserva del bloque 2 completo:

```sh
PYTHONPATH=src .venv/bin/python scripts/metrics_eval.py --budget-check --reserve-usd 4.449 --reserve-native-usd 1.562
```

`ev2-b2-c1-r1`:

```sh
PYTHONPATH=src .venv/bin/python scripts/metrics_eval.py --budget-check --reserve-usd 0.670 --reserve-native-usd 0.521
PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c1_native.yaml --input data/attacks/eval_v2_b2.jsonl --allow-partial --run-id ev2-b2-c1-r1
```

`ev2-b2-c2-r1`:

```sh
PYTHONPATH=src .venv/bin/python scripts/metrics_eval.py --budget-check --reserve-usd 0.718 --reserve-native-usd 0.000
PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c2_nemo.yaml --input data/attacks/eval_v2_b2.jsonl --allow-partial --run-id ev2-b2-c2-r1
```

`ev2-b2-c0-r1`:

```sh
PYTHONPATH=src .venv/bin/python scripts/metrics_eval.py --budget-check --reserve-usd 0.670 --reserve-native-usd 0.000
PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c0_baseline.yaml --input data/attacks/eval_v2_b2.jsonl --allow-partial --run-id ev2-b2-c0-r1
```

`ev2-b2-c3-r1`:

```sh
PYTHONPATH=src .venv/bin/python scripts/metrics_eval.py --budget-check --reserve-usd 0.766 --reserve-native-usd 0.000
PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c3_llama_guard.yaml --input data/attacks/eval_v2_b2.jsonl --allow-partial --run-id ev2-b2-c3-r1
```

`ev2-b2-c5-r1`:

```sh
PYTHONPATH=src .venv/bin/python scripts/metrics_eval.py --budget-check --reserve-usd 0.814 --reserve-native-usd 0.521
PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c5_combined.yaml --input data/attacks/eval_v2_b2.jsonl --allow-partial --run-id ev2-b2-c5-r1
```

`ev2-b2-c4-r1`:

```sh
PYTHONPATH=src .venv/bin/python scripts/metrics_eval.py --budget-check --reserve-usd 0.814 --reserve-native-usd 0.521
PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c4_combined.yaml --input data/attacks/eval_v2_b2.jsonl --allow-partial --run-id ev2-b2-c4-r1
```

## 4. Alternativas que se eligen antes de empezar

No se combinan opciones después de ver resultados. La alternativa con los tres
filtros usa el nivel 1 completo y solo el bloque 1 del nivel 2: 8,624653 USD,
3,347447 nativos y 12,813 h, más la reserva de compatibilidad de 0,02 USD.
En ese caso sustituir cada comando de cribado anterior por estos, en orden:

```sh
PYTHONPATH=src .venv/bin/python scripts/metrics_eval.py --budget-check --reserve-usd 0.020 --reserve-native-usd 0.020
PYTHONPATH=src .venv/bin/python scripts/run_input_screening.py --input data/attacks/screen_v2.jsonl --part 1 --limit 5 --filters openrouter_native --run-id sc2-probe-native-16
```

Inspeccionar las cinco decisiones y confirmar que el proveedor acepta 16 tokens.
Si no, parar y revisar el parámetro, el presupuesto y el protocolo antes de
congelar de nuevo. Las pruebas `sc2-probe-*` suman gasto, pero no entran en las
tasas del cribado. No se baja el límite para conseguir una respuesta completa:
solo se observa si pasó el filtro de entrada.

```sh
PYTHONPATH=src .venv/bin/python scripts/metrics_eval.py --budget-check --reserve-usd 0.695 --reserve-native-usd 0.438
PYTHONPATH=src .venv/bin/python scripts/run_input_screening.py --input data/attacks/screen_v2.jsonl --part 1 --filters nemo_input,llama_guard_input,openrouter_native --run-id sc2-p1-todos
```

```sh
PYTHONPATH=src .venv/bin/python scripts/metrics_eval.py --budget-check --reserve-usd 0.710 --reserve-native-usd 0.448
PYTHONPATH=src .venv/bin/python scripts/run_input_screening.py --input data/attacks/screen_v2.jsonl --part 2 --filters nemo_input,llama_guard_input,openrouter_native --run-id sc2-p2-todos
```

```sh
PYTHONPATH=src .venv/bin/python scripts/metrics_eval.py --budget-check --reserve-usd 0.724 --reserve-native-usd 0.456
PYTHONPATH=src .venv/bin/python scripts/run_input_screening.py --input data/attacks/screen_v2.jsonl --part 3 --filters nemo_input,llama_guard_input,openrouter_native --run-id sc2-p3-todos
```

```sh
PYTHONPATH=src .venv/bin/python scripts/metrics_eval.py --budget-check --reserve-usd 0.707 --reserve-native-usd 0.446
PYTHONPATH=src .venv/bin/python scripts/run_input_screening.py --input data/attacks/screen_v2.jsonl --part 4 --filters nemo_input,llama_guard_input,openrouter_native --run-id sc2-p4-todos
```

Después ejecutar solo los ocho comandos del bloque 1 de la sección 3, en el
mismo orden. No lanzar los de `sc2-p*-nemo-llama` en esta alternativa: repetirían
los pares ya medidos y las métricas los rechazarían.

### Tamaños mayores

Los importes de esta tabla llevan margen 1,5. Para comprobar si caben se aplica
además el umbral del 90 %. Los mínimos de saldo y límite se redondean hacia
arriba a 0,10 USD e incluyen 0,02 USD para la prueba nativa cuando corresponde.
Son necesidades de saldo disponible, no gasto consumido. Se debe confirmar el
remanente de la clave y sumar cualquier uso previo que aún cuente en su límite.

| Cribado | Bloques N2 | Casos N2 | USD N1+N2 | Nativo | Saldo mínimo | Límite nativo mínimo |
|---|---:|---:|---:|---:|---:|---:|
| NeMo + Llama | 1–2 | 270 | 11.287392 | 3.122901 | 12.6 | 3.5 |
| NeMo + Llama | 1–3 | 405 | 15.707646 | 4.678219 | 17.5 | 5.2 |
| Tres filtros | 1–1 | 135 | 8.624653 | 3.347447 | 9.7 | 3.8 |
| Tres filtros | 1–2 | 270 | 13.073035 | 4.908544 | 14.6 | 5.5 |
| Tres filtros | 1–3 | 405 | 17.493288 | 6.463862 | 19.5 | 7.3 |
| Tres filtros | 1–5 | 673 | 26.131715 | 9.538888 | 29.1 | 10.7 |
| Tres filtros | 1–6 | 807 | 30.458920 | 11.077994 | 33.9 | 12.4 |
| Tres filtros | 1–8 | 1075 | 39.410451 | 14.210811 | 43.9 | 15.9 |

Los bloques 3–8 quedan fuera de la opción actual. Si se elige un tamaño mayor,
se actualizan las constantes de saldo y límite antes de congelar. El orden
exacto adicional, con sus run_id y reservas, es el siguiente. Se añaden solo
los bloques completos que se hayan elegido previamente:

| Orden | run_id | Comando | Reserva USD | Reserva nativa |
|---:|---|---|---:|---:|
| 15 | `ev2-b3-c2-r1` | `PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c2_nemo.yaml --input data/attacks/eval_v2_b3.jsonl --allow-partial --run-id ev2-b3-c2-r1` | 0.714 | 0.000 |
| 16 | `ev2-b3-c3-r1` | `PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c3_llama_guard.yaml --input data/attacks/eval_v2_b3.jsonl --allow-partial --run-id ev2-b3-c3-r1` | 0.760 | 0.000 |
| 17 | `ev2-b3-c1-r1` | `PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c1_native.yaml --input data/attacks/eval_v2_b3.jsonl --allow-partial --run-id ev2-b3-c1-r1` | 0.666 | 0.519 |
| 18 | `ev2-b3-c4-r1` | `PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c4_combined.yaml --input data/attacks/eval_v2_b3.jsonl --allow-partial --run-id ev2-b3-c4-r1` | 0.808 | 0.519 |
| 19 | `ev2-b3-c0-r1` | `PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c0_baseline.yaml --input data/attacks/eval_v2_b3.jsonl --allow-partial --run-id ev2-b3-c0-r1` | 0.666 | 0.000 |
| 20 | `ev2-b3-c5-r1` | `PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c5_combined.yaml --input data/attacks/eval_v2_b3.jsonl --allow-partial --run-id ev2-b3-c5-r1` | 0.808 | 0.519 |
| 21 | `ev2-b4-c3-r1` | `PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c3_llama_guard.yaml --input data/attacks/eval_v2_b4.jsonl --allow-partial --run-id ev2-b4-c3-r1` | 0.737 | 0.000 |
| 22 | `ev2-b4-c4-r1` | `PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c4_combined.yaml --input data/attacks/eval_v2_b4.jsonl --allow-partial --run-id ev2-b4-c4-r1` | 0.782 | 0.512 |
| 23 | `ev2-b4-c2-r1` | `PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c2_nemo.yaml --input data/attacks/eval_v2_b4.jsonl --allow-partial --run-id ev2-b4-c2-r1` | 0.698 | 0.000 |
| 24 | `ev2-b4-c5-r1` | `PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c5_combined.yaml --input data/attacks/eval_v2_b4.jsonl --allow-partial --run-id ev2-b4-c5-r1` | 0.782 | 0.512 |
| 25 | `ev2-b4-c1-r1` | `PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c1_native.yaml --input data/attacks/eval_v2_b4.jsonl --allow-partial --run-id ev2-b4-c1-r1` | 0.652 | 0.512 |
| 26 | `ev2-b4-c0-r1` | `PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c0_baseline.yaml --input data/attacks/eval_v2_b4.jsonl --allow-partial --run-id ev2-b4-c0-r1` | 0.652 | 0.000 |
| 27 | `ev2-b5-c4-r1` | `PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c4_combined.yaml --input data/attacks/eval_v2_b5.jsonl --allow-partial --run-id ev2-b5-c4-r1` | 0.790 | 0.514 |
| 28 | `ev2-b5-c5-r1` | `PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c5_combined.yaml --input data/attacks/eval_v2_b5.jsonl --allow-partial --run-id ev2-b5-c5-r1` | 0.790 | 0.514 |
| 29 | `ev2-b5-c3-r1` | `PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c3_llama_guard.yaml --input data/attacks/eval_v2_b5.jsonl --allow-partial --run-id ev2-b5-c3-r1` | 0.744 | 0.000 |
| 30 | `ev2-b5-c0-r1` | `PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c0_baseline.yaml --input data/attacks/eval_v2_b5.jsonl --allow-partial --run-id ev2-b5-c0-r1` | 0.657 | 0.000 |
| 31 | `ev2-b5-c2-r1` | `PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c2_nemo.yaml --input data/attacks/eval_v2_b5.jsonl --allow-partial --run-id ev2-b5-c2-r1` | 0.703 | 0.000 |
| 32 | `ev2-b5-c1-r1` | `PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c1_native.yaml --input data/attacks/eval_v2_b5.jsonl --allow-partial --run-id ev2-b5-c1-r1` | 0.657 | 0.514 |
| 33 | `ev2-b6-c5-r1` | `PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c5_combined.yaml --input data/attacks/eval_v2_b6.jsonl --allow-partial --run-id ev2-b6-c5-r1` | 0.788 | 0.514 |
| 34 | `ev2-b6-c0-r1` | `PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c0_baseline.yaml --input data/attacks/eval_v2_b6.jsonl --allow-partial --run-id ev2-b6-c0-r1` | 0.655 | 0.000 |
| 35 | `ev2-b6-c4-r1` | `PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c4_combined.yaml --input data/attacks/eval_v2_b6.jsonl --allow-partial --run-id ev2-b6-c4-r1` | 0.788 | 0.514 |
| 36 | `ev2-b6-c1-r1` | `PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c1_native.yaml --input data/attacks/eval_v2_b6.jsonl --allow-partial --run-id ev2-b6-c1-r1` | 0.655 | 0.514 |
| 37 | `ev2-b6-c3-r1` | `PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c3_llama_guard.yaml --input data/attacks/eval_v2_b6.jsonl --allow-partial --run-id ev2-b6-c3-r1` | 0.742 | 0.000 |
| 38 | `ev2-b6-c2-r1` | `PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c2_nemo.yaml --input data/attacks/eval_v2_b6.jsonl --allow-partial --run-id ev2-b6-c2-r1` | 0.702 | 0.000 |
| 39 | `ev2-b7-c0-r1` | `PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c0_baseline.yaml --input data/attacks/eval_v2_b7.jsonl --allow-partial --run-id ev2-b7-c0-r1` | 0.672 | 0.000 |
| 40 | `ev2-b7-c1-r1` | `PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c1_native.yaml --input data/attacks/eval_v2_b7.jsonl --allow-partial --run-id ev2-b7-c1-r1` | 0.672 | 0.523 |
| 41 | `ev2-b7-c5-r1` | `PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c5_combined.yaml --input data/attacks/eval_v2_b7.jsonl --allow-partial --run-id ev2-b7-c5-r1` | 0.817 | 0.523 |
| 42 | `ev2-b7-c2-r1` | `PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c2_nemo.yaml --input data/attacks/eval_v2_b7.jsonl --allow-partial --run-id ev2-b7-c2-r1` | 0.721 | 0.000 |
| 43 | `ev2-b7-c4-r1` | `PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c4_combined.yaml --input data/attacks/eval_v2_b7.jsonl --allow-partial --run-id ev2-b7-c4-r1` | 0.817 | 0.523 |
| 44 | `ev2-b7-c3-r1` | `PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c3_llama_guard.yaml --input data/attacks/eval_v2_b7.jsonl --allow-partial --run-id ev2-b7-c3-r1` | 0.769 | 0.000 |
| 45 | `ev2-b8-c1-r1` | `PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c1_native.yaml --input data/attacks/eval_v2_b8.jsonl --allow-partial --run-id ev2-b8-c1-r1` | 0.674 | 0.522 |
| 46 | `ev2-b8-c2-r1` | `PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c2_nemo.yaml --input data/attacks/eval_v2_b8.jsonl --allow-partial --run-id ev2-b8-c2-r1` | 0.722 | 0.000 |
| 47 | `ev2-b8-c0-r1` | `PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c0_baseline.yaml --input data/attacks/eval_v2_b8.jsonl --allow-partial --run-id ev2-b8-c0-r1` | 0.674 | 0.000 |
| 48 | `ev2-b8-c3-r1` | `PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c3_llama_guard.yaml --input data/attacks/eval_v2_b8.jsonl --allow-partial --run-id ev2-b8-c3-r1` | 0.774 | 0.000 |
| 49 | `ev2-b8-c5-r1` | `PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c5_combined.yaml --input data/attacks/eval_v2_b8.jsonl --allow-partial --run-id ev2-b8-c5-r1` | 0.822 | 0.522 |
| 50 | `ev2-b8-c4-r1` | `PYTHONPATH=src .venv/bin/python scripts/run_config.py --config configs/c4_combined.yaml --input data/attacks/eval_v2_b8.jsonl --allow-partial --run-id ev2-b8-c4-r1` | 0.822 | 0.522 |

Antes de cada fila se ejecuta el mismo `--budget-check` de la sección 3 con sus
dos reservas. Antes de abrir cada bloque, se usan además las reservas completas
por bloque de `data/attacks/eval_v2_budget.json`. No se ejecuta una fila si el
control devuelve 3.

## 5. Análisis y revisión humana

Tras el último bloque elegido, incluso si hubo parada:

```sh
PYTHONPATH=src .venv/bin/python scripts/metrics_eval.py --budget-check
PYTHONPATH=src .venv/bin/python scripts/metrics_eval.py --screening
PYTHONPATH=src .venv/bin/python scripts/metrics_eval.py
PYTHONPATH=src .venv/bin/python scripts/sample_human_labels.py --size 150 --out-dir results/local/etiquetas_v2
```

El autor etiqueta `formulario.csv` sin consultar la clave, con `danino` o
`no_danino`. Si hay menos de 150 respuestas disponibles, el formulario contiene
todas y se deja constancia: la validación queda incompleta. El formulario no se
sobrescribe al repetir el comando. Si es posible, una segunda persona etiqueta
una copia ciega y se adjudican los desacuerdos. Después:

```sh
PYTHONPATH=src .venv/bin/python scripts/metrics_eval.py --human-labels results/local/etiquetas_v2/formulario.csv
```

Para presentar B como principal se requieren 150 etiquetas válidas y κ≥0,60;
κ indefinido o muestra insuficiente dejan B como exploratoria. La muestra está
equilibrada por configuración: su acuerdo no estima sin ponderación el acuerdo
global de todas las respuestas. Revisar también la matriz de confusión.

Anotar en el registro de ejecuciones las fechas, revisión, run_id, huellas,
consumo real, errores y desviaciones. Mantener las respuestas y etiquetas en
los directorios locales; publicar solo tablas y ejemplos redactados. Las tablas
principales excluyen bloques incompletos, y los gastos y errores los conservan.
