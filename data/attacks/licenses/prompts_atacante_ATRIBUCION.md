# Prompts originales del nivel 3

- PAIR: PAIR Team (copyright 2023), repositorio patrickrchao/JailbreakingLLMs,
  commit `6379ef705a0fc745530f7d895963510c021b496a`, licencia MIT en `pair_MIT.txt`,
  copiada íntegramente de `external/prompts_atacante/pair_LICENSE`.
  Fuente: https://github.com/patrickrchao/JailbreakingLLMs/tree/6379ef705a0fc745530f7d895963510c021b496a
  - `pair_system_prompts.py`: prompts del atacante (`roleplaying_prompt`,
    `logical_appeal_prompt`, `authority_endorsement_prompt`) y del juez
    (`get_judge_system_prompt`).
  - `pair_common.py`: primer mensaje (`get_init_msg`) y realimentación
    (`process_target_response`).
- Crescendo y clasificador de negativas: Microsoft Corporation, repositorio
  microsoft/PyRIT, commit `817523458433ef20c1316418bab10be312535416`, licencia MIT
  en `pyrit_MIT.txt`, copiada íntegramente de `external/prompts_atacante/pyrit_LICENSE`.
  Fuente: https://github.com/microsoft/PyRIT/tree/817523458433ef20c1316418bab10be312535416
  - `crescendo_variant_1.yaml` (autores del prompt: Mark Russinovich, Ahmed Salem
    y Ronen Eldan).
  - `refusal_objective_lenient.yaml` (AI Red Team de Microsoft).
  - `adversarial_chat_schema.yaml` y `true_false_with_rationale_schema.yaml`:
    esquemas JSON de salida, reproducidos en el código.
  - El mensaje de cada turno de Crescendo se adapta de `CrescendoAttack` en
    `pyrit/executor/attack/multi_turn/crescendo.py`.

Los originales se conservan en `data/attacks/external/prompts_atacante/`.
El motor verifica sus SHA-256 fijados, no ejecuta ninguno de ellos (los ficheros
de Python se analizan con `ast`) y registra las huellas en la cabecera de cada
ejecución. Las adaptaciones del bucle, el presupuesto y el arbitraje se describen
en `docs/protocolo_nivel3_adaptativo.md`; no equivalen a reproducir los resultados
publicados.
