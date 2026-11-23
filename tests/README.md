# tests: pruebas del código

Comprueban que el software hace lo que debe, no la eficacia de los filtros
sobre DeepSeek real. Usan respuestas preparadas y `conftest.py` bloquea la red,
así que no gastan nada.

Desde la raíz:

```sh
PYTHONPATH=src .venv/bin/pytest -q
MYPYPATH=src .venv/bin/python -m mypy probar.py src scripts tests
```

| Archivo | Qué comprueba |
|---|---|
| `conftest.py` | Bloquea sockets y DNS durante las pruebas. |
| `test_config.py` | La lectura estricta de los YAML. |
| `test_declarative.py`, `test_c0.py` | El montaje de una configuración y la reanudación de una ejecución. |
| `test_pipeline.py` | El recorrido de un caso por la cadena y la parada en el primer bloqueo. |
| `test_target_completion.py` | Cómo se trata una respuesta del objetivo incompleta o cortada. |
| `test_native_guard.py`, `test_nemo.py`, `test_llama_guard.py`, `test_structured.py` | Cada filtro: C1, C2, C3 y Guardrails AI. |
| `test_input_screening.py` | El cribado de entrada del nivel 1. |
| `test_eval_v1_corpus.py`, `test_eval_v2_corpus.py`, `test_eval_v3_corpus.py` | Que los corpus conservan sus huellas y reglas de construcción. |
| `test_separadores_unicode.py` | La lectura de JSONL con caracteres U+2028, U+2029 y U+0085. |
| `test_metrics_eval.py`, `test_figuras_resultados.py`, `test_formulario_etiquetado.py` | Métricas, figuras y formulario de etiquetado. |
| `test_auditoria_validez.py` | Errores que alterarían las cifras: costes incompletos, generaciones reutilizadas, bloqueos y tiempos del juez. |
| `test_adaptive.py` | El motor adaptativo: reanudación, presupuesto, huella y métricas. |
| `test_segundo_juez.py` | La revisión con el juez de JailbreakBench. |
| `test_probar.py` | El programa `probar.py`. |
