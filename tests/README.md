# Comprobaciones del programa

Estas pruebas detectan errores del software. Usan respuestas preparadas y
bloquean las conexiones de red mediante `conftest.py`: no consumen créditos.
No son pruebas de eficacia de las salvaguardas sobre DeepSeek real.

Desde la raíz:

```sh
PYTHONPATH=src .venv/bin/pytest -q
PYTHONPATH=src .venv/bin/mypy src scripts tests
```

Los archivos comprueban la lectura de recetas (`test_config.py`), el montaje y
la reanudación (`test_declarative.py`, `test_c0.py`), el recorrido
(`test_pipeline.py`), cada salvaguarda y los corpus y métricas de evaluación.
`test_adaptive.py` cubre el motor adaptativo (reanudación, presupuesto, huella y métricas) y
`test_segundo_juez.py`, la revisión con el juez de JailbreakBench.
`test_auditoria_validez.py` cubre errores que afectarían a las cifras: costes
incompletos, generaciones reutilizadas, bloqueos y tiempos del juez.
