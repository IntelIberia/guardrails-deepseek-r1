"""Los textos de jailbreak pueden traer U+2028, U+2029 o U+0085 dentro de un
campo JSON. Los lectores de JSONL deben partir solo por saltos de línea reales."""
import json
from pathlib import Path

from scripts import metrics_eval, run_input_screening

RARO = "antes medio fin\u0085"


def test_read_jsonl_no_parte_por_separadores_unicode(tmp_path: Path) -> None:
    fichero = tmp_path / "x.jsonl"
    filas = [{"a": RARO}, {"b": 1}]
    fichero.write_text("".join(json.dumps(f, ensure_ascii=False) + "\n" for f in filas),
                       encoding="utf-8")
    assert metrics_eval.read_jsonl(fichero) == filas


def test_completed_pairs_no_parte_por_separadores_unicode(tmp_path: Path) -> None:
    cabecera = {"record_type": "header", "run_id": "r", "config_fingerprint": "f"}
    fila = {"record_type": "result", "run_id": "r", "prompt_id": "p1", "filter": "nemo_input",
            "status": "passed", "nota": RARO}
    fichero = tmp_path / "r.jsonl"
    fichero.write_text(json.dumps(cabecera) + "\n" + json.dumps(fila, ensure_ascii=False) + "\n",
                       encoding="utf-8")
    hechos = run_input_screening.completed_pairs(fichero, cabecera)
    assert ("p1", "nemo_input") in hechos
