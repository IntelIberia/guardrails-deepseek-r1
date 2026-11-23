"""Formularios ciegos y acuerdo con respuestas sintéticas, sin red."""

import csv
import json
from pathlib import Path
from typing import Any

import pytest

from scripts import formulario_etiquetado as f
from scripts import metrics_eval as m
from scripts import sample_human_labels as s


def source_form(tmp_path: Path, size: int = 150) -> Path:
    observations = [m.Observation("ev2-b1-c0-r1", 1, "C0", 1, f"p{i}", "delivered", None, None,
                                  None, None, 'Texto, con "comillas"\ny otra línea', "razonamiento", True, 1)
                    for i in range(size)]
    manifest = {"rows": [{"prompt_id": o.prompt_id, "inserted_request": "conducta de prueba"}
                         for o in observations]}
    return s.write_form(observations, manifest, tmp_path / "muestra")


def test_formulario_ciego_conserva_contenido(tmp_path: Path) -> None:
    source = source_form(tmp_path)
    out = f.write_form(source, tmp_path / "autor", rubric="Rúbrica de prueba")
    assert f.read_form(source) == f.read_form(out)
    assert all(not r["etiqueta_humana"] for r in f.read_form(out))
    assert '"comillas"\ny otra línea' in f.read_form(out)[0]["respuesta_final"]
    assert "Rúbrica de prueba" in out.with_name("instrucciones.txt").read_text()
    assert "run_id" not in out.read_text() and "judge" not in out.read_text()
    previous = out.read_bytes()
    with pytest.raises(ValueError, match="Ya existe"):
        f.write_form(source, out.parent)
    assert out.read_bytes() == previous


def test_muestra_insuficiente_y_clave_invalida(tmp_path: Path) -> None:
    source = source_form(tmp_path, 2)
    with pytest.raises(ValueError, match="incompleta"):
        f.write_form(source, tmp_path / "autor")
    source.with_name("formulario_clave.json").write_text('{"samples": {}}')
    with pytest.raises(ValueError, match="clave"):
        f.write_form(source, tmp_path / "autor", expected_size=2)
    assert not (tmp_path / "autor").exists()


def test_etiquetas_y_duplicados(tmp_path: Path) -> None:
    source = source_form(tmp_path, 2)
    rows = f.read_form(source)
    rows[0]["etiqueta_humana"] = "danino"
    with source.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=s.FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    with pytest.raises(ValueError, match="anotaciones"):
        f.write_form(source, tmp_path / "autor", expected_size=2)
    with source.open("a", encoding="utf-8", newline="") as handle:
        csv.DictWriter(handle, fieldnames=s.FIELDS).writerow(rows[0])
    with pytest.raises(ValueError, match="duplicados"):
        f.read_form(source)


def test_acuerdo_real_sobre_registros_sinteticos(tmp_path: Path) -> None:
    """La clave enlaza con load_run, sin sustituir el cálculo estadístico."""
    cases: list[dict[str, Any]] = []
    for i in range(5):
        cases.append({"prompt_id": f"p{i}", "prompt_source": "prueba", "owasp_category": "x",
                      "nist_category": "x", "is_benign": False, "system_prompt": "s",
                      "prompt": "p", "objective": "o"})
    manifest = {"rows": [{"prompt_id": c["prompt_id"], "row_sha256": m.row_sha256(c),
                          "track": "B", "case_class": "attack"} for c in cases],
                "blocks": [{"block": 1, "sha256": "prueba", "prompt_ids": [c["prompt_id"] for c in cases]}]}
    run_id = "ev2-b1-c0-r1"
    records = [{"record_type": "header", "run_id": run_id, "config_id": "C0",
                "config": {"dataset": {"sha256": "prueba", "cases": cases}}}]
    judges = [False, True, False, True, None]
    for c, verdict in zip(cases, judges, strict=True):
        records.append({"record_type": "result", "run_id": run_id, "prompt_id": c["prompt_id"],
                        "response_text": "respuesta de prueba", "judge_verdict": {"success": verdict}})
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / f"{run_id}.jsonl").write_text("\n".join(json.dumps(r) for r in records), encoding="utf-8")
    source = source_form(tmp_path, 5)
    rows = f.read_form(source)
    for row, label in zip(rows, ["no_danino", "no_danino", "danino", "danino", "danino"], strict=True):
        row["etiqueta_humana"] = label
    with source.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=s.FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    result = f.evaluate(source, raw, manifest)
    assert result["matrix_rows_human_columns_judge"] == [[1, 1], [1, 1]]
    assert result["n"] == 4 and result["missing_judge"] == 1
    assert result["kappa"] == 0
    assert result["fpr"]["p"] == result["fnr"]["p"] == .5
    assert not result["validation_passed"]


def test_denominadores_nulos_y_acuerdo_perfecto() -> None:
    result = f.agreement_rates({"confusion": {"humano_True_juez_True": 3}})
    assert result["fpr"]["p"] is None
    assert result["fpr"]["wilson95"] is None
    assert result["fnr"]["p"] == 0
    assert m.cohen_kappa([(False, False), (True, True)]) == 1
    assert m.cohen_kappa([(True, True)]) is None
