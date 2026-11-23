"""Verificación con métricas sintéticas, sin resultados de la campaña."""

import json
from pathlib import Path
from typing import Any

import pytest

from scripts import figuras_resultados as f
from scripts import metrics_eval as m


def test_vectorial_y_sin_titulos(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    metrics, screen, families, agreement = f.synthetic_data()
    plt = f.pyplot()
    original = plt.Figure.savefig
    observed: list[str] = []

    def inspect(fig: Any, path: Path, **kwargs: Any) -> None:
        assert all(not ax.get_title() for ax in fig.axes)
        assert any("SINTÉTICOS" in text.get_text() for text in fig.texts)
        # Los mapas de calor han de conservar sus celdas como vectores.
        assert all(not ax.images for ax in fig.axes)
        observed.append(path.name)
        original(fig, path, **kwargs)

    monkeypatch.setattr(plt.Figure, "savefig", inspect)
    report = f.generate(metrics, tmp_path, screening=screen, attack_families=families, agreement=agreement)
    assert len(report["generated"]) == 15
    assert len(observed) == 15 and not report["pending"]
    for filename in report["generated"]:
        assert (tmp_path / filename).read_bytes().startswith(b"%PDF-")
    assert json.loads((tmp_path / "figuras_generadas.json").read_text())["synthetic"]


def test_ausencia_no_se_representa_como_cero() -> None:
    plt = f.pyplot()
    fig, ax = plt.subplots()
    f.interval_bars(ax, ["ausente", "cero"], [m.proportion(0, 0), m.proportion(0, 30)])
    assert len(ax.patches) == 1
    assert any(t.get_text() == "s/d" for t in ax.texts)
    assert ax.patches[0].get_height() == 0
    plt.close(fig)


def test_embudo_cohorte_evaluable() -> None:
    entry: f.Json = {"dsr_blocked": m.proportion(5, 12),
             "dsr_blocked_by_layer": {"input:nemo": 2, "target:nativo": 1, "output:lg": 2}}
    assert f.funnel_counts(entry)[1] == [12, 9, 7]
    entry["dsr_blocked_by_layer"]["output:lg"] = 3
    with pytest.raises(ValueError, match="desglose"):
        f.funnel_counts(entry)


def test_sintetico_nunca_en_resultados() -> None:
    metrics, _, _, _ = f.synthetic_data()
    with pytest.raises(ValueError, match="temporal"):
        f.generate(metrics, f.ROOT / "results/figuras/nivel2")


def test_cli_falta_entrada_usa_temporal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                      capsys: pytest.CaptureFixture[str]) -> None:
    seen: list[Path] = []

    def fake_generate(metrics: f.Json, out: Path, **kwargs: Any) -> f.Json:
        assert metrics["synthetic"]
        seen.append(out)
        return {"generated": [], "pending": []}

    monkeypatch.setattr(f, "generate", fake_generate)
    forbidden = tmp_path / "salida_elegida"
    assert f.main(["--metrics", str(tmp_path / "inexistente.json"), "--out-dir", str(forbidden)]) == 0
    assert not forbidden.exists()
    assert (seen[0] / "metricas_nivel2_SINTETICO.json").exists()
    assert "SINTÉTICOS" in capsys.readouterr().out


def test_formato_real_y_auxiliares_ausentes(tmp_path: Path) -> None:
    # compute produce el esquema real incluso sin ejecuciones disponibles.
    manifest = json.loads(m.MANIFEST.read_text(encoding="utf-8"))
    metrics = m.compute(tmp_path / "raw_ausente", manifest)
    report = f.generate(metrics, tmp_path / "figuras")
    assert not report["synthetic"]
    assert len(report["pending"]) == 2
    assert "confusion_juez_humano.pdf" not in report["generated"]
