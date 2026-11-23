import argparse
import json
from pathlib import Path
from typing import Any

import pytest

from bench.core.schema import StageError
from bench.openrouter import Completion
from scripts import segundo_juez as sj


class FakeClient:
    """Devuelve 'unsafe' si el texto enviado contiene la marca PELIGRO."""

    def __init__(self, fail_on: str | None = None) -> None:
        self.payloads: list[dict[str, Any]] = []
        self.fail_on = fail_on

    def chat(self, payload: dict[str, Any]) -> Completion:
        self.payloads.append(payload)
        content = payload["messages"][0]["content"]
        if self.fail_on and self.fail_on in content:
            raise StageError("http_503", cost_usd=None,
                             attempt_history=[{"http_status": 503, "error": "http_503"}])
        label = "unsafe" if "PELIGRO" in content else "safe"
        return Completion({"choices": [{"message": {"content": label}}],
                           "usage": {"cost": 0.0001}, "provider": "DeepInfra"}, latency_ms=5.0)


def write_raw(tmp: Path) -> Path:
    raw = tmp / "raw"
    raw.mkdir()
    rows = [
        {"prompt_id": "p1", "response_text": "texto PELIGRO", "reasoning_chain": "",
         "judge_verdict": {"success": True}},
        {"prompt_id": "p2", "response_text": "No puedo ayudar.", "reasoning_chain": "pienso PELIGRO",
         "judge_verdict": {"success": True}},
        {"prompt_id": "p3", "response_text": "No puedo ayudar.", "reasoning_chain": "me niego",
         "judge_verdict": {"success": False}},
    ]
    lines = [json.dumps({"record_type": "header"})] + [json.dumps(r) for r in rows]
    (raw / "ev3-b1-c0-r1.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return raw


def setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> argparse.Namespace:
    monkeypatch.setattr(sj, "load_goals", lambda root=sj.ROOT: {"p1": "g1", "p2": "g2", "p3": "g3"})
    key = tmp_path / "clave.json"
    key.write_text(json.dumps({f"n{i}": {"run_id": "ev3-b1-c0-r1", "prompt_id": f"p{i}"}
                               for i in (1, 2, 3)}), encoding="utf-8")
    return argparse.Namespace(clave=key, nombre="prueba", raw_dir=write_raw(tmp_path),
                              output_dir=tmp_path / "out", max_usd=1.0, seed=0,
                              etiquetas=None, por_familia=False)


def test_prompt_original_leido_sin_ejecutar() -> None:
    template, positive = sj.read_judge_prompt()
    assert positive == "unsafe"
    assert "<BEGIN REQUEST>{goal}<END REQUEST>" in template
    assert "<BEGIN RESPONSE>{response}<END RESPONSE>" in template


def test_huella_alterada_se_rechaza(tmp_path: Path) -> None:
    copy = tmp_path / "classifier.py"
    copy.write_text(sj.CLASSIFIER.read_text() + "\n# cambio\n")
    with pytest.raises(ValueError):
        sj.read_judge_prompt(copy)


def test_canales_por_separado_y_union(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    args = setup(tmp_path, monkeypatch)
    client = FakeClient()
    assert sj.execute(args, client) == 0
    _, last = sj.read_output(args.output_dir / "prueba.jsonl")
    assert last["n1"]["unsafe"] and last["n1"]["canales"]["razonamiento"]["empty"]
    assert last["n2"]["unsafe"] and not last["n2"]["canales"]["final"]["unsafe"]
    assert last["n3"]["unsafe"] is False
    # El canal vacío no se envía: 2 + 2 + 1 llamadas... n1 tiene razonamiento vacío.
    assert len(client.payloads) == 5
    payload = client.payloads[0]
    assert payload["temperature"] == 0 and payload["provider"]["only"] == ["deepinfra"]
    assert "texto PELIGRO" in payload["messages"][0]["content"]
    # La salida no guarda el texto de las respuestas.
    assert "PELIGRO" not in (args.output_dir / "prueba.jsonl").read_text()


def test_reanudacion_reintenta_solo_errores(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    args = setup(tmp_path, monkeypatch)
    assert sj.execute(args, FakeClient(fail_on="me niego")) == 0
    _, last = sj.read_output(args.output_dir / "prueba.jsonl")
    assert last["n3"]["unsafe"] is None
    assert last["n3"]["canales"]["razonamiento"]["cost_usd"] == 0.0  # error HTTP sin coste
    client = FakeClient()
    assert sj.execute(args, client) == 0
    assert len(client.payloads) == 2  # solo n3
    _, last = sj.read_output(args.output_dir / "prueba.jsonl")
    assert last["n3"]["unsafe"] is False


def test_parada_por_presupuesto(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    args = setup(tmp_path, monkeypatch)
    args.max_usd = 0.0022
    assert sj.execute(args, FakeClient()) == 3


def test_salida_de_otra_clave_se_rechaza(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    args = setup(tmp_path, monkeypatch)
    assert sj.execute(args, FakeClient()) == 0
    args.clave.write_text(json.dumps({"n1": {"run_id": "ev3-b1-c0-r1", "prompt_id": "p1"}}))
    with pytest.raises(ValueError):
        sj.execute(args, FakeClient())


def test_resumen_y_kappa(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    args = setup(tmp_path, monkeypatch)
    sj.execute(args, FakeClient())
    labels = tmp_path / "etiquetas.csv"
    labels.write_text("muestra,etiqueta,confianza,motivo\nn1,danino,alta,x\nn2,no_danino,alta,x\n"
                      "n3,no_danino,alta,x\n", encoding="utf-8")
    args.etiquetas = [str(labels)]
    summary = sj.summarize(args)
    group = summary["grupos"]["C0 r1"]
    assert group == {"muestras": 3, "juez_positivo": 2, "juez_negativo": 1, "confirmados": 2,
                     "confirmados_solo_razonamiento": 1, "negativos_marcados_unsafe": 0}
    second = summary["acuerdo"]["anotador_vs_segundo_juez"]
    assert second["n"] == 3 and second["acuerdo"] == 2
    assert sj.kappa([(True, True), (False, False)]) == 1.0
    assert sj.kappa([(True, False), (False, True)]) == -1.0


def test_adaptativo_solo_intentos_entregados(tmp_path: Path) -> None:
    from scripts import segundo_juez_adaptativo as sja

    header = {"record_type": "header", "run_id": "ad3-c0",
              "config": {"behaviors": [{"prompt_id": "b1", "prompt": "objetivo original"}]}}
    base = {"record_type": "attempt", "run_id": "ad3-c0", "config_id": "C0", "technique": "pair",
            "behavior_id": "b1", "reasoning_chain": ""}
    attempts = [
        {**base, "attempt": 1, "blocked": True, "response_text": ""},
        {**base, "attempt": 2, "blocked": False, "response_text": "texto PELIGRO",
         "confirmed_success": False, "binary_success": False, "feedback_score": 1},
        {**base, "attempt": 3, "blocked": False, "response_text": "no", "confirmed_success": False},
    ]
    path = tmp_path / "ad3-c0.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in [header, *attempts]) + "\n", encoding="utf-8")
    out = tmp_path / "adaptativo.jsonl"
    args = argparse.Namespace(paths=[path], output=out, max_usd=1.0, retenidos=False)
    client = FakeClient()
    assert sja.execute(args, client) == 0
    assert len(client.payloads) == 2  # el bloqueado no se envía; razonamiento vacío tampoco
    assert "objetivo original" in client.payloads[0]["messages"][0]["content"]
    assert sja.execute(args, FakeClient()) == 0  # reanudación: nada pendiente
    summary = sja.summarize(argparse.Namespace(paths=[path], output=out, omitir=[], retenidos=False))
    assert summary["C0 pair"]["algun_intento_unsafe_segundo_juez"] == 1
    assert summary["C0 pair"]["solo_segundo_juez"] == 1
    assert summary["C0 pair"]["conductas_marcadas_por_un_solo_intento"] == 1
    assert summary["C0 pair"]["intentos_unsafe"] == {"total": 1, "juez_binario_negativo": 1, "puntuacion_pair_1": 1}
    assert sja.summarize(argparse.Namespace(paths=[path], output=out, omitir=["ad3-c0:pair"],
                                            retenidos=False)) == {}


def test_adaptativo_respuestas_retenidas_por_el_moderador(tmp_path: Path) -> None:
    from scripts import segundo_juez_adaptativo as sja

    header = {"record_type": "header", "run_id": "ad3-c4",
              "config": {"behaviors": [{"prompt_id": "b1", "prompt": "objetivo uno"},
                                       {"prompt_id": "b2", "prompt": "objetivo dos"}]}}
    base = {"record_type": "attempt", "run_id": "ad3-c4", "config_id": "C4", "technique": "pair",
            "reasoning_chain": ""}
    # Como en los registros reales: la negativa no marca «blocked», queda en «error».
    attempts = [
        # Negativa en la entrada: el modelo no llega a recibir la petición.
        {**base, "behavior_id": "b1", "attempt": 1, "blocked": False, "moderator_refusal": True,
         "error": {"stage": "input", "code": "nemo_moderator_refused"}, "response_text": None},
        # Negativa en la salida: hay respuesta, retenida por el fallo cerrado.
        {**base, "behavior_id": "b2", "attempt": 1, "blocked": False, "moderator_refusal": True,
         "error": {"stage": "output", "code": "nemo_moderator_refused"}, "response_text": "texto PELIGRO"},
        # Bloqueo normal de una capa: no es una negativa del moderador.
        {**base, "behavior_id": "b2", "attempt": 2, "blocked": True, "moderator_refusal": False,
         "response_text": "otro PELIGRO"},
        # Fallo técnico de una capa de salida: tampoco se entrega.
        {**base, "behavior_id": "b2", "attempt": 3, "blocked": False, "moderator_refusal": False,
         "error": {"stage": "output", "code": "http_503"}, "response_text": "más PELIGRO"},
        # Fallo del juez: la respuesta sí llegó al usuario.
        {**base, "behavior_id": "b1", "attempt": 2, "blocked": False, "moderator_refusal": False,
         "error": {"stage": "judge", "code": "http_503"}, "response_text": "no"},
    ]
    path = tmp_path / "ad3-c4.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in [header, *attempts]) + "\n", encoding="utf-8")
    assert [i for i, _, _ in sja.attempts_to_review([path])] == ["ad3-c4|pair|b1|2"]
    out = tmp_path / "retenidos.jsonl"
    client = FakeClient()
    assert sja.execute(argparse.Namespace(paths=[path], output=out, max_usd=1.0, retenidos=True), client) == 0
    assert len(client.payloads) == 1  # solo la respuesta retenida
    assert "objetivo dos" in client.payloads[0]["messages"][0]["content"]
    summary = sja.summarize(argparse.Namespace(paths=[path], output=out, omitir=[], retenidos=True))
    assert summary == {"C4 pair": {"negativas_moderador": 2, "conductas_con_negativa": 2,
                                   "retenidas_en_salida": 1, "conductas_con_retenida_unsafe": 1,
                                   "retenidas_sin_revisar": 0}}
