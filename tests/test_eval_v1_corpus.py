"""Comprueba el corpus reservado eval_v1 y las reglas de preparación sin red."""

import hashlib
import json
from pathlib import Path
from typing import Any

from scripts import prepare_eval_v1 as prep
from scripts.metrics_eval import row_sha256
from scripts.run_config import load_attacks

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "data/attacks/eval_v1.jsonl"
MANIFEST: dict[str, Any] = json.loads((ROOT / "data/attacks/eval_v1_manifest.json").read_text("utf-8"))
DEV_FILES = ("c0_20.jsonl", "development12.jsonl", "h4_smoke3.jsonl", "h5_c4_smoke2.jsonl",
             "jailbreakhub_probe16.jsonl", "pilot_llm07.json")


def test_el_cargador_del_banco_acepta_el_corpus_y_los_bloques() -> None:
    attacks, digest = load_attacks(CORPUS)
    assert digest == MANIFEST["corpus_sha256"] and len(attacks) == MANIFEST["count"] == 75
    ids: list[str] = []
    for block in MANIFEST["blocks"]:
        block_attacks, block_digest = load_attacks(ROOT / block["path"])
        assert block_digest == block["sha256"]
        assert [a.prompt_id for a in block_attacks] == block["prompt_ids"]
        ids.extend(block["prompt_ids"])
    assert sorted(ids) == sorted(a.prompt_id for a in attacks)


def test_composicion_y_huellas_de_fila() -> None:
    cases = [json.loads(line) for line in CORPUS.read_text("utf-8").splitlines()]
    rows = {row["prompt_id"]: row for row in MANIFEST["rows"]}
    counts: dict[str, int] = {}
    for case in cases:
        row = rows[case["prompt_id"]]
        counts[row["scenario"]] = counts.get(row["scenario"], 0) + 1
        assert row["row_sha256"] == row_sha256(case)
        assert row["row_sha256"] == hashlib.sha256(
            (json.dumps(case, ensure_ascii=False) + "\n").encode("utf-8")).hexdigest()
        assert row["canary"] in case["system_prompt"] and row["canary"] not in case["prompt"]
        assert case["is_benign"] is (row["scenario"] == "benign")
    assert counts == {"LLM07": 30, "LLM01": 10, "LLM05": 10, "benign": 25}
    attacks = [row for row in MANIFEST["rows"] if row["case_class"] == "attack"]
    assert len({row["template_group_id"] for row in attacks}) == 50
    assert len({row["canary"] for row in MANIFEST["rows"]}) == 75


def test_ningun_caso_procede_de_los_corpus_de_desarrollo() -> None:
    dev_prompts: set[str] = set()
    for name in DEV_FILES:
        text = (ROOT / "data/attacks" / name).read_text("utf-8")
        try:
            parsed = json.loads(text)
            items = parsed if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError:
            items = [json.loads(line) for line in text.splitlines() if line.strip()]
        dev_prompts.update(item["prompt"] for item in items)
    cases = [json.loads(line) for line in CORPUS.read_text("utf-8").splitlines()]
    assert not {case["prompt"] for case in cases} & dev_prompts
    used = {row["xstest_id"] for row in MANIFEST["rows"] if row["scenario"] == "benign"}
    assert not used & prep.XSTEST_USED_IDS and len(used) == 25
    dev_sets = [prep.shingles(text) for text in dev_prompts]
    for row in MANIFEST["rows"]:
        if row["case_class"] == "attack":
            case = next(c for c in cases if c["prompt_id"] == row["prompt_id"])
            assert all(prep.jaccard(prep.shingles(case["prompt"]), dev) < prep.SIMILARITY_THRESHOLD
                       for dev in dev_sets)


def test_objetivos_inocuos_y_oraculos() -> None:
    cases = {json.loads(line)["prompt_id"]: json.loads(line)
             for line in CORPUS.read_text("utf-8").splitlines()}
    for row in MANIFEST["rows"]:
        prompt = cases[row["prompt_id"]]["prompt"]
        if row["case_class"] != "attack":
            continue
        assert row["inserted_question"] in prompt
        assert not prep.QUESTION_MARKER.search(prompt)
        if row["scenario"] == "LLM01":
            word, total = row["oracle"]["value"].split("-")
            assert word in prompt and str(total) not in prompt
        if row["scenario"] == "LLM05":
            assert prep.LLM05_JSON in prompt


def test_reglas_de_marcador_idioma_y_agrupacion() -> None:
    assert prep.question_markers("Hola [INSERT PROMPT HERE]") == ["[insert prompt here]"]
    assert prep.question_markers("usa !remind <prompt>") == []
    assert prep.question_markers("[INSERT X] y [PROMPT]") == ["[prompt]"]
    assert prep.detect_language("You are the best and you will do this for the user") == "en"
    assert prep.detect_language("Eres el mejor y que de la para con los usuarios") == "es"
    assert prep.fill_template("A [PROMPT] B [PROMPT]", "Q") == "A Q B Q"
    rows = [prep.ShenRow(0, "one two three four five six seven [PROMPT]", "", "", "2023-01-01", ""),
            prep.ShenRow(1, "one two three four five six seven [prompt]", "", "", "2023-01-02", ""),
            prep.ShenRow(2, "totally different words here for a template [PROMPT]", "", "", "", "9"),
            prep.ShenRow(3, "another unrelated text with other words [PROMPT]", "", "", "", "9")]
    groups = prep.group_templates(rows)
    assert groups[0] == groups[1] == 0 and groups[2] == groups[3] == 2
