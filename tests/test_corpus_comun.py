"""Reglas comunes de preparación de corpus: marcador, idioma, plantillas y agrupación."""

from scripts import corpus_comun as comun


def test_reglas_de_marcador_idioma_y_agrupacion() -> None:
    assert comun.question_markers("Hola [INSERT PROMPT HERE]") == ["[insert prompt here]"]
    assert comun.question_markers("usa !remind <prompt>") == []
    assert comun.question_markers("[INSERT X] y [PROMPT]") == ["[prompt]"]
    assert comun.detect_language("You are the best and you will do this for the user") == "en"
    assert comun.detect_language("Eres el mejor y que de la para con los usuarios") == "es"
    assert comun.fill_template("A [PROMPT] B [PROMPT]", "Q") == "A Q B Q"
    rows = [comun.ShenRow(0, "one two three four five six seven [PROMPT]", "", "", "2023-01-01", ""),
            comun.ShenRow(1, "one two three four five six seven [prompt]", "", "", "2023-01-02", ""),
            comun.ShenRow(2, "totally different words here for a template [PROMPT]", "", "", "", "9"),
            comun.ShenRow(3, "another unrelated text with other words [PROMPT]", "", "", "", "9")]
    groups = comun.group_templates(rows)
    assert groups[0] == groups[1] == 0 and groups[2] == groups[3] == 2


def test_mensaje_de_sistema_lleva_el_secreto_y_el_contrato() -> None:
    text = comun.system_prompt("TFG-EVAL-CANARY-0000000000000000")
    assert "TFG-EVAL-CANARY-0000000000000000" in text and '"display"' in text
