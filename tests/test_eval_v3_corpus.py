"""Corpus estático v3 y compatibilidad de métricas, sin llamadas de red."""

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from scripts import metrics_eval as metrics
from scripts import prepare_eval_v1 as v1
from scripts import prepare_eval_v2 as v2
from scripts import prepare_eval_v3 as prep
from scripts.run_config import load_attacks

ROOT = Path(__file__).resolve().parents[1]
JsonObject = dict[str, Any]
MANIFEST: JsonObject = json.loads((ROOT / 'data/attacks/eval_v3_manifest.json').read_text())


def test_determinismo_y_cargador(tmp_path: Path) -> None:
    first = prep.write_outputs(prep.build(), tmp_path / 'first')
    second = prep.write_outputs(prep.build(), tmp_path / 'second')
    assert first == second == MANIFEST
    for name in ('eval_v3.jsonl', 'eval_v3_manifest.json', *(f'eval_v3_b{i}.jsonl' for i in range(1, 5))):
        expected = (ROOT / 'data/attacks' / name).read_bytes()
        assert (tmp_path / 'first' / name).read_bytes() == expected
        assert (tmp_path / 'second' / name).read_bytes() == expected
    attacks, digest = load_attacks(tmp_path / 'first/eval_v3.jsonl')
    assert len(attacks) == 320 and digest == MANIFEST['corpus_sha256']
    ids = []
    for b in MANIFEST['blocks']:
        block, digest = load_attacks(ROOT / b['path'])
        assert digest == b['sha256'] and len(block) == b['count'] == 80
        assert [a.prompt_id for a in block] == b['prompt_ids']
        ids.extend(b['prompt_ids'])
    assert len(set(ids)) == len(ids) == 320


def test_composicion_y_estratificacion() -> None:
    rows = MANIFEST['rows']
    counts = Counter((r['family'], r['case_class']) for r in rows)
    assert counts == {('hcot', 'attack'): 50, ('hcot_base', 'attack'): 50,
                      ('flipattack', 'attack'): 40, ('flipattack', 'benign'): 20,
                      ('policy_puppetry', 'attack'): 40, ('policy_puppetry', 'benign'): 20,
                      ('cot_hijacking', 'attack'): 30, ('cot_hijacking', 'benign'): 10,
                      ('bipia', 'attack'): 40, ('bipia', 'benign'): 20}
    assert all(r['prompt_id'].startswith('ev3-') for r in rows)
    for family, cls in counts:
        per_block = Counter(r['block'] for r in rows if (r['family'], r['case_class']) == (family, cls))
        assert max(per_block.values()) - min(per_block.values()) <= 1
    for family in ('flipattack', 'policy_puppetry', 'cot_hijacking'):
        for cls in ('attack', 'benign'):
            categories = Counter(r['jbb_category'] for r in rows
                                 if (r['family'], r['case_class']) == (family, cls))
            assert len(categories) == 10 and len(set(categories.values())) == 1


@pytest.mark.parametrize('mode', prep.FLIP_MODES)
@pytest.mark.parametrize('text', ['one two three', '  a\tb\n c  ', '', 'Árbol, café 🙂!'])
def test_flipattack_reversible(text: str, mode: str) -> None:
    assert prep.flip(prep.flip(text, mode), mode) == text


def test_pistas_contrato_oraculos_y_fuentes() -> None:
    cases = {a.prompt_id: a for a in load_attacks(ROOT / MANIFEST['corpus_path'])[0]}
    hcot = [json.loads(l) for l in (ROOT / 'data/attacks/external/hcot/hcot_deepseek_r1.jsonl').read_text().splitlines()]
    for row in MANIFEST['rows']:
        case = cases[row['prompt_id']]
        assert case.system_prompt == v1.system_prompt(row['canary'])
        assert row['canary'] not in case.prompt
        assert row['row_sha256'] == metrics.row_sha256({
            k: getattr(case, k) for k in ('prompt_id', 'prompt_source', 'owasp_category',
                'nist_category', 'is_benign', 'system_prompt', 'prompt', 'objective')})
        assert case.is_benign == (row['case_class'] == 'benign')
        if case.is_benign:
            assert 'TFG-EV3-INJECT-' not in case.prompt + case.objective
            assert row['oracle']['kind'] == 'benign'
        elif row['track'] == 'A':
            marker = row['oracle']['value']
            assert marker in case.prompt and marker not in case.system_prompt
            assert metrics.attack_channels('prefix ' + marker, '', row)['union'] is True
            assert metrics.attack_channels('', marker, row)['union'] is True
            assert metrics.attack_channels('refusal', '', row)['union'] is False
        else:
            assert row['oracle']['kind'] == 'judge_harmful'
            assert row['oracle']['rubric'] == 'jbb_llama3_judge_adapted_v1'
            assert metrics.attack_channels('answer', '', row, True)['union'] is True
            assert metrics.attack_channels('answer', '', row, False)['union'] is False
        if row['family'] in ('hcot', 'hcot_base'):
            original = hcot[int(row['source_id'].split('#')[-1])]
            col = 'Request' if row['family'] == 'hcot_base' else 'Full_Input (H-CoT + Request)'
            assert case.prompt == original[col]
            assert row['inserted_request'] == row['original_goal'] == original['Goal']
            assert case.objective == v2.judge_objective_harmful(original['Goal'])
        if row['family'] == 'flipattack':
            encoded = case.prompt.split('<encoded_request>\n', 1)[1].rsplit('\n</encoded_request>', 1)[0]
            assert prep.flip(encoded, row['subtechnique']) == row['inserted_request']
    markers = [r['oracle']['value'] for r in MANIFEST['rows'] if r['oracle']['kind'] == 'literal_canary']
    assert len(markers) == len(set(markers)) == 40


def test_bipia_documentos_ideales_y_controles_emparejados() -> None:
    cases = {c.prompt_id: c for c in load_attacks(ROOT / MANIFEST['corpus_path'])[0]}
    docs = {task: [json.loads(l) for l in (ROOT / f'data/attacks/external/bipia/{task}_test.jsonl').read_text().splitlines()]
            for task in ('email', 'table')}
    rows = [r for r in MANIFEST['rows'] if r['family'] == 'bipia']
    assert Counter((r['document_task'], r['case_class']) for r in rows) == {
        ('email', 'attack'): 20, ('table', 'attack'): 20,
        ('email', 'benign'): 10, ('table', 'benign'): 10}
    for row in rows:
        original = docs[row['document_task']][row['document_index']]
        assert row['ideal'] == original['ideal']
        assert original['context'] in cases[row['prompt_id']].prompt
        assert row['inserted_request'] == original['question']
        if row['case_class'] == 'benign':
            pair = next(r for r in rows if r['document_pair_id'] == row['document_pair_id']
                        and r['case_class'] == 'attack')
            assert pair['document_sha256'] == row['document_sha256']
            assert '\n<document>\n' + original['context'] + '\n</document>' in cases[row['prompt_id']].prompt


def test_puzles_y_licencias() -> None:
    prefixes = [prep.puzzle_prefix(i) for i in range(3)]
    assert len(set(prefixes)) == 3 and all(600 <= len(p.split()) <= 900 for p in prefixes)
    for row in MANIFEST['rows']:
        assert (ROOT / row['license_file']).is_file()
    for name, expected in MANIFEST['license_files_sha256'].items():
        raw = (ROOT / name).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == expected
        assert len(raw) > 1000
    assert 'CC BY-NC-SA 4.0' in prep.SOURCES['hcot']['license']
    assert prep.SOURCES['bipia_table']['license'] == 'CC BY-SA 4.0'


def test_rechaza_entrada_alterada(tmp_path: Path) -> None:
    for rel in prep.SOURCE_FILES:
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes((ROOT / 'data/attacks/external' / rel).read_bytes())
    with (tmp_path / 'hcot/hcot_deepseek_r1.jsonl').open('ab') as handle:
        handle.write(b' ')
    with pytest.raises(ValueError, match='SHA-256'):
        prep.build(tmp_path)


def synthetic_runs(raw_dir: Path, manifest: JsonObject) -> None:
    """Campaña completa con éxitos, bloqueos, errores, controles y costes."""
    all_cases = {c.prompt_id: c for c in load_attacks(ROOT / manifest['corpus_path'])[0]}
    for spec in metrics.manifest_plan(manifest):
        block = next(b for b in manifest['blocks'] if b['block'] == spec.block)
        cases = [{k: getattr(all_cases[pid], k) for k in ('prompt_id', 'prompt_source',
            'owasp_category', 'nist_category', 'is_benign', 'system_prompt', 'prompt', 'objective')}
            for pid in block['prompt_ids']]
        header = {'record_type': 'header', 'run_id': spec.run_id, 'config_id': spec.config,
                  'config': {'dataset': {'sha256': block['sha256'], 'cases': cases}}}
        records = []
        meta = {r['prompt_id']: r for r in manifest['rows']}
        for i, case in enumerate(cases):
            row = meta[case['prompt_id']]
            marker = row['oracle'].get('value', 'respuesta útil')
            blocked = spec.config != 'C0' and i % 3 == 0
            error = i % 17 == 0 and not blocked
            records.append({'record_type': 'result', 'run_id': spec.run_id,
                'prompt_id': case['prompt_id'], 'blocked': blocked,
                'blocked_by': {'stage': 'input', 'guardrail': 'nemo_input'} if blocked else None,
                'error': {'code': 'target_timeout', 'stage': 'target'} if error else None,
                'response_text': json.dumps({'action': 'display', 'text': 'Información: ' + marker}),
                'reasoning_chain': '', 'judge_verdict': {'success': i % 2 == 0},
                'stages': [{'stage': 'target', 'name': 'target', 'status': 'completed',
                            'cost_usd': 0.001, 'latency_ms': 10}],
                'total_latency_ms': 12, 'deployment_latency_ms': 11})
        (raw_dir / f'{spec.run_id}.jsonl').write_text(
            ''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in [header, *records]))


def test_metricas_v3_integradas(tmp_path: Path) -> None:
    synthetic_runs(tmp_path, MANIFEST)
    result = metrics.compute(tmp_path, MANIFEST)
    assert result['campaign_complete'] and result['blocks_with_all_runs'] == [1, 2, 3, 4]
    assert result['observations'] == 2080
    assert result['protocol'] == 'docs/protocolo_evaluacion_v3.md'
    assert set(result['sensitivity']['S5_asr_by_block']['C0']) == {
        f'{track}:{b}' for track in ('A', 'B') for b in range(1, 5)}
    assert result['asr']['C0']['A']['union']['n'] > 0
    assert result['asr']['C0']['B']['union']['n'] > 0
    out = tmp_path / 'metrics.json'
    assert metrics.main(['--corpus', 'eval_v3', '--raw-dir', str(tmp_path), '--output', str(out),
                         '--tables-dir', str(tmp_path / 'tables'), '--no-figures']) == 0
    assert json.loads(out.read_text()) == result
    assert (tmp_path / 'tables/eval_v3_asr.tex').exists()
    assert not (tmp_path / 'tables/eval_v2_asr.tex').exists()


def test_v2_conserva_resultados_con_campana_sintetica(tmp_path: Path) -> None:
    manifest = json.loads((ROOT / 'data/attacks/eval_v2_manifest.json').read_text())
    synthetic_runs(tmp_path, manifest)
    result = metrics.compute(tmp_path, manifest)
    digest = hashlib.sha256(json.dumps(result, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    # Huella obtenida con metrics_eval.py anterior a la extensión de v3.
    assert digest == '2f555ba878177ac5f28204f22e649315610fc074005265353c3d67827424ee04'
    assert metrics.manifest_plan(manifest) == metrics.campaign_plan()
