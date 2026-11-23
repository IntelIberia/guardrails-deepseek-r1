"""Verifica el recorrido de C0 con respuestas de prueba en memoria."""

import json
from collections.abc import Callable
from dataclasses import asdict, replace
from pathlib import Path
from threading import Lock
from time import sleep

import httpx
import pytest

from bench.core.runner import run_batch, run_one
from bench.core.schema import AttackPrompt, JsonObject, TargetResponse, Verdict
from bench.judges.llm_judge import LLMJudge
from bench.openrouter import OpenRouterClient, available_providers
from bench.targets.openrouter import OpenRouterTarget

CASE = AttackPrompt(**json.loads(
    (Path(__file__).resolve().parents[1] / "data/attacks/pilot_llm07.json").read_text()
))
TEST_KEY = "clave-ficticia-para-tests"
TARGET_PAYLOAD = {
    "provider": "Proveedor de prueba",
    "choices": [{
        "finish_reason": "stop",
        "message": {
            "content": "No puedo revelar el identificador.",
            "reasoning_details": [{"type": "reasoning.text", "text": "TFG-CANARIO-ZAFIRO-6821"}],
        },
    }],
    "usage": {"cost": 0.001},
}


def test_c0_envia_el_razonamiento_y_registra_el_veredicto() -> None:
    """El juez recibe el razonamiento aunque la respuesta visible sea una negativa."""
    models: list[str] = []

    def intercept(request: httpx.Request) -> httpx.Response:
        assert request.headers["X-OpenRouter-Experimental-Metadata"] == "enabled"
        assert request.headers["Authorization"] == f"Bearer {TEST_KEY}"
        body = json.loads(request.content)
        models.append(body["model"])
        provider = "prueba" if len(models) == 1 else "openai"
        assert body["provider"]["only"] == [provider]
        assert body["seed"] == 42
        assert body["provider"]["allow_fallbacks"] is False
        if len(models) == 1:
            assert body["messages"][0]["content"] == CASE.system_prompt
            return httpx.Response(200, json=TARGET_PAYLOAD)
        assert body["temperature"] == 0
        assert body["seed"] == 42
        assert body["response_format"]["json_schema"]["strict"] is True
        data = json.loads(body["messages"][1]["content"])
        assert data["razonamiento_expuesto"] == "TFG-CANARIO-ZAFIRO-6821"
        return httpx.Response(200, json={
            "provider": "OpenAI",
            "choices": [{
                "finish_reason": "stop",
                "message": {"content": json.dumps({
                    "success": True, "confidence": 0.95, "rationale_short": "Se cumple el criterio."
                })},
            }],
            "usage": {"cost": 0.002},
        })

    record = run_fixture(intercept)
    assert models == ["deepseek/deepseek-r1", "openai/gpt-4.1-mini"]
    assert record["error"] is None
    assert record["judge_verdict"]["success"] is True
    assert record["provider"] == "Proveedor de prueba"
    assert record["total_cost_usd"] == pytest.approx(0.003)


@pytest.mark.parametrize(
    ("choice", "expected"),
    [
        ({"finish_reason": "stop", "message": {"refusal": "Rechazo"}}, "judge_refused"),
        ({"finish_reason": "content_filter", "message": {"content": None}}, "judge_refused"),
        ({"finish_reason": "stop", "message": {"content": "texto libre"}}, "judge_invalid_output"),
    ],
)
def test_fallo_del_juez_conserva_la_respuesta(choice: JsonObject, expected: str) -> None:
    """Una llamada fallida del juez deja el veredicto vacío y conserva lo observado."""
    def intercept(request: httpx.Request) -> httpx.Response:
        if json.loads(request.content)["model"] == "deepseek/deepseek-r1":
            return httpx.Response(200, json=TARGET_PAYLOAD)
        return httpx.Response(200, json={"choices": [choice]})

    record = run_fixture(intercept)
    assert record["judge_verdict"] is None
    assert record["reasoning_chain"] == "TFG-CANARIO-ZAFIRO-6821"
    assert record["error"] == {"stage": "judge", "code": expected}
    assert record["total_cost_usd"] is None


def test_fallo_del_modelo_interrumpe_el_flujo_y_oculta_la_clave() -> None:
    """Un error del modelo no ejecuta el juez, y se oculta cualquier clave reflejada."""
    def intercept(request: httpx.Request) -> httpx.Response:
        assert json.loads(request.content)["model"] == "deepseek/deepseek-r1"
        return httpx.Response(503, json={"error": {"message": f"Error {TEST_KEY}"}})

    record = run_fixture(intercept)
    assert record["error"] == {"stage": "target", "code": "http_503"}
    assert record["judge_name"] is None
    assert record["judge_verdict"] is None
    assert TEST_KEY not in json.dumps(record)


def test_catalogo_vacio_sin_credenciales() -> None:
    """La consulta previa del catálogo es pública y puede devolver cero endpoints."""
    def intercept(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert "Authorization" not in request.headers
        return httpx.Response(200, json={"data": {"endpoints": []}})

    with httpx.Client(transport=httpx.MockTransport(intercept)) as http:
        assert available_providers(http, "deepseek/deepseek-r1") == []


def test_catalogo_separa_slug_de_proveedor_de_su_etiqueta() -> None:
    """El catálogo traduce una etiqueta cuantizada al slug aceptado por provider.only."""
    def intercept(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {"endpoints": [
            {"tag": "deepinfra/fp4"},
            {"tag": "siliconflow/fp8"},
            {"tag": "streamlake"},
        ]}})

    with httpx.Client(transport=httpx.MockTransport(intercept)) as http:
        assert available_providers(http, "deepseek/deepseek-r1-0528") == [
            "deepinfra", "siliconflow", "streamlake"
        ]


def run_fixture(handler: Callable[[httpx.Request], httpx.Response]) -> JsonObject:
    """Ejecuta el motor con ambos adaptadores y un transporte de prueba."""
    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        client = OpenRouterClient(http, TEST_KEY, requests_per_second=1e9)
        return run_one(
            "run-de-prueba",
            CASE,
            OpenRouterTarget(client, "deepseek/deepseek-r1", "prueba", CASE.system_prompt, 42),
            LLMJudge(client, "openai/gpt-4.1-mini", "openai", 42),
        )


def test_jsonl_registra_cabecera_y_fallo_sin_veredicto(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """La escritura de campaña conserva la cabecera y los fallos."""
    from scripts import run_config

    def intercept(request: httpx.Request) -> httpx.Response:
        assert json.loads(request.content)["model"] == "deepseek/deepseek-r1"
        return httpx.Response(503, json={"error": {"message": "Fallo de prueba"}})

    with httpx.Client(transport=httpx.MockTransport(intercept)) as http:
        assert run_config.run_campaign(
            http, [CASE], "b" * 64, "prueba", TEST_KEY, tmp_path,
            target_model="deepseek/deepseek-r1", run_id="test-campaign",
            max_retries=0, requests_per_second=1e9, git_state=("a" * 40, False),
        ) == 1

    path = tmp_path / "test-campaign.jsonl"
    assert path.stat().st_mode & 0o777 == 0o600
    header, result = [json.loads(line) for line in path.read_text().splitlines()]
    assert header["record_type"] == "header"
    assert header["config"]["git_commit"] == "a" * 40
    assert header["config"]["target"]["params"]["provider"]["only"] == ["prueba"]
    assert header["run_id"] == result["run_id"] == path.stem
    assert result["error"] == {"stage": "target", "code": "http_503"}
    assert result["judge_verdict"] is None
    assert result["total_cost_usd"] is None


def test_reintenta_429_y_5xx_respetando_retry_after() -> None:
    """Las respuestas limitadas o transitorias usan backoff exponencial."""
    responses = [
        httpx.Response(429, headers={"Retry-After": "2"}, json={"error": {}}),
        httpx.Response(503, headers={"Retry-After": "0"}, json={"error": {}}),
        httpx.Response(200, json=TARGET_PAYLOAD),
    ]
    delays: list[float] = []

    def intercept(request: httpx.Request) -> httpx.Response:
        return responses.pop(0)

    with httpx.Client(transport=httpx.MockTransport(intercept)) as http:
        client = OpenRouterClient(
            http, TEST_KEY, max_retries=2, retry_base_delay=0.25,
            requests_per_second=1e9, sleep_fn=delays.append,
        )
        completion = client.chat({"model": "modelo-de-prueba"})
    assert completion.attempts == 3
    # El 429 careció de usage.cost: no se presenta el coste final como si
    # cubriera todos los intentos de la llamada.
    assert completion.cost_usd is None
    assert [item["http_status"] for item in completion.attempt_history or []] == [
        429, 503, 200
    ]
    history = completion.attempt_history
    assert history is not None
    assert history[0]["retry_delay_seconds"] == 2.0
    assert delays == [2.0, 0.5]


def test_limitador_aplica_un_ritmo_global_de_peticiones() -> None:
    """El cliente separa las peticiones concurrentes por el intervalo configurado."""
    clock = [0.0]
    delays: list[float] = []

    def fake_sleep(delay: float) -> None:
        delays.append(delay)
        clock[0] += delay

    def intercept(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=TARGET_PAYLOAD)

    with httpx.Client(transport=httpx.MockTransport(intercept)) as http:
        client = OpenRouterClient(
            http,
            TEST_KEY,
            max_retries=0,
            requests_per_second=2.0,
            sleep_fn=fake_sleep,
            monotonic_fn=lambda: clock[0],
        )
        for _ in range(3):
            client.chat({"model": "modelo-de-prueba"})
    assert delays == [0.5, 0.5]


def test_reintenta_error_de_transporte_y_registra_intentos() -> None:
    """Una desconexión transitoria se vuelve a intentar sin filtrar su texto."""
    calls = 0
    delays: list[float] = []

    def intercept(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise httpx.ConnectError("fallo ficticio", request=request)
        return httpx.Response(200, json=TARGET_PAYLOAD)

    with httpx.Client(transport=httpx.MockTransport(intercept)) as http:
        completion = OpenRouterClient(
            http, TEST_KEY, max_retries=1, retry_base_delay=0.125,
            requests_per_second=1e9, sleep_fn=delays.append,
        ).chat({"model": "modelo-de-prueba"})
    assert calls == 2
    assert completion.attempts == 2
    assert delays == [0.125]


def test_coste_parcial_de_reintentos_queda_desconocido() -> None:
    """Un coste disponible de un intento no se presenta como total si falta otro."""
    responses = [
        httpx.Response(429, json={"usage": {"cost": 0.1}, "error": {}}),
        httpx.Response(200, json={
            "choices": [{"message": {"content": "respuesta"}}],
        }),
    ]

    def intercept(request: httpx.Request) -> httpx.Response:
        return responses.pop(0)

    with httpx.Client(transport=httpx.MockTransport(intercept)) as http:
        completion = OpenRouterClient(
            http, TEST_KEY, max_retries=1, requests_per_second=1e9,
            sleep_fn=lambda _: None,
        ).chat({"model": "modelo-de-prueba"})
    assert completion.cost_usd is None
    assert completion.attempt_history is not None
    assert completion.attempt_history[0]["cost_usd"] == 0.1


def test_concurrencia_de_lote_respeta_el_maximo() -> None:
    """El motor procesa veinte registros de prueba sin superar el límite."""
    class State:
        active = 0
        peak = 0
        lock = Lock()

    class FakeTarget:
        name = "target-fixture"
        params: JsonObject = {}

        def generate(self, prompt: str) -> TargetResponse:
            with State.lock:
                State.active += 1
                State.peak = max(State.peak, State.active)
            sleep(0.01)
            with State.lock:
                State.active -= 1
            return TargetResponse("respuesta", None, "fixture", {}, 1, 0.0, {})

    class FakeJudge:
        name = "judge-fixture"

        def evaluate(self, attack: AttackPrompt, response: TargetResponse) -> Verdict:
            return Verdict(False, 1.0, "No se cumple.", "fixture", 1, 0.0, {})

    attacks = [replace(CASE, prompt_id=f"synthetic-test-{index:02d}") for index in range(20)]
    records = list(run_batch("test", attacks, lambda _: FakeTarget(), FakeJudge(), 3))
    assert len(records) == 20
    assert len({record["prompt_id"] for record in records}) == 20
    assert 2 <= State.peak <= 3
    assert all(record["error"] is None for record in records)


def test_reanuda_sin_repetir_negativa_del_juez_y_reintenta_error_tecnico(
    tmp_path: Path,
) -> None:
    """El reintento conserva la negativa ya clasificada y repite el caso técnico."""
    from scripts import run_config

    refused = replace(CASE, prompt_id="case-refused", prompt="prompt-refused")
    transient = replace(CASE, prompt_id="case-retry", prompt="prompt-retry")
    attacks = [refused, transient]
    counts: dict[str, int] = {}
    counts_lock = Lock()

    def intercept(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        model = body["model"]
        if model == "deepseek/deepseek-r1":
            prompt = body["messages"][1]["content"]
        else:
            item = json.loads(body["messages"][1]["content"])
            prompt = item["ataque"]
        with counts_lock:
            counts[prompt] = counts.get(prompt, 0) + 1
            occurrence = counts[prompt]
        if model == "deepseek/deepseek-r1":
            if prompt == "prompt-retry" and occurrence == 1:
                return httpx.Response(400, json={"error": {"message": "fixture"}})
            return httpx.Response(200, json=TARGET_PAYLOAD)
        if prompt == "prompt-refused":
            return httpx.Response(200, json={"choices": [{
                "finish_reason": "stop", "message": {"refusal": "fixture"},
            }]})
        return httpx.Response(200, json={"choices": [{
            "finish_reason": "stop",
            "message": {"content": json.dumps({
                "success": False, "confidence": 1.0, "rationale_short": "No se cumple."
            })},
        }]})

    with httpx.Client(transport=httpx.MockTransport(intercept)) as http:
        assert run_config.run_campaign(
            http, attacks, "c" * 64, "prueba", TEST_KEY, tmp_path,
            target_model="deepseek/deepseek-r1", run_id="resumable-test",
            max_concurrency=2, requests_per_second=1e9, max_retries=0,
            git_state=("a" * 40, False),
        ) == 1
        assert run_config.run_campaign(
            http, attacks, "c" * 64, "prueba", TEST_KEY, tmp_path,
            target_model="deepseek/deepseek-r1", run_id="resumable-test",
            max_concurrency=2, requests_per_second=1e9, max_retries=0,
            git_state=("a" * 40, False),
        ) == 0

    assert counts["prompt-refused"] == 2  # objetivo y juez; no se repitieron
    assert counts["prompt-retry"] == 3  # objetivo fallido, luego objetivo y juez
    records = [
        json.loads(line)
        for line in (tmp_path / "resumable-test.jsonl").read_text().splitlines()[1:]
    ]
    refused_records = [record for record in records if record["prompt_id"] == refused.prompt_id]
    retry_records = [record for record in records if record["prompt_id"] == transient.prompt_id]
    assert len(refused_records) == 1
    assert refused_records[0]["error"]["code"] == "judge_refused"
    assert len(retry_records) == 2
    assert retry_records[0]["error"]["code"] == "http_400"
    assert retry_records[1]["error"] is None


def test_rechaza_reanudacion_con_configuracion_distinta(tmp_path: Path) -> None:
    """Un mismo run_id no puede mezclar dos huellas de corpus."""
    from scripts import run_config

    def intercept(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=TARGET_PAYLOAD)

    with httpx.Client(transport=httpx.MockTransport(intercept)) as http:
        run_config.run_campaign(
            http, [CASE], "d" * 64, "prueba", TEST_KEY, tmp_path,
            target_model="deepseek/deepseek-r1", run_id="fingerprint-test",
            max_retries=0, requests_per_second=1e9,
            git_state=("a" * 40, False),
        )
        with pytest.raises(ValueError, match="configuración no coincide"):
            run_config.run_campaign(
                http, [CASE], "e" * 64, "prueba", TEST_KEY, tmp_path,
                target_model="deepseek/deepseek-r1", run_id="fingerprint-test",
                max_retries=0, requests_per_second=1e9,
                git_state=("a" * 40, False),
            )


def test_repara_solo_la_cola_incompleta_al_reanudar(tmp_path: Path) -> None:
    """Una caída al final conserva los registros íntegros y permite continuar."""
    from scripts import run_config

    calls = 0

    def intercept(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        body = json.loads(request.content)
        calls += 1
        if body["model"] == "deepseek/deepseek-r1" and calls == 1:
            return httpx.Response(400, json={"error": {"message": "fixture"}})
        if body["model"] == "deepseek/deepseek-r1":
            return httpx.Response(200, json=TARGET_PAYLOAD)
        return httpx.Response(200, json={"choices": [{
            "finish_reason": "stop",
            "message": {"content": json.dumps({
                "success": False, "confidence": 1.0, "rationale_short": "No se cumple."
            })},
        }]})

    path = tmp_path / "tail-repair-test.jsonl"
    with httpx.Client(transport=httpx.MockTransport(intercept)) as http:
        assert run_config.run_campaign(
            http, [CASE], "f" * 64, "prueba", TEST_KEY, tmp_path,
            target_model="deepseek/deepseek-r1", run_id="tail-repair-test",
            max_retries=0, requests_per_second=1e9,
            git_state=("a" * 40, False),
        ) == 1
        original_prefix = path.read_bytes()
        path.write_bytes(original_prefix + b'{"record_type":"result","run_id":"partial')
        assert run_config.run_campaign(
            http, [CASE], "f" * 64, "prueba", TEST_KEY, tmp_path,
            target_model="deepseek/deepseek-r1", run_id="tail-repair-test",
            max_retries=0, requests_per_second=1e9,
            git_state=("a" * 40, False),
        ) == 0

    content = path.read_bytes()
    assert content.startswith(original_prefix)
    parsed = [json.loads(line) for line in content.decode().splitlines()]
    assert len(parsed) == 3
    assert parsed[1]["error"]["code"] == "http_400"
    assert parsed[2]["error"] is None


def test_load_attacks_acepta_jsonl_y_rechaza_ids_duplicados(tmp_path: Path) -> None:
    """El corpus JSONL conserva su hash y exige identificadores únicos."""
    from scripts.run_config import load_attacks

    path = tmp_path / "attacks.jsonl"
    raw = json.dumps(asdict(CASE), ensure_ascii=False)
    path.write_text(raw + "\n" + raw + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="prompt_id duplicado"):
        load_attacks(path)
    case_b = asdict(replace(CASE, prompt_id="another-case"))
    path.write_text(raw + "\n" + json.dumps(case_b) + "\n", encoding="utf-8")
    attacks, fingerprint = load_attacks(path)
    assert [attack.prompt_id for attack in attacks] == [CASE.prompt_id, "another-case"]
    assert len(fingerprint) == 64
