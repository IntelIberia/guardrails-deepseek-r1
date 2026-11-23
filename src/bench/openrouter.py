"""Cliente de OpenRouter común a todas las fases: limita el ritmo, reintenta y registra
coste y tiempo.
"""

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from math import isfinite
from threading import Lock
from time import monotonic, perf_counter, sleep
from typing import Callable

import httpx

from bench.core.schema import JsonObject, StageError

API_URL = "https://openrouter.ai/api/v1"
METADATA_HEADER = {"X-OpenRouter-Experimental-Metadata": "enabled"}


def routing(provider_slug: str) -> JsonObject:
    """Limita el enrutamiento a un proveedor y exige los parámetros solicitados."""
    return {"only": [provider_slug], "allow_fallbacks": False, "require_parameters": True}


@dataclass(frozen=True)
class Completion:
    """Respuesta y metadatos observados en una llamada."""

    raw: JsonObject
    latency_ms: float
    attempts: int = 1
    cost_override: float | None = None
    cost_summary_known: bool = False
    attempt_history: list[JsonObject] | None = None
    wall_latency_ms: float | None = None

    @property
    def cost_usd(self) -> float | None:
        """Lee el coste informado por el servicio."""
        if self.cost_summary_known:
            return self.cost_override
        usage = self.raw.get("usage")
        cost = usage.get("cost") if isinstance(usage, dict) else None
        if (
            isinstance(cost, (int, float))
            and not isinstance(cost, bool)
            and isfinite(cost)
            and cost >= 0
        ):
            return float(cost)
        return None

    @property
    def provider(self) -> str | None:
        """Identifica al proveedor declarado en la respuesta."""
        provider = self.raw.get("provider")
        return provider if isinstance(provider, str) else None

    def error(self, code: str) -> StageError:
        """Adjunta la evidencia disponible al fallo de la etapa."""
        return StageError(
            code, self.raw, self.latency_ms, self.cost_usd, self.provider,
            self.attempts, self.attempt_history, self.wall_latency_ms,
        )

    def choice(self) -> JsonObject:
        """Devuelve la primera elección de una respuesta de chat válida."""
        choices = self.raw.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            raise self.error("invalid_completion")
        choice: JsonObject = choices[0]
        if not isinstance(choice.get("message"), dict):
            raise self.error("invalid_completion")
        return choice


class OpenRouterClient:
    """Envía peticiones y evita que la credencial se propague a los registros."""

    def __init__(
        self,
        http: httpx.Client,
        api_key: str,
        *,
        max_retries: int = 3,
        retry_base_delay: float = 1.0,
        requests_per_second: float = 1.0,
        sleep_fn: Callable[[float], None] = sleep,
        monotonic_fn: Callable[[], float] = monotonic,
        pace_fn: Callable[[], None] | None = None,
    ) -> None:
        if max_retries < 0:
            raise ValueError("max_retries no puede ser negativo")
        if retry_base_delay < 0 or not isfinite(retry_base_delay):
            raise ValueError("retry_base_delay debe ser finito y no negativo")
        if requests_per_second <= 0 or not isfinite(requests_per_second):
            raise ValueError("requests_per_second debe ser finito y mayor que cero")
        self.http = http
        self.api_key = api_key
        self.max_retries = max_retries
        self.retry_base_delay = retry_base_delay
        self.requests_per_second = requests_per_second
        self.sleep_fn = sleep_fn
        self.monotonic_fn = monotonic_fn
        self._shared_pace = pace_fn
        self._pace_lock = Lock()
        self._next_request_at = 0.0

    def _pace(self) -> None:
        """Asigna turnos globales para limitar también las llamadas concurrentes."""
        if self._shared_pace is not None:
            self._shared_pace()
            return
        interval = 1.0 / self.requests_per_second
        with self._pace_lock:
            now = self.monotonic_fn()
            scheduled = max(now, self._next_request_at)
            self._next_request_at = scheduled + interval
        delay = scheduled - now
        if delay > 0:
            self.sleep_fn(delay)

    @staticmethod
    def _retry_after(response: httpx.Response) -> float | None:
        """Interpreta Retry-After como segundos o fecha HTTP."""
        value = response.headers.get("Retry-After")
        if value is None:
            return None
        try:
            seconds = float(value)
        except ValueError:
            try:
                timestamp = parsedate_to_datetime(value)
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=timezone.utc)
                seconds = (timestamp - datetime.now(timezone.utc)).total_seconds()
            except (TypeError, ValueError, OverflowError):
                return None
        return max(0.0, seconds) if isfinite(seconds) else None

    def chat(self, payload: JsonObject) -> Completion:
        """Ejecuta una llamada de chat con metadatos de enrutamiento."""
        started = perf_counter()
        accumulated_cost = 0.0
        all_costs_known = True
        attempts = 0
        request_latency_ms = 0.0
        attempt_history: list[JsonObject] = []
        for retry_index in range(self.max_retries + 1):
            attempts += 1
            self._pace()
            request_started = perf_counter()
            try:
                response = self.http.post(
                    f"{API_URL}/chat/completions",
                    json=payload,
                    headers={
                        **METADATA_HEADER,
                        "Authorization": f"Bearer {self.api_key}",
                    },
                )
            except httpx.RequestError as exc:
                elapsed_request_ms = (perf_counter() - request_started) * 1000
                request_latency_ms += elapsed_request_ms
                if retry_index < self.max_retries:
                    delay = min(self.retry_base_delay * (2**retry_index), 30.0)
                    attempt_history.append({
                        "attempt": attempts, "http_status": None,
                        "error": "transport_error", "cost_usd": None,
                        "latency_ms": elapsed_request_ms,
                        "retry_delay_seconds": delay,
                    })
                    all_costs_known = False
                    self.sleep_fn(delay)
                    continue
                attempt_history.append({
                    "attempt": attempts, "http_status": None,
                    "error": "transport_error", "cost_usd": None,
                    "latency_ms": elapsed_request_ms,
                    "retry_delay_seconds": None,
                })
                all_costs_known = False
                raise StageError(
                    "transport_error", latency_ms=request_latency_ms,
                    attempts=attempts, attempt_history=attempt_history,
                    wall_latency_ms=(perf_counter() - started) * 1000,
                ) from exc

            elapsed_request_ms = (perf_counter() - request_started) * 1000
            request_latency_ms += elapsed_request_ms

            try:
                parsed = response.json()
            except ValueError:
                parsed = None

            raw: JsonObject = {}
            if isinstance(parsed, dict):
                # Normaliza las secuencias de escape antes de retirar la credencial.
                try:
                    serialized = json.dumps(parsed, allow_nan=False)
                except ValueError:
                    serialized = "{}"
                raw = json.loads(serialized.replace(self.api_key, "[REDACTED]"))

            one_cost = Completion(raw, 0.0).cost_usd
            if one_cost is not None:
                accumulated_cost += one_cost
            else:
                all_costs_known = False
            retryable = response.status_code == 429 or 500 <= response.status_code <= 599
            if retryable and retry_index < self.max_retries:
                retry_after = self._retry_after(response)
                backoff = min(self.retry_base_delay * (2**retry_index), 30.0)
                delay = max(backoff, retry_after or 0.0)
                attempt_history.append({
                    "attempt": attempts, "http_status": response.status_code,
                    "error": f"http_{response.status_code}", "cost_usd": one_cost,
                    "latency_ms": elapsed_request_ms,
                    "retry_after_seconds": retry_after,
                    "retry_delay_seconds": delay,
                })
                self.sleep_fn(delay)
                continue

            attempt_history.append({
                "attempt": attempts, "http_status": response.status_code,
                "error": None if response.is_success else f"http_{response.status_code}",
                "cost_usd": one_cost, "latency_ms": elapsed_request_ms,
                "retry_after_seconds": self._retry_after(response),
                "retry_delay_seconds": None,
            })
            wall_latency_ms = (perf_counter() - started) * 1000
            cost_override = accumulated_cost if all_costs_known else None
            completion = Completion(
                raw, request_latency_ms, attempts, cost_override, True,
                attempt_history, wall_latency_ms,
            )
            if not response.is_success:
                raise completion.error(f"http_{response.status_code}")
            if "error" in raw:
                raise completion.error("api_error")
            if not raw:
                raise completion.error("invalid_response")
            return completion

        raise AssertionError("bucle de reintentos agotado sin resultado")


def available_providers(http: httpx.Client, model: str) -> list[str]:
    """Consulta el catálogo público sin credenciales ni llamadas de inferencia."""
    try:
        response = http.get(f"{API_URL}/models/{model}/endpoints")
        response.raise_for_status()
        endpoints = response.json()["data"]["endpoints"]
        if not isinstance(endpoints, list):
            raise TypeError("endpoints debe ser una lista")
        tags = [endpoint["tag"] for endpoint in endpoints]
        if any(not isinstance(tag, str) or not tag for tag in tags):
            raise ValueError("Proveedor sin identificador")
    except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
        raise StageError("endpoint_catalog_unavailable") from exc
    # La API etiqueta algunas variantes con la cuantización tras una barra,
    # mientras que `provider.only` acepta el slug del proveedor.
    return sorted({tag.split("/", 1)[0] for tag in tags})
