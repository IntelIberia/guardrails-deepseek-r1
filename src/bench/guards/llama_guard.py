"""C3: clasifica la entrada y cada canal de salida con Llama Guard 4 a través de OpenRouter."""

import re
from time import perf_counter

from bench.core.config import GuardSpec
from bench.core.schema import GuardDecision, JsonObject, Stage, StageError
from bench.openrouter import OpenRouterClient, routing

MODEL = "meta-llama/llama-guard-4-12b"
POLICY = "native_s1_s14"
_UNSAFE = re.compile(r"unsafe\n(S(?:[1-9]|1[0-4])(?:,[ \t]*S(?:[1-9]|1[0-4]))*)\Z")


def parse_assessment(text: object) -> tuple[bool, list[str]]:
    """Acepta únicamente las dos formas de clasificación documentadas por Meta."""
    if not isinstance(text, str):
        raise ValueError("Clasificación de Llama Guard ausente")
    normalized = text.strip().replace("\r\n", "\n")
    if normalized == "safe":
        return False, []
    match = _UNSAFE.fullmatch(normalized)
    if match is None:
        raise ValueError("Clasificación de Llama Guard no válida")
    categories = [item.strip() for item in match.group(1).split(",")]
    if len(set(categories)) != len(categories):
        raise ValueError("Categorías duplicadas en la clasificación")
    return True, categories


def _sum_known(calls: list[JsonObject], field: str) -> float | None:
    """No presenta una suma completa si falta el dato de alguna llamada."""
    values = [call[field] for call in calls]
    return None if any(value is None for value in values) else float(sum(values))


class LlamaGuard:
    """Aplica la política nativa; una canaria no se redefine como dato personal."""

    def __init__(
        self, client: OpenRouterClient, name: str, stages: frozenset[Stage],
        provider: str, seed: int, max_tokens: int = 128,
    ) -> None:
        self.client = client
        self.name = name
        self.stages = stages
        self.params: JsonObject = {
            "model": MODEL, "provider": routing(provider), "temperature": 0,
            "seed": seed, "max_tokens": max_tokens, "stream": False,
            "usage": {"include": True},
        }

    def check(self, text: str, stage: Stage, context: JsonObject) -> GuardDecision:
        """Clasifica los canales en orden y devuelve el primer bloqueo confirmado.

        Conserva el gasto de las llamadas ya hechas incluso si falla una.
        """
        if stage not in self.stages:
            raise ValueError("Etapa no declarada para Llama Guard")
        if stage is Stage.INPUT:
            channels = [("input_text", text)]
            user_text = text
        else:
            input_value = context.get("input_text")
            if not isinstance(input_value, str):
                raise ValueError("Llama Guard de salida requiere input_text")
            user_text = input_value
            channels = []
            for field in ("response_text", "reasoning_chain"):
                value = context.get(field)
                if value is not None and not isinstance(value, str):
                    raise ValueError(f"{field} debe ser texto o null")
                if value:
                    channels.append((field, value))
            if not channels:
                raise ValueError("Llama Guard de salida requiere al menos un canal de texto")

        started = perf_counter()
        calls: list[JsonObject] = []
        raw: JsonObject = {
            "policy": POLICY, "template": "provider_native_chat",
            "params": self.params, "calls": calls,
            "channel_order": [field for field, _ in channels],
        }

        def history() -> list[JsonObject]:
            return [
                {**attempt, "channel": call["channel"]}
                for call in calls for attempt in (call["attempt_history"] or [])
            ]

        for channel, content in channels:
            messages = [{"role": "user", "content": user_text}]
            if stage is Stage.OUTPUT:
                messages.append({"role": "assistant", "content": content})
            # El transporte ya retira la clave de las respuestas. Los mensajes
            # añadidos por este adaptador al registro necesitan la misma retirada.
            logged_messages = [
                {"role": message["role"],
                 "content": message["content"].replace(self.client.api_key, "[REDACTED]")}
                for message in messages
            ]
            try:
                completion = self.client.chat({**self.params, "messages": messages})
                choice = completion.choice()
                if choice["message"].get("refusal"):
                    raise completion.error("llama_guard_refused")
                if choice.get("finish_reason") != "stop":
                    raise completion.error("llama_guard_incomplete")
                try:
                    blocked, categories = parse_assessment(choice["message"].get("content"))
                except ValueError as exc:
                    raise completion.error("llama_guard_invalid_output") from exc
            except StageError as exc:
                calls.append({
                    "channel": channel, "status": "error", "error": exc.code,
                    "messages": logged_messages, "raw": exc.raw, "provider": exc.provider,
                    "cost_usd": exc.cost_usd, "latency_ms": exc.latency_ms,
                    "wall_latency_ms": exc.wall_latency_ms, "attempts": exc.attempts,
                    "attempt_history": exc.attempt_history,
                })
                raise StageError(
                    exc.code, raw, _sum_known(calls, "latency_ms"),
                    _sum_known(calls, "cost_usd"), exc.provider,
                    sum(call["attempts"] for call in calls), history(),
                    (perf_counter() - started) * 1000,
                ) from exc
            calls.append({
                "channel": channel, "status": "completed", "blocked": blocked,
                "categories": categories, "messages": logged_messages, "raw": completion.raw,
                "provider": completion.provider, "cost_usd": completion.cost_usd,
                "latency_ms": completion.latency_ms,
                "wall_latency_ms": completion.wall_latency_ms,
                "attempts": completion.attempts, "attempt_history": completion.attempt_history,
            })
            if blocked:
                # Un bloqueo confirmado es la decisión de la capa: no se arriesga a
                # que un fallo técnico en otro canal lo convierta en error.
                raw["channels_skipped_after_block"] = [
                    field for field, _ in channels[len(calls):]
                ]
                break

        blocked_calls = [call for call in calls if call["blocked"]]
        reason = "; ".join(
            f"{call['channel']}: {','.join(call['categories'])}" for call in blocked_calls
        ) or "safe según la política nativa S1–S14 en todos los canales evaluados"
        providers = {call["provider"] for call in calls}
        provider = next(iter(providers)) if len(providers) == 1 else None
        latency = _sum_known(calls, "latency_ms")
        assert latency is not None  # Todas las llamadas completadas aportan latencia.
        return GuardDecision(
            bool(blocked_calls), reason, raw, latency, _sum_known(calls, "cost_usd"),
            provider, sum(call["attempts"] for call in calls), history(),
            (perf_counter() - started) * 1000,
        )


def validate_llama_guard_spec(spec: GuardSpec) -> None:
    """Comprueba etapas y opciones sin cliente, credenciales ni tráfico de red."""
    if not spec.stages or any(stage not in {"input", "output"} for stage in spec.stages):
        raise ValueError("Llama Guard requiere etapas input/output")
    if len(spec.stages) != len(set(spec.stages)):
        raise ValueError("Llama Guard no admite etapas duplicadas")
    options = spec.options
    if options.keys() - {"model", "provider", "policy", "max_tokens"}:
        raise ValueError("Opciones desconocidas para Llama Guard")
    if options.get("model", MODEL) != MODEL:
        raise ValueError("Este adaptador implementa exclusivamente Llama Guard 4 12B")
    if options.get("policy", POLICY) != POLICY:
        raise ValueError("Este adaptador solo implementa la política native_s1_s14")
    provider = options.get("provider", "deepinfra")
    if not isinstance(provider, str) or not provider.strip() or provider != provider.strip():
        raise ValueError("provider debe ser un identificador no vacío")
    max_tokens = options.get("max_tokens", 128)
    if type(max_tokens) is not int or not 32 <= max_tokens <= 1024:
        raise ValueError("max_tokens debe ser entero entre 32 y 1024")


def build_llama_guard(spec: GuardSpec, client: OpenRouterClient, seed: int) -> LlamaGuard:
    """Construye el adaptador tras validar su declaración sin llamadas de red."""
    validate_llama_guard_spec(spec)
    options = spec.options
    return LlamaGuard(
        client, spec.name, frozenset(Stage(stage) for stage in spec.stages),
        options.get("provider", "deepinfra"), seed, options.get("max_tokens", 128),
    )
