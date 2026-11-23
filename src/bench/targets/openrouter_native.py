"""C1, C4 y C5: llama a DeepSeek-R1 con la clave que lleva el filtro de inyección de OpenRouter."""

import json
import hashlib
import os
from pathlib import Path

from bench.core.schema import GuardDecision, GuardrailBlocked, Stage, StageError, TargetResponse
from bench.openrouter import OpenRouterClient
from bench.targets.openrouter import OpenRouterTarget

BLOCK_MESSAGE = "Request blocked: prompt injection patterns detected"
NATIVE_NAME = "openrouter-native-regex"
ROOT = Path(__file__).resolve().parents[3]


class NativeGuardedTarget(OpenRouterTarget):
    """Reconoce solo el rechazo específico del detector remoto de inyección."""

    native_policy: dict[str, str]

    def generate(self, prompt: str) -> TargetResponse:
        """Hace una sola petición al objetivo; otro 403 permanece como error."""
        return self.generate_messages([{"role": "user", "content": prompt}])

    def generate_messages(self, messages: list[dict[str, str]]) -> TargetResponse:
        """Reconoce también el bloqueo remoto de una conversación."""
        try:
            return super().generate_messages(messages)
        except StageError as exc:
            raw = exc.raw or {}
            error = raw.get("error", {})
            message = error.get("message") if isinstance(error, dict) else None
            if exc.code != "http_403" or not isinstance(message, str) or BLOCK_MESSAGE not in message:
                raise
            raise GuardrailBlocked(NATIVE_NAME, Stage.INPUT, GuardDecision(
                True, BLOCK_MESSAGE, raw, exc.latency_ms or 0.0, exc.cost_usd,
                exc.provider, exc.attempts, exc.attempt_history, exc.wall_latency_ms,
            )) from exc


def native_target(client: OpenRouterClient, model: str, provider: str,
                  system_prompt: str, seed: int) -> NativeGuardedTarget:
    """Exige credencial aislada y ficha de activación; jamás modifica la cuenta."""
    key = os.getenv("OPENROUTER_NATIVE_API_KEY", "").strip()
    if not key:
        raise ValueError("Falta OPENROUTER_NATIVE_API_KEY: C1, C4 y C5 necesitan una clave aislada del juez")
    if key == client.api_key:
        raise ValueError("La clave nativa no puede coincidir con la clave del juez/moderadores")
    path = Path(os.getenv("OPENROUTER_NATIVE_POLICY_FILE", "results/local/openrouter_native_policy.json"))
    if not path.is_absolute():
        path = ROOT / path
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError("Falta una ficha de política nativa verificada; consulta docs/openrouter_native.md") from exc
    required = {"policy_id", "verified_at", "scope", "action", "filter", "scan_scope",
                "positive_control_run", "base_key_control_run", "target_key_sha256", "base_key_sha256",
                "verification_run_file", "verification_run_sha256"}
    if (not isinstance(policy, dict) or not required.issubset(policy)
        or any(not isinstance(policy[k], str) or not policy[k].strip() for k in required)
        or policy["scope"] != "target_key_only" or policy["action"] != "block"
        or policy["filter"] != "regex-prompt-injection" or policy["scan_scope"] != "user_only"):
        raise ValueError("Ficha nativa incompleta: se requieren ámbito de clave y controles reales")
    if policy["target_key_sha256"] != hashlib.sha256(key.encode()).hexdigest():
        raise ValueError("La ficha de política corresponde a otra clave del objetivo")
    if policy["base_key_sha256"] != hashlib.sha256(client.api_key.encode()).hexdigest():
        raise ValueError("La ficha de política corresponde a otra clave base del juez")
    try:
        proof_path = Path(policy["verification_run_file"])
        if not proof_path.is_absolute():
            proof_path = ROOT / proof_path
        proof_bytes = proof_path.read_bytes()
        proof = json.loads(proof_bytes)
        observations = proof["observations"]
        expected = [("base", "benign", "completed"), ("base", "injection", "completed"),
                    ("native", "benign", "completed"), ("native", "injection", "native_block")]
        actual = [(r["key_role"], r["control"], r["status"]) for r in observations]
        if (hashlib.sha256(proof_bytes).hexdigest() != policy["verification_run_sha256"]
            or actual != expected or proof.get("passed") is not True
            or proof.get("policy_id") != policy["policy_id"]
            or proof.get("key_sha256") != {"base": policy["base_key_sha256"], "native": policy["target_key_sha256"]}
            or proof.get("run_id") != policy["positive_control_run"]
            or proof.get("run_id") != policy["base_key_control_run"]):
            raise ValueError("Evidencia diferencial incoherente")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ValueError("Falta evidencia íntegra de activación diferencial de C1") from exc
    guarded_client = OpenRouterClient(
        client.http, key, max_retries=client.max_retries,
        retry_base_delay=client.retry_base_delay, requests_per_second=client.requests_per_second,
        sleep_fn=client.sleep_fn, monotonic_fn=client.monotonic_fn,
        pace_fn=client._pace,
    )
    target = NativeGuardedTarget(guarded_client, model, provider, system_prompt, seed)
    # Metadatos locales de auditoría: no son parámetros de inferencia.
    target.native_policy = {k: policy[k] for k in sorted(required)}
    return target
