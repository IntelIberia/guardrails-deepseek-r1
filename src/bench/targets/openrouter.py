"""C0, C2 y C3: llama a DeepSeek-R1 a través de OpenRouter."""

from bench.core.schema import JsonObject, TargetResponse
from bench.openrouter import OpenRouterClient, routing


class OpenRouterTarget:
    """Envía un caso al modelo con el proveedor fijado."""

    def __init__(
        self,
        client: OpenRouterClient,
        model: str,
        provider: str,
        system_prompt: str,
        seed: int,
    ) -> None:
        self.client = client
        self.name = model
        self.system_prompt = system_prompt
        self.params: JsonObject = {
            "stream": False,
            "provider": routing(provider),
            "reasoning": {"exclude": False},
            "usage": {"include": True},
            "seed": seed,
        }

    def generate(self, prompt: str) -> TargetResponse:
        """Recupera la respuesta final y el razonamiento expuesto."""
        return self.generate_messages([{"role": "user", "content": prompt}])

    def generate_messages(self, messages: list[dict[str, str]]) -> TargetResponse:
        """Genera con el historial visible, sin reenviar razonamiento interno."""
        completion = self.client.chat(
            {
                "model": self.name,
                "messages": [
                    {"role": "system", "content": self.system_prompt},
                    *messages,
                ],
                **self.params,
            }
        )
        choice = completion.choice()
        if choice.get("finish_reason") != "stop":
            raise completion.error("target_incomplete")
        message = choice["message"]
        text = message.get("content")
        reasoning = message.get("reasoning")
        if not isinstance(reasoning, str) or not reasoning:
            details = message.get("reasoning_details")
            if isinstance(details, list):
                pieces = [
                    item["text"]
                    for item in details
                    if isinstance(item, dict) and isinstance(item.get("text"), str)
                ]
                reasoning = "\n".join(pieces) or None
        text = text if isinstance(text, str) else None
        reasoning = reasoning if isinstance(reasoning, str) and reasoning else None
        if not text and not reasoning:
            raise completion.error("target_empty")
        return TargetResponse(
            text, reasoning, completion.provider, self.params,
            completion.latency_ms, completion.cost_usd, completion.raw,
            completion.attempts, completion.attempt_history,
            completion.wall_latency_ms,
        )
