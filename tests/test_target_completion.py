"""Una generación truncada no es evidencia de respuesta segura."""

import httpx
import pytest

from bench.core.schema import StageError
from bench.openrouter import OpenRouterClient
from bench.targets.openrouter import OpenRouterTarget


@pytest.mark.parametrize("reason", ["length", "error", "content_filter", None])
def test_generacion_no_finalizada_no_se_juzga_como_segura(reason: str | None) -> None:
    """Conserva la respuesta parcial en el error y no produce un TargetResponse válido."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "choices": [{"finish_reason": reason, "message": {"content": "texto parcial"}}],
            "usage": {"cost": 0.01},
        })

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        target = OpenRouterTarget(OpenRouterClient(http, "fixture"), "modelo", "proveedor", "", 42)
        with pytest.raises(StageError, match="target_incomplete") as caught:
            target.generate("consulta")
    assert caught.value.cost_usd == 0.01
    assert caught.value.raw is not None
    assert caught.value.raw["choices"][0]["message"]["content"] == "texto parcial"
