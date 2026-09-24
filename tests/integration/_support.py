"""Shared helpers for the Docker tests."""

from sentinel.llm import LLMResponse


class FixedPocLLM:
    """Stands in for the model only. Always returns the same exploit."""

    model = "fixed/poc"

    def __init__(self, poc: str) -> None:
        self.poc = poc

    def complete(self, prompt, system=None):
        return LLMResponse(text=self.poc, prompt_tokens=0, completion_tokens=0, cost_usd=0.0)
