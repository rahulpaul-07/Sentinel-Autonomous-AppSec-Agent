"""
sentinel/llm.py
----------------
The "model layer": the ONLY part of Sentinel that talks directly to an AI model.

Why isolate this in one file?
  - Every other part of Sentinel asks THIS module for AI help. Nothing else ever
    imports a vendor SDK directly.
  - So switching from Claude to GPT to a free local model is a ONE-LINE config
    change here, and the rest of the codebase never notices.
  - This is the "Adapter" pattern (a form of dependency inversion). It's exactly
    the kind of design choice interviewers ask you to justify.

Under the hood we use `litellm`, a library that speaks to 100+ providers through a
single function. We wrap it in our own small class so the rest of our code depends
on OUR clean interface, not on litellm's details.

Lazy imports
------------
`litellm` (and its ~40 transitive packages) is imported the first time a model call
actually happens, not when this module loads. That means importing the pieces built
ON TOP of this layer -- the HTML report renderer, the pure JSON parser, the metric
math -- costs nothing and needs nothing installed. Only code that truly calls a model
pulls in the SDK. Rendering a saved ScanReport to HTML shouldn't require an LLM SDK,
and now it doesn't.

Resilience
----------
Hosted providers fail transiently all the time: rate limits (429), capacity
spikes (503), dropped connections. A scan makes a dozen-plus model calls, so a
single blip used to abort the whole run and throw away every finding already
proven. `complete()` retries those errors with exponential backoff, honouring the
provider's own "retry in Ns" hint when it gives one. Errors that retrying cannot
fix -- a bad API key, an unknown model name -- still fail immediately, because
sleeping four times before reporting "invalid key" helps nobody.
"""

from __future__ import annotations

import logging
import os
import random
import re
import time
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Providers often say exactly how long to wait: "Please try again in 10.68s".
# Obeying that beats guessing.
_RETRY_HINT = re.compile(r"try again in ([\d.]+)\s*s", re.IGNORECASE)

MAX_BACKOFF_SECONDS = 60.0

_litellm = None  # cached module handle; imported on first real use
_env_loaded = False


def _get_litellm():
    """Import litellm once, quiet its noisy logging, and cache the handle."""
    global _litellm
    if _litellm is None:
        import litellm  # heavy import, deferred until an actual model call

        # litellm emits provider deprecation warnings on every call, which drown
        # out our own output. Keep errors, drop the noise.
        logging.getLogger("LiteLLM").setLevel(logging.ERROR)
        litellm.suppress_debug_info = True
        _litellm = litellm
    return _litellm


def _ensure_env() -> None:
    """Load a local .env into the environment once, if python-dotenv is present."""
    global _env_loaded
    if not _env_loaded:
        try:
            from dotenv import load_dotenv

            load_dotenv()
        except Exception:  # dotenv optional; env vars can be set another way
            pass
        _env_loaded = True


def _retryable_errors(litellm) -> tuple:
    """The transient failures worth retrying -- the same request may succeed later."""
    ex = litellm.exceptions
    return (
        ex.RateLimitError,           # 429 - too fast, or quota window
        ex.ServiceUnavailableError,  # 503 - provider overloaded
        ex.InternalServerError,      # 500 - provider hiccup
        ex.APIConnectionError,       # network dropped mid-flight
        ex.Timeout,                  # provider too slow to answer
    )


@dataclass
class LLMResponse:
    """A structured result from the model.

    We return a small object instead of a bare string so callers can also see how
    many tokens were used and what the call cost -- numbers useful for a
    'cost per finding' metric later.
    """
    text: str
    prompt_tokens: int
    completion_tokens: int
    cost_usd: float
    # Why the model stopped: "stop" for a finished reply, "length" when it hit its
    # token limit. Kept because an empty or cut-off reply is otherwise unexplainable.
    finish_reason: str = ""


class LLMClient:
    """A thin, provider-agnostic wrapper around an AI model.

    The rest of Sentinel only ever uses this class. Swap providers by changing the
    SENTINEL_MODEL value in your .env -- no code changes required.
    """

    def __init__(
        self,
        model: str | None = None,
        temperature: float = 0.0,
        max_retries: int = 4,
    ) -> None:
        _ensure_env()
        # If no model is passed in, read it from the environment (set in .env).
        # Examples: "claude-sonnet-5", "gpt-4o-mini", "ollama/llama3.2".
        self.model = model or os.getenv("SENTINEL_MODEL")
        if not self.model:
            raise ValueError(
                "No model configured. Set SENTINEL_MODEL in your .env file "
                "(e.g. SENTINEL_MODEL=ollama/llama3.2)."
            )

        # temperature 0.0 = focused and repeatable, which is what we want for
        # security analysis (consistency, not creativity).
        self.temperature = temperature

        # Four retries with backoff covers roughly a minute of provider trouble,
        # which is longer than most rate-limit windows.
        self.max_retries = max_retries

    # ------------------------------------------------------------------ helpers

    def _backoff_seconds(self, error: Exception, attempt: int) -> float:
        """How long to wait before retry number `attempt` (0-indexed).

        Prefer the provider's own hint. Otherwise exponential backoff -- 1s, 2s,
        4s, 8s -- plus a little random jitter so parallel callers don't all wake up
        and retry in the same instant.
        """
        hint = _RETRY_HINT.search(str(error))
        if hint:
            # Small cushion on top of the stated delay: their clock and ours differ.
            return min(float(hint.group(1)) + 0.5, MAX_BACKOFF_SECONDS)
        return min(2.0 ** attempt + random.uniform(0, 0.5), MAX_BACKOFF_SECONDS)

    # --------------------------------------------------------------- public API

    def complete(self, prompt: str, system: str | None = None) -> LLMResponse:
        """Send one prompt to the model and get a structured response back.

        `system` is an optional 'system prompt': high-level instructions that set
        the model's role, e.g. "You are a meticulous security analyst."

        Transient provider failures are retried with backoff. Anything else -- a
        bad key, an unknown model -- raises straight away.
        """
        litellm = _get_litellm()
        retryable = _retryable_errors(litellm)

        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        response = None
        for attempt in range(self.max_retries + 1):
            try:
                # One call litellm routes to whichever provider self.model names:
                #   "ollama/..." -> local, "claude-..." -> Anthropic, "groq/..." -> Groq
                response = litellm.completion(
                    model=self.model,
                    messages=messages,
                    temperature=self.temperature,
                )
                break
            except retryable as exc:
                if attempt == self.max_retries:
                    logger.error(
                        "Model call failed after %d retries: %s", self.max_retries, exc
                    )
                    raise
                delay = self._backoff_seconds(exc, attempt)
                logger.warning(
                    "Transient model error (%s). Retry %d/%d in %.1fs.",
                    type(exc).__name__, attempt + 1, self.max_retries, delay,
                )
                time.sleep(delay)

        if response is None:  # pragma: no cover - unreachable in normal flow
            raise RuntimeError("Model call returned no response.")

        choice = response.choices[0]
        text = choice.message.content or ""
        finish_reason = str(getattr(choice, "finish_reason", "") or "")

        usage = getattr(response, "usage", None)
        prompt_tokens = getattr(usage, "prompt_tokens", 0) if usage else 0
        completion_tokens = getattr(usage, "completion_tokens", 0) if usage else 0

        try:
            cost = litellm.completion_cost(completion_response=response)
        except Exception:
            cost = 0.0

        return LLMResponse(
            text=text,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            cost_usd=cost,
            finish_reason=finish_reason,
        )
