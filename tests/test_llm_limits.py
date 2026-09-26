"""
How the model client treats a provider limit.

A 429 means two different things. A per-minute limit clears in seconds, and
waiting it out is right. A per-day limit clears in minutes or hours, and retrying
it only delays a failure. The provider says which in its own words -- "try again in
2.5s" versus "try again in 16m11.568s" -- but the hint parser only understood the
first form, so on a daily limit the client ignored the hint, retried four times in
fifteen seconds and then crashed. These tests drive the real client with only
litellm's network call replaced.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from sentinel import llm as llm_mod
from sentinel.llm import MAX_BACKOFF_SECONDS, QuotaExhausted, parse_retry_hint

GROQ_DAILY = (
    'GroqException - {"error":{"message":"Rate limit reached for model '
    '`openai/gpt-oss-120b` in organization `org_x` service tier `on_demand` on tokens '
    'per day (TPD): Limit 200000, Used 198583, Requested 3666. Please try again in '
    '16m11.568s. Need more tokens?","type":"tokens","code":"rate_limit_exceeded"}}'
)


# --- reading the provider's hint ---------------------------------------------------

@pytest.mark.parametrize("text, seconds", [
    ("Please try again in 2.5s.", 2.5),
    ("Please try again in 16m11.568s.", 16 * 60 + 11.568),
    ("Please try again in 9m30.24s", 9 * 60 + 30.24),
    ("try again in 1h2m3s", 3723),
    ("try again in 45m", 45 * 60),
    ("try again in 350ms", 0.35),
    ("Try Again In 3S", 3),
])
def test_hint_is_read_in_any_unit(text, seconds):
    assert parse_retry_hint(text) == pytest.approx(seconds)


@pytest.mark.parametrize("text", ["", "rate limited", "try again later", "try again in s"])
def test_no_hint_is_none(text):
    assert parse_retry_hint(text) is None


# --- the client -----------------------------------------------------------------------

class RateLimitError(Exception):
    pass


def _fake_litellm(errors, response=None):
    """Raise each error in turn, then return the response. Records every call."""
    calls = []

    def completion(**kwargs):
        calls.append(kwargs)
        if len(calls) <= len(errors):
            raise errors[len(calls) - 1]
        return response

    exc = {n: type(n, (Exception,), {}) for n in (
        "APIConnectionError", "Timeout", "ServiceUnavailableError", "InternalServerError")}
    exc["RateLimitError"] = RateLimitError
    return SimpleNamespace(completion=completion, completion_cost=lambda **kw: 0.0,
                           exceptions=SimpleNamespace(**exc)), calls


def _ok(prompt_tokens=100, completion_tokens=20):
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="ok"), finish_reason="stop")],
        usage=SimpleNamespace(prompt_tokens=prompt_tokens, completion_tokens=completion_tokens),
    )


@pytest.fixture
def client(monkeypatch):
    sleeps = []
    monkeypatch.setattr(llm_mod.time, "sleep", sleeps.append)
    monkeypatch.setenv("SENTINEL_MODEL", "stub/model")

    def make(errors, response=None):
        fake, calls = _fake_litellm(errors, response or _ok())
        monkeypatch.setattr(llm_mod, "_get_litellm", lambda: fake)
        return llm_mod.LLMClient(), calls, sleeps
    return make


def test_daily_limit_stops_at_once_with_the_wait_and_the_reason(client):
    c, calls, sleeps = client([RateLimitError(GROQ_DAILY)])

    with pytest.raises(QuotaExhausted) as exc:
        c.complete("hi")

    assert len(calls) == 1, "retried a limit that will not clear within the backoff cap"
    assert sleeps == []
    assert exc.value.retry_after == pytest.approx(971.568)
    assert "tokens per day" in str(exc.value)
    assert "16m" in exc.value.summary()


def test_short_limit_waits_as_the_provider_says_then_succeeds(client):
    c, calls, sleeps = client([RateLimitError("Please try again in 2.5s.")])

    assert c.complete("hi").text == "ok"
    assert len(calls) == 2
    assert sleeps == [pytest.approx(3.0)]           # the hint plus a half-second cushion


def test_wait_exactly_at_the_cap_is_still_waited(client):
    c, calls, _ = client([RateLimitError(f"try again in {MAX_BACKOFF_SECONDS - 0.5}s")])
    assert c.complete("hi").text == "ok" and len(calls) == 2


def test_limit_without_a_hint_keeps_the_exponential_backoff(client):
    c, calls, sleeps = client([RateLimitError("slow down"), RateLimitError("slow down")])
    assert c.complete("hi").text == "ok"
    assert len(calls) == 3 and len(sleeps) == 2


def test_quota_exhausted_is_not_a_subclass_of_the_retryable_error():
    """If it were, a caller catching rate limits to retry would retry it too."""
    assert not issubclass(QuotaExhausted, RateLimitError)


# --- token accounting ----------------------------------------------------------------

def test_client_totals_the_tokens_of_every_successful_call(client):
    c, _, _ = client([])
    c.complete("a")
    c.complete("b")
    assert c.usage() == {"calls": 2, "prompt_tokens": 200, "completion_tokens": 40,
                         "total_tokens": 240}


def test_every_request_carries_a_timeout(client, monkeypatch):
    """A provider that accepts the connection and never answers must not hang a scan."""
    c, calls, _ = client([])
    c.complete("hi")
    assert calls[0]["timeout"] == llm_mod.DEFAULT_REQUEST_TIMEOUT

    monkeypatch.setenv("SENTINEL_LLM_TIMEOUT", "600")
    c, calls, _ = client([])
    c.complete("hi")
    assert calls[0]["timeout"] == 600.0


class AuthenticationError(Exception):
    pass


def test_a_bad_key_is_one_clean_error_not_a_library_traceback(client):
    """Not retryable, and reported as ModelError so the CLI can print one line."""
    c, calls, sleeps = client([AuthenticationError("Invalid API Key\nlong provider body")])
    with pytest.raises(llm_mod.ModelError) as exc:
        c.complete("hi")
    assert len(calls) == 1 and sleeps == []
    assert str(exc.value) == "stub/model: AuthenticationError: Invalid API Key"


def test_exhausted_retries_are_a_model_error(client):
    c, calls, _ = client([RateLimitError("slow down")] * 5)
    with pytest.raises(llm_mod.ModelError):
        c.complete("hi")
    assert len(calls) == 5


def test_cli_reports_a_model_error_with_its_own_exit_code(monkeypatch, capsys):
    import scan

    class Failing:
        model = "stub/model"

    monkeypatch.setattr(scan, "LLMClient", lambda: Failing())

    class Boom:
        def __init__(self, *a, **k):
            pass

        def scan(self, **k):
            raise llm_mod.ModelError("stub/model", AuthenticationError("Invalid API Key"))

    monkeypatch.setattr(scan, "Scanner", Boom)
    assert scan.main(["targets/vulnerable_app", "--no-validate"]) == scan.EXIT_MODEL
    err = capsys.readouterr().err
    assert "Invalid API Key" in err and "Traceback" not in err
