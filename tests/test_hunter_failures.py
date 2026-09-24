"""
"The hunter found nothing" and "the hunter's reply was unreadable" must differ.

Both used to produce an empty list. On the clean control, "no candidates" in an
evaluation run could mean the model judged the code safe, or that its reply had no
parseable JSON at all, and nothing in the output could tell them apart.
"""

from __future__ import annotations

from sentinel.hunter import Hunter
from sentinel.llm import LLMResponse
from sentinel.scanner import Scanner
from sentinel.tools import Tools


class ScriptedLLM:
    model = "stub/model"

    def __init__(self, hunt_reply: str):
        self.hunt_reply = hunt_reply

    def complete(self, prompt, system=None):
        text = self.hunt_reply if "Analyze this Python file" in prompt else "print('x')"
        return LLMResponse(text=text, prompt_tokens=0, completion_tokens=0, cost_usd=0.0)


def _hunter(reply, root="targets/vulnerable_app"):
    return Hunter(ScriptedLLM(reply), Tools(root))


def test_explicit_empty_list_is_a_real_nothing_found():
    h = _hunter('{"findings": []}')
    assert h.hunt() == []
    assert h.unreadable_files == [] and h.dropped_entries == 0


def test_reply_without_json_is_recorded_as_unreadable():
    h = _hunter("I could not find any issues in this file.")
    assert h.hunt() == []
    assert h.unreadable_files == ["app.py"]


def test_object_without_a_findings_list_is_unreadable_not_empty():
    h = _hunter('{"results": [{"vuln_class": "SQL Injection", "line": 33}]}')
    assert h.hunt() == []
    assert h.unreadable_files == ["app.py"]


def test_malformed_entries_are_counted_when_dropped():
    h = _hunter('{"findings": [{"vuln_class": "SQL Injection", "line": 33},'
                ' {"vuln_class": "Command Injection"}, {"line": "forty"}]}')
    found = h.hunt()
    assert [f.line for f in found] == [33]
    assert h.dropped_entries == 2
    assert h.unreadable_files == []


def test_counts_reset_between_hunts():
    h = _hunter("not json")
    h.hunt()
    h.llm.hunt_reply = '{"findings": []}'
    h.hunt()
    assert h.unreadable_files == [] and h.dropped_entries == 0


def test_scan_report_carries_and_announces_unreadable_replies():
    report = Scanner(ScriptedLLM("no json here"), "targets/vulnerable_app").scan(
        validate=False, patch=False)

    assert report.hunter_unreadable == ["app.py"]
    hunter = report.to_dict()["hunter"]
    assert hunter["unreadable_files"] == ["app.py"] and hunter["dropped_entries"] == 0
    assert "unreadable" in report.summary()


# --- an unreadable reply must carry the evidence of why ----------------------------
#
# Empty, truncated and prose replies need different fixes. Recording only that a
# reply was unreadable left all three indistinguishable.

class ReplyLLM:
    model = "stub/model"

    def __init__(self, text, finish_reason):
        self.text, self.finish_reason = text, finish_reason

    def complete(self, prompt, system=None):
        return LLMResponse(text=self.text, prompt_tokens=0, completion_tokens=0,
                           cost_usd=0.0, finish_reason=self.finish_reason)


def test_empty_reply_is_described_with_its_finish_reason():
    h = Hunter(ReplyLLM("", "length"), Tools("targets/safe_app"))
    h.hunt()
    d = h.unreadable_details["app.py"]
    assert d["reply_chars"] == 0 and d["finish_reason"] == "length"
    assert d["reply"] == "" and d["parse_error"] == "no JSON object in reply"
    assert d["attempts"] == 2


def test_unreadable_reply_is_kept_whole_up_to_a_cap():
    """A parse failure is usually at the END of a reply, so a head excerpt is useless."""
    prose = "No vulnerabilities were found in this file. " * 200
    h = Hunter(ReplyLLM(prose, "stop"), Tools("targets/safe_app"))
    h.hunt()
    d = h.unreadable_details["app.py"]
    assert d["reply_chars"] == len(prose) and d["finish_reason"] == "stop"
    assert d["reply"] == prose[:4000]


def test_summary_names_the_reason_for_each_unreadable_file():
    report = Scanner(ReplyLLM("", "length"), "targets/safe_app").scan(
        validate=False, patch=False)
    assert "app.py (empty reply: no JSON object in reply, finish_reason=length, 2 attempts)" in report.summary()
    assert report.to_dict()["hunter"]["details"]["app.py"]["finish_reason"] == "length"


def test_llm_client_passes_finish_reason_through(monkeypatch):
    """The real client, with only litellm's network call replaced."""
    from types import SimpleNamespace

    from sentinel import llm as llm_mod

    fake_response = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=None),
                                 finish_reason="length")],
        usage=SimpleNamespace(prompt_tokens=10, completion_tokens=0),
    )
    fake_litellm = SimpleNamespace(
        completion=lambda **kw: fake_response,
        completion_cost=lambda **kw: 0.0,
        exceptions=SimpleNamespace(**{n: type(n, (Exception,), {}) for n in (
            "RateLimitError", "APIConnectionError", "Timeout", "ServiceUnavailableError",
            "InternalServerError", "APIError", "BadGatewayError")}),
    )
    monkeypatch.setattr(llm_mod, "_get_litellm", lambda: fake_litellm)
    monkeypatch.setenv("SENTINEL_MODEL", "stub/model")

    r = llm_mod.LLMClient().complete("hi")
    assert r.text == "" and r.finish_reason == "length"



# --- one retry for a malformed reply ------------------------------------------------
#
# Captured from gpt-oss-120b on targets/safe_app: a complete, sensible reply with one
# `]` too many. json.loads rejects it at character 310. The same prompt parsed in 12
# of 13 attempts, so the failure is random, and asking once more is the fix that
# neither guesses at the model's intent nor depends on one provider's JSON mode.

REAL_MALFORMED = (
    '{"findings": [{"vuln_class": "Server Side Request Forgery", "line": 34, '
    '"severity": "medium", "description": "The \'host\' query parameter is taken from '
    'the request and passed directly to subprocess.run ping, enabling an attacker to '
    'make the server send network requests to arbitrary hosts.", "confidence": 0.9}]]}'
)
VALID = ('{"findings": [{"vuln_class": "Server Side Request Forgery", "line": 34, '
         '"severity": "medium", "description": "d", "confidence": 0.9}]}')


class SequenceLLM:
    """Replies in order and counts the calls, so tests can assert on the CALLS."""

    model = "stub/model"

    def __init__(self, *replies):
        self.replies, self.calls = list(replies), 0

    def complete(self, prompt, system=None):
        text = self.replies[min(self.calls, len(self.replies) - 1)]
        self.calls += 1
        return LLMResponse(text=text, prompt_tokens=0, completion_tokens=0,
                           cost_usd=0.0, finish_reason="stop")


def test_the_captured_reply_really_is_invalid_json():
    import json

    import pytest
    with pytest.raises(json.JSONDecodeError):
        json.loads(REAL_MALFORMED)


def test_malformed_reply_is_retried_once_and_the_retry_is_used():
    llm = SequenceLLM(REAL_MALFORMED, VALID)
    h = Hunter(llm, Tools("targets/safe_app"))

    found = h.hunt()

    assert llm.calls == 2
    assert [(f.vuln_class, f.line) for f in found] == [("Server Side Request Forgery", 34)]
    assert h.unreadable_files == []
    assert h.retried_files == ["app.py"]


def test_two_malformed_replies_record_the_whole_reply_and_the_parse_error():
    llm = SequenceLLM(REAL_MALFORMED, REAL_MALFORMED)
    h = Hunter(llm, Tools("targets/safe_app"))

    assert h.hunt() == []
    assert llm.calls == 2
    d = h.unreadable_details["app.py"]
    assert d["reply"] == REAL_MALFORMED
    assert "Expecting ',' delimiter" in d["parse_error"]
    assert d["attempts"] == 2


def test_a_readable_reply_is_never_retried():
    llm = SequenceLLM(VALID)
    Hunter(llm, Tools("targets/safe_app")).hunt()
    assert llm.calls == 1


def test_an_explicit_empty_list_is_never_retried():
    llm = SequenceLLM('{"findings": []}')
    h = Hunter(llm, Tools("targets/safe_app"))
    assert h.hunt() == [] and llm.calls == 1 and h.retried_files == []


def test_missing_findings_list_is_retried_and_named():
    llm = SequenceLLM('{"results": []}', '{"results": []}')
    h = Hunter(llm, Tools("targets/safe_app"))
    h.hunt()
    assert llm.calls == 2
    assert h.unreadable_details["app.py"]["parse_error"] == "JSON object has no 'findings' list"


def test_retries_are_reported_but_are_not_a_warning():
    report = Scanner(SequenceLLM(REAL_MALFORMED, VALID), "targets/safe_app").scan(
        validate=False, patch=False)
    assert report.to_dict()["hunter"]["retried_files"] == ["app.py"]
    assert "WARNING" not in report.summary()
