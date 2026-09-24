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
    assert d == {"reply_chars": 0, "finish_reason": "length", "excerpt": ""}


def test_prose_reply_keeps_a_bounded_excerpt():
    prose = "No vulnerabilities were found in this file. " * 20
    h = Hunter(ReplyLLM(prose, "stop"), Tools("targets/safe_app"))
    h.hunt()
    d = h.unreadable_details["app.py"]
    assert d["reply_chars"] == len(prose) and d["finish_reason"] == "stop"
    assert d["excerpt"] == prose[:200]


def test_summary_names_the_reason_for_each_unreadable_file():
    report = Scanner(ReplyLLM("", "length"), "targets/safe_app").scan(
        validate=False, patch=False)
    assert "app.py (empty reply, finish_reason=length)" in report.summary()
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
