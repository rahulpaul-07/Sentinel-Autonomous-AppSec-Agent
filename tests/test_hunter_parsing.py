"""The hunter's JSON extraction must survive the messy shapes real models emit."""

from sentinel.hunter import _extract_json_object


def test_plain_object():
    assert _extract_json_object('{"findings": []}') == {"findings": []}


def test_object_wrapped_in_fences_and_prose():
    raw = 'Sure! Here is the result:\n```json\n{"findings": [{"line": 3}]}\n```\nHope that helps.'
    assert _extract_json_object(raw) == {"findings": [{"line": 3}]}


def test_braces_inside_strings_do_not_confuse_the_scanner():
    raw = '{"findings": [{"description": "payload like {\\"a\\":1} breaks naive regex"}]}'
    out = _extract_json_object(raw)
    assert out["findings"][0]["description"].startswith("payload")


def test_trailing_second_object_is_ignored():
    # Greedy {.*} would span both and fail; the balanced scan takes only the first.
    raw = '{"findings": []}\n{"garbage": true}'
    assert _extract_json_object(raw) == {"findings": []}


def test_no_json_returns_none():
    assert _extract_json_object("no json here at all") is None
