"""ScanReport.to_dict must be a faithful, JSON-safe view of the report."""

import json
from tests._fixtures import sample_report


def test_to_dict_is_json_serializable_and_complete():
    d = sample_report().to_dict()
    json.dumps(d)  # must not raise
    # Three exploits printed the marker, but only one drove the reported line.
    assert d["counts"]["confirmed"] == 3
    assert d["counts"]["line_proven"] == 1
    assert d["counts"]["class_only"] == 2
    assert d["counts"]["gated_out"] == 1
    assert d["counts"]["not_testable"] == 1
    # Severity counts follow the STRICT tier, so class-only highs are excluded.
    assert d["counts"]["by_severity"] == {"critical": 1}
    assert len(d["patches"]) == 1
    # Confirmed findings carry their proof and their execution trace.
    confirmed = [s for s in d["scanned"] if s["confirmed"]]
    assert all("validation" in s and s["validation"]["poc_code"] for s in confirmed)
    assert all("witness" in s["validation"] for s in confirmed)
    # The gated finding records why static analysis rejected it.
    gated = [s for s in d["scanned"] if s["evidence"] == "unreachable"][0]
    assert gated["reachability"]["verdict"] == "safe_usage"
