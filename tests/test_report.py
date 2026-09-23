"""The HTML report must render real data from a ScanReport and be self-contained."""

from tests._fixtures import sample_report
from sentinel.report import render_html


def test_report_is_self_contained():
    html = render_html(sample_report())
    # No external requests: a security report must render offline and leak nothing.
    assert "http://" not in html and "https://" not in html
    assert "<script" not in html.lower()  # no JS, nothing to execute


def test_report_shows_real_counts_and_findings():
    html = render_html(sample_report())
    assert "SQL Injection" in html
    assert "Hardcoded Secret" in html
    assert "app.py:33" in html
    # The proving PoC and the fix diff are embedded for line-proven findings.
    assert "SENTINEL_PWNED" in html
    assert "cursor.execute" in html


def test_report_separates_evidence_tiers():
    """The report must never present a class-only proof as a line-proven one."""
    html = render_html(sample_report())
    assert "LINE PROVEN" in html
    assert "CLASS ONLY" in html
    assert "NO PATH" in html
    # Each tier gets its own section heading.
    assert "Line-proven" in html and "Class-only" in html


def test_report_shows_witness_and_gate_reasoning():
    """A reader must be able to see WHY a finding landed in its tier."""
    html = render_html(sample_report())
    assert "Execution witness" in html
    # The class-only finding explains that the target file never ran.
    assert "never executed any code in app.py" in html
    # The gated finding explains the static verdict that rejected it.
    assert "Static gate" in html
    assert "shell=False" in html


def test_class_only_findings_are_not_patched():
    """We must not rewrite a line we could not show even executes."""
    from sentinel.report import _finding_card
    report = sample_report()
    d = report.to_dict()
    patches = {p["file"]: p["diff"] for p in d["patches"]}
    class_only = [s for s in d["scanned"] if s["evidence"] == "class_only"][0]
    card = _finding_card(class_only, patches)
    assert "Proposed secure-fix diff" not in card


def test_report_escapes_html():
    from sentinel.hunter import Finding
    from sentinel.scanner import ScanReport, ScannedFinding
    evil = Finding("XSS<script>", "a.py", 1, "low", "<b>bad</b>", 0.5)
    html = render_html(ScanReport(target="t", scanned=[ScannedFinding(evil, False)]))
    assert "<script>" not in html.replace("&lt;script&gt;", "")


def test_section_counts_match_the_cards_shown():
    """Regression: a section header must count the cards beneath it.

    'Not demonstrated' previously subtracted the class-only count from rejected --
    but class-only findings ARE confirmed, so they were never in rejected. The
    header read 0 above a visible card.
    """
    import re
    report = sample_report()
    html = render_html(report)
    d = report.to_dict()

    headers = dict(
        re.findall(r'<h2 class="section[^"]*">([^<]+?)\s*<span class="count">(\d+)</span>', html)
    )
    assert int(headers["Line-proven"]) == len(report.line_proven)
    assert int(headers["Class-only"]) == len(report.class_only)
    assert int(headers["Not demonstrated"]) == len(report.rejected)
    # And every rejected finding really does get a card rendered.
    assert int(headers["Not demonstrated"]) >= d["counts"]["gated_out"]


def test_each_finding_reports_its_own_witness_line():
    """Regression: a witness must never be attributed to another finding's line."""
    html = render_html(sample_report())
    # The secret at app.py:18 must not claim it reached line 33.
    secret_card = html.split("Hardcoded Secret")[1].split("</article>")[0]
    assert "app.py:18" in secret_card
    assert "app.py:33" not in secret_card
