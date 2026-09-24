"""
render_sample_report.py
-----------------------
Render the sample report published at docs/sample-report.html.

The published sample is built from the test suite's fixture report, not from a
scan. That fixture covers every evidence tier in one page, which no single real
scan of the benchmark targets does. Because it is not a scan result, the header
says so: the model field names the fixture instead of a provider, so nobody reads
it as a measured run.

Run from the project root:

    python -m examples.render_sample_report
"""

from pathlib import Path

from sentinel.report import render_html
from tests._fixtures import sample_report

OUT = Path("docs/sample-report.html")


def main() -> None:
    report = sample_report()
    report.model = "illustrative fixture (no model call, not a scan result)"
    OUT.write_text(render_html(report, title="Sentinel sample report"), encoding="utf-8")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
