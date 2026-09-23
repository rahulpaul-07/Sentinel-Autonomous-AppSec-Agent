"""
sentinel/report.py
------------------
Render a ScanReport as a single, self-contained HTML file.

Design goals, in order:
  1. HONEST. Every number on the page comes from the ScanReport passed in. There is
     no template data and nothing is fabricated. An empty scan renders an empty
     report, not a fake one.
  2. SELF-CONTAINED. All CSS is inlined and there are zero external requests -- no
     CDN, no web fonts, no analytics. A security tool's output should render on an
     air-gapped box and leak nothing. This is the reason the styling is hand-written
     rather than pulled from a component library.
  3. STRUCTURED FROM DATA. The HTML is built from report.to_dict(), so the report
     and the --json output can never drift apart.

The page shows: a header with target/model/runtime, summary tiles (candidates,
confirmed, rejected, patched files) and a severity breakdown, then one card per
finding -- confirmed findings carry the proof-of-concept that demonstrated them and
the proposed fix diff; rejected candidates are listed separately so you can see what
the validator threw out and why.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone

from sentinel.scanner import ScanReport

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}


def _esc(text: object) -> str:
    return html.escape(str(text), quote=True)


def _diff_html(diff: str) -> str:
    """Colour a unified diff: additions green, removals red, hunk headers muted."""
    rows = []
    for line in diff.splitlines():
        cls = "ctx"
        if line.startswith("+") and not line.startswith("+++"):
            cls = "add"
        elif line.startswith("-") and not line.startswith("---"):
            cls = "del"
        elif line.startswith("@@") or line.startswith("+++") or line.startswith("---"):
            cls = "meta"
        rows.append(f'<span class="dl {cls}">{_esc(line) or "&nbsp;"}</span>')
    return "\n".join(rows)


# evidence tier -> (css slug, badge text, one-line meaning)
_TIER = {
    "line_proven": ("proven", "LINE PROVEN", "Exploit ran and the reported line executed."),
    "class_only": ("classonly", "CLASS ONLY", "Exploit succeeded, but the reported line never ran."),
    "unproven": ("rejected", "UNPROVEN", "The exploit never succeeded."),
    "unreachable": ("gated", "NO PATH", "Static analysis found no attacker path to this line."),
    "env_incomplete": ("envgap", "NOT TESTABLE",
                       "The sandbox lacks a dependency the target imports, so nothing was tested."),
}


def _witness_block(val: dict) -> str:
    """Render what the line tracer observed, if a trace was captured."""
    w = val.get("witness")
    if not w:
        return ""
    if not w.get("available"):
        return (
            '<div class="witness"><span class="wlabel">Execution witness</span>'
            "No trace was captured for this run.</div>"
        )
    tf, tl = _esc(w.get("target_file", "")), _esc(w.get("target_line", ""))
    if w.get("line_executed"):
        body = f'<span class="wyes">reached {tf}:{tl}</span> during the exploit.'
    elif w.get("file_executed"):
        near = w.get("nearest_line")
        near_txt = f" (nearest executed line {near})" if near else ""
        body = (
            f'<span class="wno">ran code in {tf} but never reached line {tl}</span>'
            f"{near_txt} &mdash; only the vulnerability class was demonstrated."
        )
    else:
        body = (
            f'<span class="wno">never executed any code in {tf}</span> &mdash; the '
            "exploit reproduced the class in isolation."
        )
    return f'<div class="witness"><span class="wlabel">Execution witness</span>{body}</div>'


def _envgap_block(val: dict) -> str:
    """Name the package the sandbox was missing, so the gap is actionable."""
    mod = val.get("missing_module")
    if not mod:
        return ""
    return (
        '<div class="gate"><span class="wlabel">Sandbox gap</span>'
        f"The target imports <code>{_esc(mod)}</code>, which is not installed in the "
        "sandbox image. The exploit stopped at that import, so this claim was never "
        "tested.</div>"
    )


def _gate_block(scanned: dict) -> str:
    """For gated-out candidates, show why the static gate rejected them."""
    r = scanned.get("reachability")
    if not r or not r.get("verdict") in ("no_taint_path", "no_sink_at_line", "safe_usage"):
        return ""
    return (
        '<div class="gate"><span class="wlabel">Static gate</span>'
        f'{_esc(r.get("reason", ""))}</div>'
    )


def _finding_card(scanned: dict, patches_by_file: dict[str, str]) -> str:
    f = scanned["finding"]
    sev = (f["severity"] or "unknown").lower()
    tier = scanned.get("evidence", "unproven")
    css, badge, meaning = _TIER.get(tier, _TIER["unproven"])

    poc_block = ""
    val = scanned.get("validation")
    if val and val.get("poc_code"):
        attempts = val.get("attempts", 1)
        poc_block = f"""
        {_envgap_block(val)}
        {_witness_block(val)}
        <details class="drawer">
          <summary>Proof-of-concept exploit <span class="muted">&middot; {attempts} attempt(s)</span></summary>
          <pre class="code poc">{_esc(val["poc_code"])}</pre>
          <div class="micro-label">Sandbox output</div>
          <pre class="code out">{_esc(val.get("output", "").strip() or "(no output captured)")}</pre>
        </details>"""

    diff_block = ""
    diff = patches_by_file.get(f["file"])
    if tier == "line_proven" and diff:
        diff_block = f"""
        <details class="drawer">
          <summary>Proposed secure-fix diff</summary>
          <pre class="code diff">{_diff_html(diff)}</pre>
        </details>"""

    conf_pct = int(round(float(f.get("confidence", 0.0)) * 100))
    return f"""
      <article class="card {css}">
        <div class="card-head">
          <div class="card-title">
            <span class="sev sev-{_esc(sev)}">{_esc(sev)}</span>
            <h3>{_esc(f["vuln_class"])}</h3>
          </div>
          <span class="status status-{css}" title="{_esc(meaning)}">{badge}</span>
        </div>
        <div class="loc"><span class="mono">{_esc(f["file"])}:{_esc(f["line"])}</span>
          <span class="conf" title="Hunter confidence">conf {conf_pct}%</span>
        </div>
        <p class="desc">{_esc(f["description"])}</p>
        {_gate_block(scanned)}
        {poc_block}
        {diff_block}
      </article>"""


def render_html(report: ScanReport, title: str = "Sentinel Scan Report") -> str:
    data = report.to_dict()
    counts = data["counts"]
    patches_by_file = {p["file"]: p["diff"] for p in data["patches"]}

    _TIER_ORDER = {"line_proven": 0, "class_only": 1, "env_incomplete": 2,
                   "unproven": 3, "unreachable": 4}
    scanned_sorted = sorted(
        data["scanned"],
        key=lambda s: (
            _TIER_ORDER.get(s.get("evidence", "unproven"), 9),
            _SEVERITY_ORDER.get((s["finding"]["severity"] or "unknown").lower(), 4),
        ),
    )

    def cards(tier: str) -> str:
        return "".join(
            _finding_card(s, patches_by_file)
            for s in scanned_sorted
            if s.get("evidence") == tier
        )

    proven_cards = cards("line_proven")
    classonly_cards = cards("class_only")
    envgap_cards = cards("env_incomplete")
    other_cards = cards("unproven") + cards("unreachable")

    sev = counts["by_severity"]
    sev_pills = "".join(
        f'<span class="pill pill-{k}">{v} {k}</span>'
        for k, v in sorted(sev.items(), key=lambda kv: _SEVERITY_ORDER.get(kv[0], 4))
    ) or '<span class="muted">no line-proven findings</span>'

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    n_proven = counts.get("line_proven", 0)
    n_class = counts.get("class_only", 0)
    n_gated = counts.get("gated_out", 0)

    proven_section = (
        f'<h2 class="section">Line-proven <span class="count">{n_proven}</span></h2>'
        f'<p class="hint">The exploit succeeded <em>and</em> the reported line executed while it ran. '
        f'These are claims demonstrated about this code.</p>{proven_cards}'
        if proven_cards
        else f'<h2 class="section">Line-proven <span class="count">0</span></h2>'
        '<p class="empty">No finding was proven exploitable at its reported line.</p>'
    )

    classonly_section = (
        f'<h2 class="section muted-h">Class-only <span class="count">{n_class}</span></h2>'
        f'<p class="hint">An exploit printed the success marker, but the trace shows the reported '
        f'line never executed. That proves the vulnerability <em>class</em> is exploitable, not that '
        f'this line is &mdash; so these are held back from the headline count and are not patched.</p>'
        f"{classonly_cards}"
        if classonly_cards
        else ""
    )

    n_envgap = counts.get("not_testable", 0)
    envgap_section = (
        f'<h2 class="section muted-h">Not testable <span class="count">{n_envgap}</span></h2>'
        f'<p class="hint">The exploit could not run because the sandbox image is missing a '
        f'third-party package the target imports. Nothing was proven <em>or</em> disproven &mdash; '
        f'these are reported separately rather than counted as failed exploits, because calling '
        f'them unproven would claim a test that never happened.</p>{envgap_cards}'
        if envgap_cards
        else ""
    )

    other_section = (
        f'<h2 class="section muted-h">Not demonstrated <span class="count">'
        f'{counts.get("not_demonstrated", counts["rejected"])}'
        f'</span></h2>'
        f'<p class="hint">Flagged by the hunter, then either rejected by the static reachability '
        f'gate before any model call ({n_gated}) or never demonstrated by a working exploit. '
        f'They are shown so nothing is silently dropped.</p>{other_cards}'
        if other_cards
        else ""
    )

    sections = proven_section + classonly_section + envgap_section + other_section

    return f"""<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>{_esc(title)}</title>
<style>
:root {{
  --bg:#0a0c11; --bg2:#0e1119; --panel:#12161f; --panel2:#161b26;
  --line:#232a38; --text:#e7ecf3; --muted:#8a93a6; --micro:#5f6b80;
  --accent:#4f8cff; --accent2:#7c5cff; --ok:#2fd47a; --bad:#ff5c6c;
  --crit:#ff5c6c; --high:#ff9f43; --med:#ffd23f; --low:#5bc8ff; --unknown:#8a93a6;
}}
:root:not([data-theme="dark"]) {{
  --bg:#f6f8fc; --bg2:#eef2f8; --panel:#ffffff; --panel2:#f2f5fb;
  --line:#dde3ee; --text:#12161f; --muted:#5a6577; --micro:#8894a6;
}}
* {{ box-sizing:border-box; }}
html,body {{ margin:0; padding:0; background:var(--bg); color:var(--text);
  font:15px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }}
.mono,.code,.conf {{ font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace; }}
.wrap {{ max-width:960px; margin:0 auto; padding:40px 22px 80px; }}

.hero {{ position:relative; overflow:hidden; border:1px solid var(--line);
  border-radius:18px; padding:34px 30px; background:
    radial-gradient(120% 140% at 0% 0%, rgba(79,140,255,.16), transparent 55%),
    radial-gradient(120% 140% at 100% 0%, rgba(124,92,255,.14), transparent 55%),
    var(--panel); }}
.hero::before {{ content:""; position:absolute; inset:0; opacity:.5;
  background-image:linear-gradient(var(--line) 1px,transparent 1px),
    linear-gradient(90deg,var(--line) 1px,transparent 1px);
  background-size:34px 34px; mask:radial-gradient(80% 80% at 50% 0%,#000,transparent 75%);
  -webkit-mask:radial-gradient(80% 80% at 50% 0%,#000,transparent 75%); }}
.hero > * {{ position:relative; }}
.brand {{ display:flex; align-items:center; gap:11px; font-weight:700;
  letter-spacing:.3px; font-size:14px; color:var(--muted); }}
.brand .dot {{ width:9px; height:9px; border-radius:50%;
  background:var(--ok); box-shadow:0 0 14px var(--ok); }}
.hero h1 {{ margin:14px 0 6px; font-size:30px; letter-spacing:-.5px; }}
.hero h1 .accent {{ background:linear-gradient(90deg,var(--accent),var(--accent2));
  -webkit-background-clip:text; background-clip:text; color:transparent; }}
.meta-row {{ display:flex; flex-wrap:wrap; gap:8px 18px; margin-top:14px;
  color:var(--muted); font-size:13px; }}
.meta-row span {{ margin:0 16px 2px 0; }}
.meta-row b {{ color:var(--text); font-weight:600; }}

.tiles {{ display:flex; flex-wrap:wrap; gap:12px; margin:22px 0 8px; }}
.tile {{ flex:1 1 160px; border:1px solid var(--line); border-radius:14px;
  padding:16px 16px 14px; background:var(--panel); }}
.tile .n {{ font-size:30px; font-weight:750; letter-spacing:-1px; line-height:1; }}
.tile .l {{ color:var(--muted); font-size:12.5px; margin-top:6px;
  text-transform:uppercase; letter-spacing:.6px; }}
.tile.good .n {{ color:var(--ok); }} .tile.bad .n {{ color:var(--bad); }}
.tile.warn .n {{ color:var(--high); }}

.pills {{ display:flex; flex-wrap:wrap; gap:8px; margin:16px 0 4px; }}
.pill {{ font-size:12.5px; padding:5px 11px; border-radius:999px;
  border:1px solid var(--line); background:var(--panel2); text-transform:capitalize; }}
.pill-critical {{ color:var(--crit); border-color:color-mix(in srgb,var(--crit) 45%,var(--line)); }}
.pill-high {{ color:var(--high); border-color:color-mix(in srgb,var(--high) 45%,var(--line)); }}
.pill-medium {{ color:var(--med); border-color:color-mix(in srgb,var(--med) 45%,var(--line)); }}
.pill-low {{ color:var(--low); border-color:color-mix(in srgb,var(--low) 45%,var(--line)); }}

.section {{ font-size:18px; margin:34px 0 14px; display:flex; align-items:center; gap:10px; }}
.section .count {{ font-size:13px; color:var(--muted); border:1px solid var(--line);
  border-radius:999px; padding:1px 9px; font-weight:600; }}
.muted-h {{ color:var(--muted); }}
.hint {{ color:var(--muted); font-size:13.5px; margin:-6px 0 14px; }}
.empty {{ color:var(--muted); border:1px dashed var(--line); border-radius:12px;
  padding:16px; text-align:center; }}

.card {{ border:1px solid var(--line); border-radius:15px; padding:18px 18px 14px;
  background:var(--panel); margin-bottom:14px; }}
.card.proven {{ border-left:3px solid var(--bad); }}
.card.classonly {{ border-left:3px solid var(--high); }}
.card.rejected {{ opacity:.82; border-left:3px solid var(--line); }}
.card.gated {{ opacity:.72; border-left:3px solid var(--accent2); }}
.card.envgap {{ opacity:.82; border-left:3px solid var(--micro); }}
.card-head {{ display:flex; align-items:center; justify-content:space-between; gap:12px; }}
.card-title {{ display:flex; align-items:center; gap:11px; }}
.card-title h3 {{ margin-left:2px; }}
.card-title h3 {{ margin:0; font-size:17px; }}
.sev {{ margin-right:10px; font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:.5px;
  padding:3px 8px; border-radius:6px; color:#0a0c11; }}
.sev-critical {{ background:var(--crit); }} .sev-high {{ background:var(--high); }}
.sev-medium {{ background:var(--med); }} .sev-low {{ background:var(--low); }}
.sev-unknown {{ background:var(--unknown); }}
.status {{ font-size:11px; font-weight:700; letter-spacing:.6px; padding:4px 10px;
  border-radius:999px; }}
.status-proven {{ color:var(--bad); background:color-mix(in srgb,var(--bad) 15%,transparent);
  border:1px solid color-mix(in srgb,var(--bad) 40%,var(--line)); }}
.status-classonly {{ color:var(--high); background:color-mix(in srgb,var(--high) 15%,transparent);
  border:1px solid color-mix(in srgb,var(--high) 40%,var(--line)); }}
.status-rejected {{ color:var(--muted); background:var(--panel2); border:1px solid var(--line); }}
.status-gated {{ color:var(--accent2); background:color-mix(in srgb,var(--accent2) 14%,transparent);
  border:1px solid color-mix(in srgb,var(--accent2) 40%,var(--line)); }}
.status-envgap {{ color:var(--micro); background:var(--bg2); border:1px solid var(--line); }}
.witness,.gate {{ font-size:13px; color:var(--muted); background:var(--bg2);
  border:1px solid var(--line); border-radius:10px; padding:10px 12px; margin:10px 0 2px; }}
.wlabel {{ display:block; color:var(--micro); font-size:10.5px; text-transform:uppercase;
  letter-spacing:.6px; margin-bottom:4px; }}
.wyes {{ color:var(--ok); font-weight:600; }}
.wno {{ color:var(--high); font-weight:600; }}
.loc {{ display:flex; align-items:center; gap:12px; margin:10px 0 4px; font-size:13px; }}
.loc .mono {{ margin-right:12px; }}
.loc .mono {{ color:var(--accent); }}
.conf {{ color:var(--micro); font-size:12px; }}
.desc {{ color:var(--text); margin:6px 0 12px; }}

.drawer {{ border-top:1px solid var(--line); padding-top:10px; margin-top:6px; }}
.drawer summary {{ cursor:pointer; color:var(--muted); font-size:13.5px;
  font-weight:600; list-style:none; user-select:none; }}
.drawer summary::-webkit-details-marker {{ display:none; }}
.drawer summary::before {{ content:"\\25B8"; display:inline-block; margin-right:8px;
  transition:transform .15s ease; color:var(--micro); }}
.drawer[open] summary::before {{ transform:rotate(90deg); }}
.micro-label {{ color:var(--micro); font-size:11px; text-transform:uppercase;
  letter-spacing:.6px; margin:12px 0 5px; }}
.code {{ background:var(--bg2); border:1px solid var(--line); border-radius:10px;
  padding:13px 14px; overflow-x:auto; font-size:12.5px; line-height:1.55; margin:10px 0 0;
  white-space:pre; }}
.code.out {{ color:var(--muted); }}
.diff {{ display:flex; flex-direction:column; }}
.dl {{ display:block; white-space:pre; }}
.dl.add {{ color:var(--ok); }} .dl.del {{ color:var(--bad); }}
.dl.meta {{ color:var(--accent2); }} .dl.ctx {{ color:var(--muted); }}
.muted {{ color:var(--muted); }}
footer {{ margin-top:44px; padding-top:18px; border-top:1px solid var(--line);
  color:var(--micro); font-size:12.5px; display:flex; justify-content:space-between;
  flex-wrap:wrap; gap:8px; }}
footer a {{ color:var(--muted); text-decoration:none; border-bottom:1px dotted var(--line); }}
</style>
</head>
<body>
<div class="wrap">
  <header class="hero">
    <div class="brand"><span class="dot"></span> SENTINEL &middot; AUTONOMOUS APPSEC AGENT</div>
    <h1>Scan report <span class="accent">&middot; proven, not asserted</span></h1>
    <div class="meta-row">
      <span>Target <b class="mono">{_esc(data["target"])}</b></span>
      <span>Model <b class="mono">{_esc(data["model"] or "n/a")}</b></span>
      <span>Runtime <b>{_esc(data["elapsed_seconds"])}s</b></span>
      <span>Generated <b>{_esc(generated)}</b></span>
    </div>
  </header>

  <div class="tiles">
    <div class="tile"><div class="n">{counts["candidates"]}</div><div class="l">Candidates</div></div>
    <div class="tile bad"><div class="n">{n_proven}</div><div class="l">Line proven</div></div>
    <div class="tile warn"><div class="n">{n_class}</div><div class="l">Class only</div></div>
    <div class="tile"><div class="n">{n_envgap}</div><div class="l">Not testable</div></div>
    <div class="tile"><div class="n">{n_gated}</div><div class="l">No path</div></div>
    <div class="tile good"><div class="n">{counts["patched_files"]}</div><div class="l">Files fixed</div></div>
  </div>
  <div class="pills">{sev_pills}</div>

  {sections}

  <footer>
    <span>Line-proven findings were demonstrated by an executed exploit in a network-disabled
      sandbox, with a line trace confirming the reported line ran.</span>
    <span>Sentinel</span>
  </footer>
</div>
</body>
</html>"""


def write_html(report: ScanReport, path: str, title: str = "Sentinel Scan Report") -> str:
    from pathlib import Path

    out = Path(path)
    out.write_text(render_html(report, title=title), encoding="utf-8")
    return str(out.resolve())
