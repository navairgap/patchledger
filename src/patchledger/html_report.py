"""Self-contained HTML report renderer.

Security posture:

* Every dynamic value passes through ``html.escape`` — finding titles,
  evidence, paths, scanner names, everything.
* The report contains **no JavaScript**; the Content-Security-Policy forbids
  scripts, objects, frames and remote resources. Inline CSS is the only
  active content, and it is a static string compiled into this file.
* The report is a single self-contained file that renders offline.
"""

from __future__ import annotations

import html

from patchledger import __version__
from patchledger.models import Severity
from patchledger.reporting import SEVERITY_ORDER, ReportData

_CSS = """
:root {
  --bg: #0d1117; --bg2: #111826; --panel: #161b27; --line: #232b3b;
  --text: #dce3ed; --muted: #8b96a8;
  --green: #3fb968; --green-dim: #1d3a29;
  --red: #e5534b; --orange: #d18616; --yellow: #d4a72c; --blue: #539bf5;
  --mono: ui-monospace, "SF Mono", "Cascadia Mono", Menlo, Consolas, monospace;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.6 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
.wrap { max-width: 1080px; margin: 0 auto; padding: 2rem 1.25rem 4rem; }
header { border-bottom: 1px solid var(--line); padding-bottom: 1.5rem; margin-bottom: 2rem; }
.brand { color: var(--green); font-weight: 700; letter-spacing: .04em; font-size: .85rem;
  text-transform: uppercase; }
h1 { font-size: 1.7rem; margin: .35rem 0 .5rem; }
h2 { font-size: 1.15rem; margin: 2.25rem 0 .75rem; color: var(--text);
  border-bottom: 1px solid var(--line); padding-bottom: .4rem; }
h3 { font-size: 1rem; margin: 0 0 .6rem; }
.meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
  gap: .6rem 1.5rem; }
.meta div { font-size: .9rem; }
.meta span.k { color: var(--muted); display: inline-block; min-width: 6.5rem; }
code, .mono { font-family: var(--mono); font-size: .85em; color: #a8d0b0;
  background: var(--bg2); padding: .1em .4em; border-radius: 4px; word-break: break-all; }
.badge { display: inline-block; padding: .18rem .7rem; border-radius: 999px;
  font-weight: 700; font-size: .8rem; letter-spacing: .05em; text-transform: uppercase; }
.badge.fail { background: #3a1d20; color: var(--red); border: 1px solid #6b2a2c; }
.badge.warn { background: #33260e; color: var(--yellow); border: 1px solid #5c481c; }
.badge.pass { background: var(--green-dim); color: var(--green); border: 1px solid #2a5238; }
.panel { background: var(--panel); border: 1px solid var(--line); border-radius: 10px;
  padding: 1rem 1.25rem; margin: .75rem 0; }
table { width: 100%; border-collapse: collapse; font-size: .9rem; }
th, td { text-align: left; padding: .45rem .6rem; border-bottom: 1px solid var(--line); }
th { color: var(--muted); font-weight: 600; }
.counts { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: .75rem; }
.count { background: var(--bg2); border: 1px solid var(--line); border-radius: 10px;
  padding: .8rem 1rem; text-align: center; }
.count .n { font-size: 1.6rem; font-weight: 800; }
.count .lbl { font-size: .75rem; color: var(--muted); text-transform: uppercase;
  letter-spacing: .06em; }
.sev-critical { color: var(--red); } .sev-high { color: var(--orange); }
.sev-medium { color: var(--yellow); } .sev-low { color: var(--blue); }
.sev-info, .sev-unknown { color: var(--muted); }
.finding { border-left: 3px solid var(--line); margin: 1rem 0; }
.finding.critical, .finding.high { border-left-color: var(--red); }
.finding.medium { border-left-color: var(--orange); }
.finding.low { border-left-color: var(--blue); }
.finding-head { display: flex; flex-wrap: wrap; gap: .5rem; align-items: baseline; }
.finding-head .idx { color: var(--muted); font-size: .85rem; }
.sev-tag { font-size: .72rem; font-weight: 800; padding: .12rem .5rem;
  border-radius: 4px; text-transform: uppercase; letter-spacing: .05em; }
.sev-tag.critical, .sev-tag.high { background: #3a1d20; color: var(--red); }
.sev-tag.medium { background: #33260e; color: var(--yellow); }
.sev-tag.low { background: #16262e; color: var(--blue); }
.sev-tag.info, .sev-tag.unknown { background: var(--bg2); color: var(--muted); }
pre.evidence {
  background: #0a0e14; border: 1px solid var(--line); border-radius: 8px;
  padding: .75rem 1rem; overflow-x: auto; font-family: var(--mono); font-size: .82rem;
  color: #b8c4d4; margin: .6rem 0;
}
.remediation { border-left: 3px solid var(--green-dim); padding: .4rem 0 .4rem 1rem;
  margin: .6rem 0; color: var(--muted); font-size: .9rem; white-space: pre-wrap; }
.remediation strong { color: var(--green); }
.note { background: #1c2a1e; border: 1px solid #2a5238; color: #9fd8ae; border-radius: 8px;
  padding: .7rem 1rem; margin: 1rem 0; font-size: .9rem; }
.warnbox { background: #2d2410; border: 1px solid #5c481c; color: #e8c66a; border-radius: 8px;
  padding: .7rem 1rem; margin: 1rem 0; font-size: .9rem; }
footer { margin-top: 3rem; border-top: 1px solid var(--line); padding-top: 1rem;
  color: var(--muted); font-size: .82rem; }
a { color: var(--blue); }
@media (max-width: 640px) { .wrap { padding: 1.25rem .9rem 3rem; } h1 { font-size: 1.35rem; } }
"""


def esc(value) -> str:
    """Escape any dynamic value for safe HTML interpolation."""
    return html.escape(str(value) if value is not None else "", quote=True)


def _severity_tag(severity: Severity) -> str:
    return f'<span class="sev-tag {esc(severity.value)}">{esc(severity.value)}</span>'


def _status_badge(status: str) -> str:
    if status.startswith("FAIL"):
        cls = "fail"
    elif status.startswith("WARN"):
        cls = "warn"
    else:
        cls = "pass"
    return f'<span class="badge {cls}">{esc(status)}</span>'


def render_html(data: ReportData) -> str:
    """Render the report as one self-contained, escaped HTML document."""
    out: list[str] = []
    push = out.append

    push("<!DOCTYPE html>")
    push('<html lang="en">')
    push("<head>")
    push('<meta charset="utf-8">')
    push('<meta name="viewport" content="width=device-width, initial-scale=1">')
    push("<meta http-equiv=\"Content-Security-Policy\" "
         "content=\"default-src 'none'; style-src 'unsafe-inline'\">")
    push(f"<title>PatchLedger report — {esc(data.project_name)}</title>")
    push(f"<style>{_CSS}</style>")
    push("</head>")
    push("<body>")
    push('<div class="wrap">')

    # ---------------------------------------------------------- header
    push("<header>")
    push('<div class="brand">PatchLedger — Find it. Understand it. Fix it. Prove it.</div>')
    push("<h1>Security Report</h1>")
    if data.is_synthetic_example:
        push('<div class="note"><strong>SYNTHETIC EXAMPLE DATA</strong> — generated '
             "for illustration only, not the result of a real scan.</div>")
    push('<div class="meta">')
    push(f"<div><span class='k'>Project</span> {esc(data.project_name)}</div>")
    push(f"<div><span class='k'>Root</span> <code>{esc(data.project_root)}</code></div>")
    push(f"<div><span class='k'>Scan</span> <code>{esc(data.scan.id)}</code></div>")
    push(f"<div><span class='k'>Created</span> {esc(data.scan.created_at)}</div>")
    push(f"<div><span class='k'>Source</span> {esc(data.scan.source.value)}</div>")
    if data.scan.git_commit:
        push(f"<div><span class='k'>Git</span> <code>{esc(data.scan.git_commit[:12])}</code>"
             + (f" ({esc(data.scan.git_branch)})" if data.scan.git_branch else "") + "</div>")
    push(f"<div><span class='k'>Generated</span> {esc(data.generated_at)}</div>")
    push(f"<div><span class='k'>Status</span> {_status_badge(data.overall_status())}</div>")
    push("</div>")
    push("</header>")

    # -------------------------------------------------------- coverage
    push("<h2>Scanner coverage</h2>")
    if not data.coverage.has_coverage:
        push('<div class="note">No scanner information recorded for this scan '
             "(imported reports only).</div>")
    else:
        push('<div class="panel"><table>')
        push("<tr><th>Tool</th><th>Status</th><th>Version</th><th>Note</th></tr>")
        for t in data.scan.tools:
            push(
                f"<tr><td><code>{esc(t.tool)}</code></td>"
                f"<td>{esc(t.status.value)}</td>"
                f"<td>{esc(t.version or '-')}</td>"
                f"<td>{esc(t.note or '-')}</td></tr>"
            )
        push("</table></div>")
    if not data.coverage.complete:
        push('<div class="warnbox"><strong>Incomplete coverage</strong> — some tools '
             "did not run. Findings are not a complete picture, and any resolution "
             "claims are treated as unverified.</div>")

    # --------------------------------------------------------- summary
    push("<h2>Summary</h2>")
    counts = data.severity_counts()
    push('<div class="counts">')
    for severity in SEVERITY_ORDER:
        push(
            f'<div class="count"><div class="n sev-{esc(severity.value)}">'
            f"{counts.get(severity.value, 0)}</div>"
            f'<div class="lbl">{esc(severity.value)}</div></div>'
        )
    push("</div>")

    # ------------------------------------------------------ comparison
    if data.comparison is not None:
        c = data.comparison
        push(f"<h2>Comparison with scan <code>{esc(c.baseline_scan_id)}</code> "
             f"({esc(c.baseline_created_at)})</h2>")
        push('<div class="panel"><table>')
        for label, value in (
            ("New", c.new), ("Persistent", c.persistent),
            ("Resolved candidates", c.resolved_candidates),
            ("Verified fixed", c.verified_fixed), ("Inconclusive", c.inconclusive),
            ("Reintroduced", c.reintroduced),
            ("Changed severity", c.changed_severity), ("Changed evidence", c.changed_evidence),
        ):
            push(f"<tr><th>{esc(label)}</th><td>{value}</td></tr>")
        push("</table>")
        for note in c.notes:
            push(f'<div class="note">{esc(note)}</div>')
        push("</div>")

    # -------------------------------------------------------- findings
    push(f"<h2>Findings ({len(data.findings)})</h2>")
    if not data.findings:
        push('<div class="note">No findings recorded.</div>')
    for i, f in enumerate(data.findings, 1):
        push(f'<div class="finding {esc(f.severity.value)} panel">')
        push('<div class="finding-head">')
        push(f'<span class="idx">#{i}</span>')
        push(_severity_tag(f.severity))
        push(f"<h3>{esc(f.title)}</h3>")
        push("</div>")
        push(
            f"<div><span class='k' style='color:var(--muted)'>Scanner</span> "
            f"{esc(f.scanner)} — <code>{esc(f.rule_id)}</code></div>"
        )
        push(
            f"<div><span class='k' style='color:var(--muted)'>Location</span> "
            f"<code>{esc(f.location_str)}</code></div>"
        )
        push(
            f"<div><span class='k' style='color:var(--muted)'>Category</span> "
            f"{esc(f.category)} — confidence {esc(f.confidence.value)}"
            + (f" (scanner said: {esc(f.raw_severity)})" if f.raw_severity else "")
            + f" — fingerprint <code>{esc(f.fingerprint)}</code></div>"
        )
        if f.description and f.description != f.title:
            push(f"<p>{esc(f.description)}</p>")
        if f.evidence:
            push("<div style='color:var(--muted);font-size:.85rem'>Evidence "
                 "(scanner-reported, secrets redacted):</div>")
            push(f"<pre class='evidence'>{esc(f.evidence.rstrip())}</pre>")
        if f.score_factors:
            push(f"<div style='font-size:.9rem'>Risk score <strong>{f.score}</strong> — "
                 f"{esc('; '.join(f.score_factors))}</div>")
        if f.remediation:
            push('<div class="remediation"><strong>Remediation guidance</strong> '
                 "(advice, not evidence):")
            push(f"{esc(f.remediation)}")
            push("</div>")
        if len(f.occurrences) > 1:
            push(f"<div style='font-size:.85rem;color:var(--muted)'>{len(f.occurrences)} "
                 "occurrences merged (identical fingerprint)</div>")
        push("</div>")

    # ---------------------------------------------------------- footer
    push("<footer>")
    push(f"Generated by patchledger {__version__} — evidence is scanner-reported; "
         "remediation text is advice from the local knowledge base. "
         "This report contains no JavaScript.")
    push("</footer>")
    push("</div>")
    push("</body>")
    push("</html>")
    return "\n".join(out)
