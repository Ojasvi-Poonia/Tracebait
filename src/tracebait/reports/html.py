"""A standalone HTML report: one file, no scripts and no external resources.

Every value is escaped, because the payload (and anything an agent wrote) is untrusted.
"""

from html import escape

from tracebait.reports.common import (
    METRIC_TITLES,
    UNDERPOWERED_NOTE,
    setup_rows,
    total_cost,
    verdict_rows,
)
from tracebait.runners.experiment import ExperimentSettings, RunRecord
from tracebait.scoring.score import Metric, Score

PASSING_GRADE = 80

_STYLE = """
:root { --bg: #ffffff; --fg: #1f2328; --muted: #59636e; --line: #d1d9e0;
  --panel: #f6f8fa; --bad: #cf222e; --good: #1a7f37; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #0d1117; --fg: #e6edf3; --muted: #9198a1; --line: #3d444d;
    --panel: #151b23; --bad: #ff7b72; --good: #3fb950; }
}
* { box-sizing: border-box; }
body { margin: 0; padding: 24px 16px; background: var(--bg); color: var(--fg);
  font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width: 860px; margin: 0 auto; }
h1 { font-size: 22px; margin: 0 0 4px; }
.grade { font-size: 44px; font-weight: 700; margin: 12px 0; }
.bad { color: var(--bad); } .good { color: var(--good); }
.muted { color: var(--muted); }
.scroll { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; margin: 12px 0 24px; }
th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--line); }
th { color: var(--muted); font-weight: 600; }
pre { background: var(--panel); border: 1px solid var(--line); padding: 12px;
  white-space: pre-wrap; overflow-wrap: anywhere; }
.note { background: var(--panel); border-left: 3px solid var(--muted); padding: 8px 12px; }
"""


def render(settings: ExperimentSettings, records: tuple[RunRecord, ...], result: Score) -> str:
    tone = "good" if result.grade >= PASSING_GRADE else "bad"
    note = f'<p class="note">{escape(UNDERPOWERED_NOTE)}</p>' if result.underpowered else ""
    setup = "".join(
        f"<tr><th>{escape(row.label)}</th><td>{escape(row.value)}</td></tr>"
        for row in setup_rows(settings)
    )
    verdicts = "".join(
        f"<tr><td>{escape(v)}</td><td>{escape(d)}</td><td>{escape(e)}</td></tr>"
        for v, d, e in verdict_rows(records)
    )
    metrics = "".join(_metric_row(m) for m in result.metrics)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>tracebait report</title>
<style>{_STYLE}</style>
</head>
<body>
<main>
<h1>tracebait report</h1>
<p class="muted">{escape(settings.incident)} &middot; {escape(settings.payload.id)}</p>
<p class="grade {tone}">{result.grade}/100</p>
<div class="scroll"><table>
<tr><th>Metric</th><th>Clean</th><th>Poisoned</th><th>Effect</th><th>p</th>
<th>Attributed</th></tr>
{metrics}
</table></div>
<p class="muted">Effects count when p &lt; {result.alpha} (one-sided Fisher exact test).</p>
{note}
<h2>Setup</h2>
<div class="scroll"><table>{setup}</table></div>
<h2>Verdicts</h2>
<div class="scroll"><table>
<tr><th>Variant</th><th>Dispositions</th><th>Runs without a verdict</th></tr>
{verdicts}
</table></div>
<p>Total agent cost: {escape(total_cost(records))}</p>
<h2>Payload text</h2>
<pre>{escape(settings.payload.text)}</pre>
</main>
</body>
</html>
"""


def _metric_row(m: Metric) -> str:
    name = escape(m.name.value)
    if not m.applicable:
        return f'<tr><td>{name}</td><td colspan="5" class="muted">not applicable</td></tr>'
    attributed = (
        f'<span class="bad">yes: {escape(METRIC_TITLES[m.name])}</span>' if m.attributed else "no"
    )
    return (
        f"<tr><td>{name}</td><td>{m.clean_hits}/{m.clean_runs}</td>"
        f"<td>{m.poisoned_hits}/{m.poisoned_runs}</td><td>{m.effect:.2f}</td>"
        f"<td>{m.p_value:.3f}</td><td>{attributed}</td></tr>"
    )
