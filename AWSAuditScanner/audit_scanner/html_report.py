"""Generate HTML summary report from scan results."""

from __future__ import annotations

import html
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any


def _status_badge(status: str) -> str:
    colors = {
        "PASS": "#1a7f37",
        "FAIL": "#cf222e",
        "PARTIAL": "#bf8700",
        "NOT_TESTED": "#656d76",
    }
    color = colors.get(status, "#656d76")
    return f'<span style="color:{color};font-weight:600">{html.escape(status)}</span>'


def write_html_report(
    path: Path,
    domain: str,
    auditor: str,
    timestamp: str,
    account_summaries: list[dict[str, Any]],
    all_results: dict[str, list[dict[str, Any]]],
) -> Path:
    total = Counter()
    rows = []
    for summary in account_summaries:
        total["Passed"] += summary["passed"]
        total["Failed"] += summary["failed"]
        total["Partial"] += summary["partial"]
        total["Not Tested"] += summary["not_tested"]
        rows.append(
            "<tr>"
            f"<td>{html.escape(summary['account'])}</td>"
            f"<td>{summary['passed']}</td>"
            f"<td>{summary['failed']}</td>"
            f"<td>{summary['partial']}</td>"
            f"<td>{summary['not_tested']}</td>"
            "</tr>"
        )

    detail_sections = []
    for account_name, results in sorted(all_results.items()):
        detail_rows = []
        for item in results:
            detail_rows.append(
                "<tr>"
                f"<td>{html.escape(str(item.get('ControlId', '')))}</td>"
                f"<td>{html.escape(str(item.get('Region', '')))}</td>"
                f"<td>{_status_badge(str(item.get('Status', '')))}</td>"
                f"<td>{html.escape(str(item.get('Severity', '')))}</td>"
                f"<td>{html.escape(str(item.get('Notes', '')))}</td>"
                "</tr>"
            )
        detail_sections.append(
            f"<h2>{html.escape(account_name)}</h2>"
            "<table><thead><tr><th>Control</th><th>Region</th><th>Status</th>"
            "<th>Severity</th><th>Notes</th></tr></thead><tbody>"
            + "".join(detail_rows)
            + "</tbody></table>"
        )

    document = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>AWS Audit Scanner — {html.escape(domain)}</title>
  <style>
    body {{ font-family: Segoe UI, Arial, sans-serif; margin: 2rem; color: #1f2328; }}
    h1, h2 {{ margin-bottom: 0.5rem; }}
    table {{ border-collapse: collapse; width: 100%; margin: 1rem 0 2rem; }}
    th, td {{ border: 1px solid #d0d7de; padding: 0.5rem 0.75rem; text-align: left; }}
    th {{ background: #f6f8fa; }}
    .meta {{ color: #656d76; margin-bottom: 1.5rem; }}
    .totals span {{ margin-right: 1.5rem; }}
  </style>
</head>
<body>
  <h1>AWS Audit Scanner Report</h1>
  <p class="meta">
    Domain: <strong>{html.escape(domain)}</strong><br>
    Auditor: {html.escape(auditor)}<br>
    Generated: {html.escape(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}<br>
    Scan timestamp: {html.escape(timestamp)}
  </p>
  <div class="totals">
    <span>Passed: <strong>{total['Passed']}</strong></span>
    <span>Failed: <strong>{total['Failed']}</strong></span>
    <span>Partial: <strong>{total['Partial']}</strong></span>
    <span>Not tested: <strong>{total['Not Tested']}</strong></span>
  </div>
  <h2>Summary by account</h2>
  <table>
    <thead><tr><th>Account</th><th>Passed</th><th>Failed</th><th>Partial</th><th>Not Tested</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
  {''.join(detail_sections)}
</body>
</html>"""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(document, encoding="utf-8")
    return path
