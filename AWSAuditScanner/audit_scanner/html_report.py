"""Generate HTML summary report from scan results."""

from __future__ import annotations

import html
import json
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


def _evidence_lookup(evidence_records: list[dict[str, Any]]) -> dict[tuple[str, str], list[dict[str, Any]]]:
    lookup: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for record in evidence_records:
        key = (str(record.get("control_id", "")), str(record.get("region", "")))
        lookup[key] = list(record.get("commands_executed") or [])
    return lookup


def _successful_commands(commands: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [command for command in commands if command.get("success")]


def _format_command_output(commands: list[dict[str, Any]]) -> str:
    successful = _successful_commands(commands)
    if not successful:
        return ""

    blocks: list[str] = []
    for index, command in enumerate(successful, start=1):
        command_line = html.escape(str(command.get("command") or ""))
        exit_code = command.get("exit_code")
        exit_label = f" (exit {exit_code})" if exit_code is not None else ""
        output = str(command.get("output") or "").strip()
        output_block = (
            f'<pre class="command-output">{html.escape(output)}</pre>'
            if output
            else '<p class="muted">No stdout captured</p>'
        )
        blocks.append(
            '<div class="command-block">'
            f'<div class="command-title">Command {index}{html.escape(exit_label)}</div>'
            f'<pre class="command-line">{command_line}</pre>'
            f"{output_block}"
            "</div>"
        )
    return "".join(blocks)


def _format_evidence(evidence: Any) -> str:
    if evidence is None:
        return ""
    if isinstance(evidence, (dict, list)):
        try:
            text = json.dumps(evidence, indent=2, ensure_ascii=False, default=str)
        except TypeError:
            text = str(evidence)
    else:
        text = str(evidence)
    return f'<pre class="evidence-output">{html.escape(text)}</pre>'


def _control_detail_rows(
    results: list[dict[str, Any]],
    evidence_records: list[dict[str, Any]],
) -> str:
    command_lookup = _evidence_lookup(evidence_records)
    rows: list[str] = []

    for item in results:
        control_id = str(item.get("ControlId", ""))
        region = str(item.get("Region", ""))
        status = str(item.get("Status", ""))
        notes = str(item.get("Notes", ""))
        commands = command_lookup.get((control_id, region), [])
        command_html = _format_command_output(commands)
        evidence_html = _format_evidence(item.get("Evidence"))

        rows.append(
            "<tr>"
            f"<td>{html.escape(control_id)}</td>"
            f"<td>{html.escape(region)}</td>"
            f"<td>{_status_badge(status)}</td>"
            f"<td>{html.escape(str(item.get('Severity', '')))}</td>"
            f"<td>{html.escape(notes)}</td>"
            "</tr>"
        )

        if status == "NOT_TESTED":
            continue

        detail_parts: list[str] = []
        if command_html:
            detail_parts.append(
                "<section>"
                f"<h4>CLI output ({len(_successful_commands(commands))} successful command(s))</h4>"
                f"{command_html}"
                "</section>"
            )
        if evidence_html:
            detail_parts.append(
                "<section>"
                "<h4>Evidence</h4>"
                f"{evidence_html}"
                "</section>"
            )
        if not detail_parts:
            continue

        rows.append(
            '<tr class="control-detail-row">'
            '<td colspan="5">'
            f'<details class="control-details"><summary>View command output and evidence</summary>'
            f'{"".join(detail_parts)}'
            "</details>"
            "</td>"
            "</tr>"
        )

    return "".join(rows)


def write_html_report(
    path: Path,
    domain: str,
    auditor: str,
    timestamp: str,
    account_summaries: list[dict[str, Any]],
    all_results: dict[str, list[dict[str, Any]]],
    all_evidence: dict[str, list[dict[str, Any]]] | None = None,
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
        evidence_records = (all_evidence or {}).get(account_name, [])
        detail_sections.append(
            f"<h2>{html.escape(account_name)}</h2>"
            "<table><thead><tr><th>Control</th><th>Region</th><th>Status</th>"
            "<th>Severity</th><th>Notes</th></tr></thead><tbody>"
            + _control_detail_rows(results, evidence_records)
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
    h4 {{ margin: 0.75rem 0 0.35rem; font-size: 0.95rem; }}
    table {{ border-collapse: collapse; width: 100%; margin: 1rem 0 2rem; }}
    th, td {{ border: 1px solid #d0d7de; padding: 0.5rem 0.75rem; text-align: left; vertical-align: top; }}
    th {{ background: #f6f8fa; }}
    .meta {{ color: #656d76; margin-bottom: 1.5rem; }}
    .totals span {{ margin-right: 1.5rem; }}
    .control-detail-row td {{ background: #f6f8fa; padding-top: 0; }}
    .control-details summary {{
      cursor: pointer;
      color: #0969da;
      font-weight: 600;
      margin: 0.25rem 0 0.5rem;
    }}
    .command-block {{
      border: 1px solid #d0d7de;
      border-radius: 6px;
      background: #ffffff;
      margin: 0.5rem 0;
      padding: 0.75rem;
    }}
    .command-title {{ font-size: 0.85rem; color: #656d76; margin-bottom: 0.35rem; }}
    .command-line, .command-output, .evidence-output {{
      margin: 0;
      white-space: pre-wrap;
      word-break: break-word;
      font-family: Consolas, Monaco, monospace;
      font-size: 0.82rem;
      background: #0d1117;
      color: #e6edf3;
      border-radius: 4px;
      padding: 0.65rem 0.75rem;
      overflow-x: auto;
    }}
    .command-line {{ margin-bottom: 0.5rem; }}
    .muted {{ color: #656d76; font-style: italic; }}
    section + section {{ margin-top: 1rem; }}
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
