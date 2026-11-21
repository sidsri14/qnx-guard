"""Reporters for QNX Sentinel (qnx-guard) output formats.

Supports:
- Terminal / Text (Colored ANSI)
- JSON
- SARIF 2.1.0 (Static Analysis Results Interchange Format for GitHub Code Scanning)
- Interactive HTML Dashboard
"""

import json
from typing import Any, Dict
from qnx_guard.models import ScanSummary, Severity


def render_terminal(summary: ScanSummary) -> str:
    lines = []
    lines.append("=" * 72)
    lines.append("  QNX Sentinel (qnx-guard) v0.1.0 — Real-Time Systems Audit")
    lines.append("  Host Linter & Static Safety Validator for QNX SDP 8.0")
    lines.append("=" * 72)
    lines.append(f"Scanned {summary.scanned_files} files across target repository.")
    lines.append("")

    if not summary.findings:
        lines.append("  [PASS] No safety or security violations detected. System is clean!")
        lines.append("=" * 72)
        return "\n".join(lines)

    for f in summary.findings:
        sev_color = f"[{f.severity.value}]"
        lines.append(f"{sev_color} {f.rule_id}: {f.rule_name}")
        lines.append(f"  Location: {f.file_path}:{f.line_number}")
        lines.append(f"  Category: {f.category}")
        lines.append(f"  Message:  {f.message}")
        lines.append(f"  Snippet:  `{f.matched_text}`")
        lines.append(f"  Fix:      {f.remediation}")
        lines.append("-" * 72)

    lines.append("")
    lines.append("Scan Summary:")
    lines.append(f"  Total Findings:   {summary.total_findings}")
    lines.append(f"  High Severity:    {summary.high_severity}")
    lines.append(f"  Medium Severity:  {summary.medium_severity}")
    lines.append(f"  Low Severity:     {summary.low_severity}")
    lines.append(f"  Informational:    {summary.info_severity}")
    lines.append("=" * 72)
    return "\n".join(lines)


def render_json(summary: ScanSummary) -> str:
    return json.dumps(summary.to_dict(), indent=2)


def render_sarif(summary: ScanSummary) -> str:
    sarif: Dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "qnx-guard",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/sidsri14/qnx-guard",
                        "rules": [
                            {
                                "id": f.rule_id,
                                "name": f.rule_name,
                                "shortDescription": {"text": f.message},
                                "defaultConfiguration": {
                                    "level": "error" if f.severity == Severity.HIGH else "warning"
                                },
                            }
                            for f in summary.findings
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": f.rule_id,
                        "level": "error" if f.severity == Severity.HIGH else "warning",
                        "message": {"text": f"{f.message} Remediation: {f.remediation}"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": f.file_path},
                                    "region": {"startLine": f.line_number},
                                }
                            }
                        ],
                    }
                    for f in summary.findings
                ],
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def render_html(summary: ScanSummary) -> str:
    rows = ""
    for f in summary.findings:
        sev_class = "high" if f.severity == Severity.HIGH else "medium" if f.severity == Severity.MEDIUM else "low"
        rows += f"""
        <tr class="{sev_class}">
          <td><strong>{f.rule_id}</strong></td>
          <td><span class="badge {sev_class}">{f.severity.value}</span></td>
          <td><code>{f.file_path}:{f.line_number}</code></td>
          <td>{f.message}</td>
          <td><pre>{f.matched_text}</pre></td>
          <td><em>{f.remediation}</em></td>
        </tr>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>QNX Sentinel (qnx-guard) - Security & Real-Time Audit Report</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 40px; background: #0d1117; color: #c9d1d9; }}
    h1 {{ color: #58a6ff; font-size: 24px; border-bottom: 1px solid #30363d; padding-bottom: 12px; }}
    .stats {{ display: flex; gap: 20px; margin: 24px 0; }}
    .stat-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 16px 24px; min-width: 140px; }}
    .stat-val {{ font-size: 28px; font-weight: bold; margin-top: 8px; }}
    .high-val {{ color: #f85149; }}
    .med-val {{ color: #d29922; }}
    .low-val {{ color: #58a6ff; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 20px; background: #161b22; border: 1px solid #30363d; }}
    th, td {{ padding: 12px 16px; border: 1px solid #30363d; text-align: left; font-size: 14px; }}
    th {{ background: #21262d; color: #8b949e; }}
    .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 12px; font-weight: bold; }}
    .badge.high {{ background: #f85149; color: #fff; }}
    .badge.medium {{ background: #d29922; color: #fff; }}
    .badge.low {{ background: #1f6feb; color: #fff; }}
    pre {{ background: #0d1117; padding: 6px; border-radius: 4px; margin: 0; font-size: 12px; }}
  </style>
</head>
<body>
  <h1>QNX Sentinel (qnx-guard) — Real-Time Safety & Security Audit</h1>
  <p>Static verification report for QNX SDP 8.0 Neutrino microkernel components and IFS buildfiles.</p>
  <div class="stats">
    <div class="stat-card"><div>Scanned Files</div><div class="stat-val">{summary.scanned_files}</div></div>
    <div class="stat-card"><div>Total Findings</div><div class="stat-val">{summary.total_findings}</div></div>
    <div class="stat-card"><div>High Severity</div><div class="stat-val high-val">{summary.high_severity}</div></div>
    <div class="stat-card"><div>Medium Severity</div><div class="stat-val med-val">{summary.medium_severity}</div></div>
    <div class="stat-card"><div>Low / Info</div><div class="stat-val low-val">{summary.low_severity + summary.info_severity}</div></div>
  </div>
  <table>
    <thead>
      <tr>
        <th>Rule</th>
        <th>Severity</th>
        <th>Location</th>
        <th>Message</th>
        <th>Code Snippet</th>
        <th>Remediation</th>
      </tr>
    </thead>
    <tbody>
      {rows if rows else "<tr><td colspan='6' style='text-align:center;'>No issues detected. Codebase complies with QNX safety standards.</td></tr>"}
    </tbody>
  </table>
</body>
</html>
"""
