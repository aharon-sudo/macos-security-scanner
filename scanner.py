#!/usr/bin/env python3
# macOS Security Compliance Scanner
#
# Checks a Mac's config against controls modeled on the CIS Apple
# macOS Benchmark (SIP, Gatekeeper, FileVault, firewall, screen lock,
# guest account, remote access, software updates) and scores it.
#
# Usage:
#   python3 scanner.py
#   python3 scanner.py --html report.html
#   python3 scanner.py --json report.json
#
# Not a certified CIS-CAT scan, just my own version of one.

import argparse
import datetime
import json
import platform
import sys

from checks import run_all_checks

# ANSI colors for terminal output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
GRAY = "\033[90m"
BOLD = "\033[1m"
RESET = "\033[0m"

STATUS_COLOR = {
    "PASS": GREEN,
    "FAIL": RED,
    "WARN": YELLOW,
    "SKIP": GRAY,
}


def print_terminal_report(results):
    total = len(results)
    counts = {"PASS": 0, "FAIL": 0, "WARN": 0, "SKIP": 0}
    for r in results:
        counts[r["status"]] += 1

    print(f"\n{BOLD}CIS macOS Benchmark Compliance Scanner{RESET}")
    print(f"Host: {platform.node()}  |  OS: {platform.system()} {platform.release()}")
    print(f"Scan time: {datetime.datetime.now().isoformat(timespec='seconds')}")
    print("-" * 70)

    current_category = None
    for r in results:
        if r["category"] != current_category:
            current_category = r["category"]
            print(f"\n{BOLD}{current_category}{RESET}")
        color = STATUS_COLOR.get(r["status"], "")
        print(f"  [{color}{r['status']:>4}{RESET}] {r['id']:<5} {r['title']}")
        print(f"          {GRAY}{r['details']}{RESET}")
        if r["status"] == "FAIL":
            print(f"          {YELLOW}Fix: {r['remediation']}{RESET}")

    scored = counts["PASS"] + counts["FAIL"]
    score = (counts["PASS"] / scored * 100) if scored else 0.0

    print("\n" + "-" * 70)
    print(f"{BOLD}Summary{RESET}: {counts['PASS']} passed, {counts['FAIL']} failed, "
          f"{counts['WARN']} warnings, {counts['SKIP']} skipped  (of {total} checks)")
    print(f"{BOLD}Compliance score{RESET}: {score:.1f}%  "
          f"(based on {scored} pass/fail-applicable checks)\n")

    return counts, score


def write_html_report(results, counts, score, out_path):
    rows = ""
    current_category = None
    for r in results:
        if r["category"] != current_category:
            current_category = r["category"]
            rows += f'<tr class="category-row"><td colspan="4">{current_category}</td></tr>\n'
        status_class = r["status"].lower()
        remediation = f'<div class="remediation">Fix: {r["remediation"]}</div>' if r["status"] == "FAIL" else ""
        rows += f"""
        <tr class="{status_class}">
            <td class="status-cell"><span class="badge {status_class}">{r['status']}</span></td>
            <td class="id-cell">{r['id']}</td>
            <td>
                <div class="title">{r['title']}</div>
                <div class="details">{r['details']}</div>
                {remediation}
            </td>
            <td class="ref-cell">{r['reference']}</td>
        </tr>"""

    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CIS macOS Benchmark Compliance Report</title>
<style>
  :root {{
    --bg: #0f1115;
    --panel: #161922;
    --border: #262b38;
    --text: #e6e8ee;
    --muted: #8b93a7;
    --pass: #34d399;
    --fail: #f87171;
    --warn: #fbbf24;
    --skip: #6b7280;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    padding: 32px;
  }}
  .wrap {{ max-width: 900px; margin: 0 auto; }}
  h1 {{ font-size: 22px; margin: 0 0 4px 0; }}
  .meta {{ color: var(--muted); font-size: 13px; margin-bottom: 24px; }}
  .summary {{
    display: flex; gap: 12px; margin-bottom: 28px; flex-wrap: wrap;
  }}
  .stat {{
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 10px; padding: 14px 18px; min-width: 110px;
  }}
  .stat .num {{ font-size: 24px; font-weight: 700; }}
  .stat .label {{ font-size: 12px; color: var(--muted); margin-top: 2px; }}
  .stat.pass .num {{ color: var(--pass); }}
  .stat.fail .num {{ color: var(--fail); }}
  .stat.warn .num {{ color: var(--warn); }}
  .stat.score .num {{ color: var(--text); }}
  table {{ width: 100%; border-collapse: collapse; }}
  td {{ padding: 10px 8px; border-bottom: 1px solid var(--border); vertical-align: top; font-size: 13px; }}
  tr.category-row td {{
    font-weight: 700; color: var(--muted); text-transform: uppercase;
    font-size: 11px; letter-spacing: 0.05em; padding-top: 22px; border-bottom: none;
  }}
  .status-cell {{ width: 70px; }}
  .id-cell {{ width: 50px; color: var(--muted); font-variant-numeric: tabular-nums; }}
  .ref-cell {{ width: 100px; color: var(--muted); font-size: 12px; }}
  .badge {{
    display: inline-block; padding: 2px 8px; border-radius: 999px;
    font-size: 11px; font-weight: 700; letter-spacing: 0.03em;
  }}
  .badge.pass {{ background: rgba(52,211,153,0.15); color: var(--pass); }}
  .badge.fail {{ background: rgba(248,113,113,0.15); color: var(--fail); }}
  .badge.warn {{ background: rgba(251,191,36,0.15); color: var(--warn); }}
  .badge.skip {{ background: rgba(107,114,128,0.15); color: var(--skip); }}
  .title {{ font-weight: 600; margin-bottom: 2px; }}
  .details {{ color: var(--muted); }}
  .remediation {{ color: var(--warn); margin-top: 4px; font-size: 12px; }}
  footer {{ margin-top: 28px; color: var(--muted); font-size: 12px; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>CIS macOS Benchmark Compliance Report</h1>
  <div class="meta">Host: {platform.node()} &middot; OS: {platform.system()} {platform.release()} &middot; Generated {datetime.datetime.now().isoformat(timespec='seconds')}</div>

  <div class="summary">
    <div class="stat score"><div class="num">{score:.0f}%</div><div class="label">Compliance score</div></div>
    <div class="stat pass"><div class="num">{counts['PASS']}</div><div class="label">Passed</div></div>
    <div class="stat fail"><div class="num">{counts['FAIL']}</div><div class="label">Failed</div></div>
    <div class="stat warn"><div class="num">{counts['WARN']}</div><div class="label">Warnings</div></div>
  </div>

  <table>
    {rows}
  </table>

  <footer>
    Generated by cis-benchmark-scanner &middot; checks are modeled on the CIS Apple macOS Benchmark and simplified for educational use.
  </footer>
</div>
</body>
</html>
"""
    with open(out_path, "w") as f:
        f.write(html)


def main():
    parser = argparse.ArgumentParser(description="CIS Benchmark-style compliance scanner")
    parser.add_argument("--html", metavar="PATH", help="Write an HTML report to PATH")
    parser.add_argument("--json", metavar="PATH", help="Write raw JSON results to PATH")
    parser.add_argument("--fail-under", type=float, default=None,
                         help="Exit with a non-zero status if the compliance score is below this percentage")
    args = parser.parse_args()

    results = run_all_checks()
    counts, score = print_terminal_report(results)

    if args.html:
        write_html_report(results, counts, score, args.html)
        print(f"HTML report written to {args.html}")

    if args.json:
        with open(args.json, "w") as f:
            json.dump({"score": score, "counts": counts, "results": results}, f, indent=2)
        print(f"JSON results written to {args.json}")

    if args.fail_under is not None and score < args.fail_under:
        sys.exit(1)


if __name__ == "__main__":
    main()
