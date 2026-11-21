"""Command-line interface for QNX Sentinel (qnx-guard)."""

import argparse
import sys
from pathlib import Path
from qnx_guard.scanner import Scanner
from qnx_guard.reporters import render_terminal, render_json, render_sarif, render_html


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="qnx-guard",
        description="QNX Sentinel (qnx-guard) — Real-Time Static Safety & Security Linter for QNX SDP 8.0",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to file or directory to scan (default: current directory)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "sarif", "html"],
        default="text",
        help="Output report format (default: text)",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Output file path (default: stdout)",
    )
    parser.add_argument(
        "--fail-on-high",
        action="store_true",
        help="Exit with non-zero code if any HIGH severity finding is detected",
    )

    args = parser.parse_args()
    target_path = Path(args.path).resolve()

    if not target_path.exists():
        sys.stderr.write(f"Error: Target path '{args.path}' does not exist.\n")
        sys.exit(2)

    scanner = Scanner(target_path)
    summary = scanner.scan()

    if args.format == "json":
        output = render_json(summary)
    elif args.format == "sarif":
        output = render_sarif(summary)
    elif args.format == "html":
        output = render_html(summary)
    else:
        output = render_terminal(summary)

    if args.output:
        out_path = Path(args.output).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output, encoding="utf-8")
        print(f"Report written to {out_path}")
    else:
        print(output)

    if args.fail_on_high and summary.high_severity > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
