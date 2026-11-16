"""Command line use: python -m app.cli example.com [--json]

Exit code is 0 for grades A+ to C and 1 for D or F, so it can gate a CI job.
"""
from __future__ import annotations

import argparse
import json
import sys

from .netguard import TargetError
from .scanner import scan

MARK = {"pass": "PASS", "warn": "WARN", "fail": "FAIL", "info": "INFO"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="securecheck", description="Passive website security check")
    parser.add_argument("url")
    parser.add_argument("--json", action="store_true", help="print the full report as JSON")
    args = parser.parse_args(argv)

    try:
        report = scan(args.url)
    except TargetError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"\n{report['host']}   grade {report['grade']}   score {report['score']}/100\n")
        category = None
        for f in report["findings"]:
            if f["category"] != category:
                category = f["category"]
                print(f"  {category}")
            print(f"    [{MARK[f['status']]}] {f['title']}")
            if f["status"] in ("warn", "fail"):
                print(f"           {f['detail']}")
                if f["fix"]:
                    print(f"           Fix: {f['fix']}")
        print()
    return 0 if report["grade"] in ("A+", "A", "B", "C") else 1


if __name__ == "__main__":
    sys.exit(main())
