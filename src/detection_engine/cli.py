from __future__ import annotations

import argparse
import json
import sys

from detection_engine.engine import run_detections
from detection_engine.loader import load_rules
from detection_engine.validate import main as validate_main


def _cmd_list() -> int:
    rules = load_rules()
    if not rules:
        print("No Sigma rules found.", file=sys.stderr)
        return 1
    width = max(len(rule.stem) for rule in rules)
    for rule in rules:
        source = f"{rule.product or '-'}/{rule.service or '-'}"
        print(f"{rule.stem:<{width}}  {source:<16}  {rule.level:<13}  {rule.title}")
    return 0


def _cmd_run(*, as_json: bool) -> int:
    alerts = run_detections()
    if as_json:
        json.dump([alert.as_dict() for alert in alerts], sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    if not alerts:
        print("No alerts.")
        return 0

    for alert in alerts:
        event_type = alert.as_dict()["event_type"]
        print(
            f"[{alert.rule.level}] {alert.rule.title} "
            f"({alert.sample.name} / {alert.event_id} / {event_type})"
        )
    print(f"\n{len(alerts)} alert(s)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="detection-engine",
        description="Validate and run Sigma detections against sample events.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("validate", help="Validate the detections tree")
    sub.add_parser("list", help="List loaded Sigma rules")
    run = sub.add_parser("run", help="Evaluate rules against sample events")
    run.add_argument(
        "--json",
        action="store_true",
        help="Print alerts as JSON",
    )

    args = parser.parse_args(argv)
    if args.command == "validate":
        return validate_main()
    if args.command == "list":
        return _cmd_list()
    if args.command == "run":
        return _cmd_run(as_json=args.json)
    parser.error(f"unknown command {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
