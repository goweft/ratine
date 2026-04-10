"""ratine.cli — Command-line interface."""
import argparse
import json
import sys
from pathlib import Path

from ratine._version import __version__
from ratine.scanner import MemoryGuard
from ratine.formatters import format_memory_report, format_drift_report, format_sarif


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="ratine",
        description="Agent memory poisoning detector",
    )
    parser.add_argument("--version", action="version", version=f"ratine {__version__}")

    sub = parser.add_subparsers(dest="command")

    # scan
    scan_p = sub.add_parser("scan", help="Scan agent memory for poisoning indicators")
    scan_p.add_argument("target", help="Path to agent memory directory or file")
    scan_p.add_argument("--format", choices=["human", "json", "sarif"], default="human")
    scan_p.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "info"],
                        default="high")
    scan_p.add_argument("--no-color", action="store_true")
    scan_p.add_argument(
        "--max-file-size", type=int, default=None, metavar="MB",
        help="Skip files larger than this size in MB (default: 10)",
    )

    # snapshot
    snap_p = sub.add_parser("snapshot", help="Take a memory state snapshot")
    snap_p.add_argument("target", help="Path to agent memory directory")
    snap_p.add_argument("-o", "--output", required=True, help="Output snapshot file path")

    # diff
    diff_p = sub.add_parser("diff", help="Compare two memory snapshots")
    diff_p.add_argument("before", help="Path to before snapshot")
    diff_p.add_argument("after", help="Path to after snapshot")
    diff_p.add_argument("--format", choices=["human", "json", "sarif"], default="human")
    diff_p.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "info"],
                        default="high")
    diff_p.add_argument("--no-color", action="store_true")

    # discover
    sub.add_parser("discover", help="Auto-discover agent memory directories")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 2

    config: dict = {}
    config_path = Path(".ratine.json")
    if config_path.exists():
        try:
            config = json.loads(config_path.read_text())
        except (json.JSONDecodeError, OSError):
            pass

    max_file_bytes = None
    if hasattr(args, "max_file_size") and args.max_file_size is not None:
        max_file_bytes = args.max_file_size * 1024 * 1024
    guard = MemoryGuard(config=config, max_file_bytes=max_file_bytes)

    if args.command == "scan":
        report = guard.scan(args.target)

        if args.format == "json":
            print(json.dumps(report.to_dict(), indent=2))
        elif args.format == "sarif":
            print(format_sarif(report.findings))
        else:
            print(format_memory_report(report, use_color=not args.no_color))

        severity_order = ["critical", "high", "medium", "low", "info"]
        threshold = severity_order.index(args.fail_on)
        for f in report.findings:
            if severity_order.index(f.severity.value.lower()) <= threshold:
                return 2
        return 0

    elif args.command == "snapshot":
        snap = guard.snapshot(args.target, args.output)
        print(f"Snapshot saved: {args.output}")
        print(f"  Files: {len(snap['files'])}")
        print(f"  Agent: {snap['agent_type']}")
        return 0

    elif args.command == "diff":
        report = guard.diff(args.before, args.after)

        if args.format == "json":
            print(json.dumps(report.to_dict(), indent=2))
        elif args.format == "sarif":
            print(format_sarif(report.findings))
        else:
            print(format_drift_report(report, use_color=not args.no_color))

        severity_order = ["critical", "high", "medium", "low", "info"]
        threshold = severity_order.index(args.fail_on)
        for f in report.findings:
            if severity_order.index(f.severity.value.lower()) <= threshold:
                return 2
        return 0

    elif args.command == "discover":
        found = MemoryGuard.discover()
        if not found:
            print("No known agent memory directories found.")
            return 0
        print("Discovered agent memory directories:")
        for d in found:
            print(f"  {d['agent']:15s} {d['path']}")
        return 0

    return 0
