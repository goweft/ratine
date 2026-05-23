"""ratine.cli — Command-line interface."""
import argparse
import datetime
import io
import json
import sys
import time
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
    scan_p.add_argument(
        "--semantic", action="store_true",
        help="Use LLM to classify ambiguous findings (requires RATINE_LLM_API_KEY)",
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

    # watch
    watch_p = sub.add_parser("watch", help="Continuously monitor agent memory for new findings")
    watch_p.add_argument("target", help="Path to agent memory directory")
    watch_p.add_argument("--interval", type=int, default=300, metavar="SECONDS",
                         help="Seconds between scans (default: 300)")
    watch_p.add_argument("--max-runs", type=int, default=None, metavar="N",
                         help="Stop after N scans (default: run forever)")
    watch_p.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "info"],
                         default="high")
    watch_p.add_argument("--format", choices=["human", "json"], default="human")
    watch_p.add_argument("--no-color", action="store_true")

    # install-service
    svc_p = sub.add_parser("install-service", help="Install systemd user timer for scheduled scanning")
    svc_p.add_argument("target", help="Path to agent memory directory to monitor")
    svc_p.add_argument("--interval", type=int, default=300, metavar="SECONDS",
                       help="Scan interval in seconds (default: 300)")
    svc_p.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "info"],
                       default="high")
    svc_p.add_argument("--output-dir", default=None, metavar="DIR",
                       help="Directory for unit files (default: ~/.config/systemd/user/)")

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

        if getattr(args, "semantic", False):
            from ratine.semantic import SemanticAnalyzer
            analyzer = SemanticAnalyzer(config.get("semantic", {}))
            report.findings = analyzer.analyze(report.findings, Path(args.target))
            report.health_score = max(0, 100 - sum(f.severity.weight for f in report.findings))

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

    elif args.command == "watch":
        _run_watch(
            guard=guard,
            target=args.target,
            interval=args.interval,
            max_runs=args.max_runs,
            fail_on=args.fail_on,
            fmt=args.format,
            use_color=not args.no_color,
        )
        return _watch_exit_code

    elif args.command == "install-service":
        return _run_install_service(
            target=args.target,
            interval=args.interval,
            fail_on=args.fail_on,
            output_dir=args.output_dir,
        )

    return 0


# ── Watch helpers ─────────────────────────────────────────────────────────────

_watch_exit_code = 0  # module-level so tests can inspect after main() returns


def _run_watch(guard, target, interval, max_runs, fail_on, fmt, use_color,
               _sleep=None):
    """Core watch loop — separated so tests can inject a no-op sleep."""
    global _watch_exit_code
    _watch_exit_code = 0

    if _sleep is None:
        _sleep = time.sleep

    severity_order = ["critical", "high", "medium", "low", "info"]
    threshold = severity_order.index(fail_on)

    bold  = "\033[1m" if use_color else ""
    dim   = "\033[2m" if use_color else ""
    reset = "\033[0m" if use_color else ""

    seen: set = set()
    run = 0

    try:
        while max_runs is None or run < max_runs:
            run += 1
            ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            report = guard.scan(target)

            new_findings = [
                f for f in report.findings
                if (f.rule_id, f.file_path, f.line_number) not in seen
            ]
            for f in report.findings:
                seen.add((f.rule_id, f.file_path, f.line_number))

            if fmt == "json":
                out = {
                    "run":              run,
                    "timestamp":        ts,
                    "health_score":     report.health_score,
                    "total_files":      report.total_files,
                    "new_findings_count": len(new_findings),
                    "new_findings":     [f.to_dict() for f in new_findings],
                }
                print(json.dumps(out), flush=True)
            else:
                sev_color = ""
                if new_findings:
                    worst = min(new_findings, key=lambda f: severity_order.index(f.severity.value.lower()))
                    sev_color = worst.severity.color if use_color else ""
                status = (
                    f"{dim}[{ts}]{reset}  run={run}"
                    f"  agent={report.agent_type}"
                    f"  files={report.total_files}"
                    f"  score={report.health_score}"
                    f"  new={sev_color}{len(new_findings)}{reset}"
                )
                print(status, flush=True)
                for f in new_findings:
                    sc = f.severity.color if use_color else ""
                    loc = f"{f.file_path}:{f.line_number}" if f.line_number else f.file_path
                    print(f"  {sc}● {f.rule_id} [{f.severity.value}]{reset}  {loc}  {f.message}")
                    if f.detail:
                        print(f"    {dim}{f.detail}{reset}")

            for f in new_findings:
                if severity_order.index(f.severity.value.lower()) <= threshold:
                    _watch_exit_code = 2

            if max_runs is None or run < max_runs:
                _sleep(interval)

    except KeyboardInterrupt:
        print("\nWatch stopped.", flush=True)


# ── Install-service helper ────────────────────────────────────────────────────

_SERVICE_TEMPLATE = """[Unit]
Description=ratine agent memory poisoning scan
After=default.target

[Service]
Type=oneshot
ExecStart={ratine_cmd} scan {target} --format json --fail-on {fail_on}
StandardOutput=journal
StandardError=journal
"""

_TIMER_TEMPLATE = """[Unit]
Description=ratine memory scan — every {interval}s

[Timer]
OnBootSec=60
OnUnitActiveSec={interval}s
AccuracySec=10s

[Install]
WantedBy=timers.target
"""


def _run_install_service(target, interval, fail_on, output_dir):
    out = Path(output_dir) if output_dir else Path.home() / ".config" / "systemd" / "user"
    out.mkdir(parents=True, exist_ok=True)

    ratine_cmd = f"{sys.executable} -m ratine"
    target_abs = str(Path(target).resolve())

    svc_path   = out / "ratine-scan.service"
    timer_path = out / "ratine-scan.timer"

    svc_path.write_text(_SERVICE_TEMPLATE.format(
        ratine_cmd=ratine_cmd, target=target_abs, fail_on=fail_on,
    ))
    timer_path.write_text(_TIMER_TEMPLATE.format(interval=interval))

    print(f"Installed:")
    print(f"  {svc_path}")
    print(f"  {timer_path}")
    print()
    print("Enable and start:")
    print("  systemctl --user daemon-reload")
    print("  systemctl --user enable --now ratine-scan.timer")
    print()
    print("Check status:")
    print("  systemctl --user status ratine-scan.timer")
    print("  journalctl --user -u ratine-scan.service -f")
    return 0
