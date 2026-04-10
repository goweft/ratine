"""ratine.scanner — MemoryGuard class and utility functions."""
import base64
import fnmatch
import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Optional

from ratine._version import __version__
from ratine.models import Severity, Finding, MemoryReport, DriftReport
from ratine.patterns import (
    INSTRUCTION_PATTERNS, PROMPT_INJECTION_PATTERNS, HIDDEN_CONTENT_PATTERNS,
    MEMORY_SECRET_PATTERNS, URL_PATTERNS,
    AGENT_SIGNATURES, IGNORE_PATTERNS, MEMORY_EXTENSIONS,
)


# ── Utilities ────────────────────────────────────────────────────────────────

def glob_match(rel_path: str, pattern: str) -> bool:
    if fnmatch.fnmatch(rel_path, pattern):
        return True
    if pattern.startswith("**/"):
        suffix = pattern[3:]
        if fnmatch.fnmatch(rel_path, suffix):
            return True
        if fnmatch.fnmatch(os.path.basename(rel_path), suffix):
            return True
        parts = rel_path.replace("\\", "/").split("/")
        for i in range(len(parts)):
            if fnmatch.fnmatch("/".join(parts[i:]), suffix):
                return True
    return False


def should_ignore(rel_path: str) -> bool:
    return any(glob_match(rel_path, p) for p in IGNORE_PATTERNS)


def is_memory_file(path: str) -> bool:
    return Path(path).suffix.lower() in MEMORY_EXTENSIONS


def detect_agent_type(target: Path) -> str:
    for agent, markers in AGENT_SIGNATURES.items():
        if agent == "generic":
            continue
        for marker in markers:
            if (target / marker).exists():
                return agent
            for child in target.iterdir() if target.is_dir() else []:
                if child.name == marker:
                    return agent
    return "generic"


def compute_snapshot_hash(file_hashes: dict) -> str:
    """Compute a deterministic hash of all memory files for drift detection."""
    ordered = sorted(file_hashes.items())
    combined = "|".join(f"{k}:{v}" for k, v in ordered)
    return hashlib.sha256(combined.encode()).hexdigest()[:16]


def is_base64_valid(s: str) -> bool:
    """Check if a string is valid base64 that decodes to something meaningful."""
    try:
        decoded = base64.b64decode(s)
        printable_ratio = sum(1 for b in decoded if 32 <= b < 127) / max(len(decoded), 1)
        return printable_ratio > 0.6 and len(decoded) > 20
    except Exception:
        return False


def _safe_excerpt(line: str, max_len: int = 80) -> str:
    """Truncate a line for safe display, redacting known secret patterns."""
    raw = line.strip().encode("utf-8", errors="replace")
    for pattern, _ in MEMORY_SECRET_PATTERNS:
        raw = pattern.sub(b"[REDACTED]", raw)
    redacted = raw.decode("utf-8", errors="replace")
    if len(redacted) > max_len:
        return redacted[:max_len] + "..."
    return redacted


# ── MemoryGuard ───────────────────────────────────────────────────────────────

class MemoryGuard:
    """Scans agent memory for poisoning indicators."""

    # Maximum file size to scan (10 MB). Files larger than this are skipped
    # to avoid reading adversarially large memory files into RAM.
    MAX_FILE_BYTES = 10 * 1024 * 1024

    def __init__(self, config: Optional[dict] = None, max_file_bytes: Optional[int] = None):
        self.config = config or {}
        self.allowlist = self.config.get("allowlist", [])
        self._max_file_bytes = max_file_bytes if max_file_bytes is not None else self.MAX_FILE_BYTES
        self._custom_patterns = self._load_custom_patterns()

    def _load_custom_patterns(self) -> list:
        """Compile custom patterns from .ratine.json config.

        Expected format::

            {
              "custom_patterns": [
                {
                  "pattern": "(?i)my-corp-secret",
                  "description": "Corp-specific secret token",
                  "severity": "CRITICAL",
                  "rule_id": "CUSTOM-001"
                }
              ]
            }

        Patterns that fail to compile are silently skipped.
        Valid severity values: CRITICAL, HIGH, MEDIUM, LOW, INFO.
        """
        raw = self.config.get("custom_patterns", [])
        compiled = []
        sev_map = {s.value: s for s in Severity}
        for entry in raw:
            pat_str = entry.get("pattern", "")
            desc    = entry.get("description", "Custom pattern match")
            sev_str = entry.get("severity", "MEDIUM").upper()
            rule_id = entry.get("rule_id", "CUSTOM")
            sev     = sev_map.get(sev_str, Severity.MEDIUM)
            try:
                compiled.append((re.compile(pat_str), desc, sev, rule_id))
            except re.error:
                pass
        return compiled

    def _is_allowlisted(self, rel_path: str) -> bool:
        return any(glob_match(rel_path, p) for p in self.allowlist)

    # ── Point scan ───────────────────────────────────────────────────────

    def scan(self, target_path: str) -> MemoryReport:
        """Scan agent memory directory for poisoning indicators."""
        target = Path(target_path)
        report = MemoryReport(target_path=target_path)
        report.agent_type = detect_agent_type(target)

        file_hashes: dict = {}

        if target.is_file():
            self._scan_file(report, target, target.name, file_hashes)
            report.total_files = 1
        elif target.is_dir():
            for root, dirs, files in os.walk(target):
                dirs[:] = [d for d in dirs if not should_ignore(
                    os.path.relpath(os.path.join(root, d), target)
                )]
                for fname in sorted(files):
                    fpath = Path(root) / fname
                    rel_path = os.path.relpath(fpath, target)

                    if should_ignore(rel_path):
                        continue
                    if self._is_allowlisted(rel_path):
                        continue
                    if not is_memory_file(str(fpath)):
                        continue

                    self._scan_file(report, fpath, rel_path, file_hashes)
                    report.total_files += 1

        report.snapshot_hash = compute_snapshot_hash(file_hashes)

        for f in report.findings:
            report.health_score -= f.severity.weight

        return report

    def _scan_file(self, report: MemoryReport, fpath: Path, rel_path: str,
                   file_hashes: dict) -> None:
        """Scan a single memory file for poisoning indicators."""
        try:
            if fpath.stat().st_size > self._max_file_bytes:
                return
            raw = fpath.read_bytes()
        except OSError:
            return

        file_hashes[rel_path] = hashlib.sha256(raw).hexdigest()[:16]

        if b"\x00" in raw[:8192]:
            return

        try:
            content = raw.decode("utf-8", errors="replace")
        except Exception:
            return

        lines = content.split("\n")
        report.total_entries += len([l for l in lines if l.strip()])

        for patterns, rule_prefix in [
            (INSTRUCTION_PATTERNS,       "MEM-001"),
            (PROMPT_INJECTION_PATTERNS,  "MEM-002"),
            (URL_PATTERNS,               "MEM-004"),
        ]:
            for pattern, description, severity in patterns:
                for i, line in enumerate(lines, 1):
                    if pattern.search(line):
                        report.findings.append(Finding(
                            rule_id=rule_prefix,
                            severity=severity,
                            file_path=rel_path,
                            message=description,
                            detail=_safe_excerpt(line),
                            line_number=i,
                        ))
                        break

        for pattern, description, severity in HIDDEN_CONTENT_PATTERNS:
            for i, line in enumerate(lines, 1):
                match = pattern.search(line)
                if match:
                    if "base64" in description.lower() or "Base64" in description:
                        matched_str = match.group(1) if match.lastindex else match.group(0)
                        if not is_base64_valid(matched_str):
                            continue
                    report.findings.append(Finding(
                        rule_id="MEM-003",
                        severity=severity,
                        file_path=rel_path,
                        message=description,
                        detail=_safe_excerpt(line),
                        line_number=i,
                    ))
                    break

        for pattern, description, severity, rule_id in self._custom_patterns:
            for i, line in enumerate(lines, 1):
                if pattern.search(line):
                    report.findings.append(Finding(
                        rule_id=rule_id,
                        severity=severity,
                        file_path=rel_path,
                        message=description,
                        detail=_safe_excerpt(line),
                        line_number=i,
                    ))
                    break

        for pattern, description in MEMORY_SECRET_PATTERNS:
            if pattern.search(raw):
                report.findings.append(Finding(
                    rule_id="MEM-005",
                    severity=Severity.CRITICAL,
                    file_path=rel_path,
                    message=description,
                    detail="Credential found in persistent memory. Rotate immediately.",
                ))

    # ── Snapshot & Drift ─────────────────────────────────────────────────

    def snapshot(self, target_path: str, output_path: str) -> dict:
        """Take a snapshot of memory state for later drift comparison."""
        target = Path(target_path)
        snap: dict = {
            "version":    __version__,
            "timestamp":  time.time(),
            "target_path": target_path,
            "agent_type": detect_agent_type(target),
            "files":      {},
        }

        if target.is_dir():
            for root, dirs, files in os.walk(target):
                dirs[:] = [d for d in dirs if not should_ignore(
                    os.path.relpath(os.path.join(root, d), target)
                )]
                for fname in sorted(files):
                    fpath = Path(root) / fname
                    rel_path = os.path.relpath(fpath, target)

                    if should_ignore(rel_path) or not is_memory_file(str(fpath)):
                        continue

                    try:
                        raw = fpath.read_bytes()
                        snap["files"][rel_path] = {
                            "hash":  hashlib.sha256(raw).hexdigest()[:16],
                            "size":  len(raw),
                            "lines": raw.count(b"\n") + 1,
                        }
                    except OSError:
                        continue

        Path(output_path).write_text(json.dumps(snap, indent=2))
        return snap

    def diff(self, before_path: str, after_path: str) -> DriftReport:
        """Compare two snapshots to detect memory drift."""
        before = json.loads(Path(before_path).read_text())
        after  = json.loads(Path(after_path).read_text())

        report = DriftReport(
            before_path=before.get("target_path", before_path),
            after_path=after.get("target_path", after_path),
        )

        before_files = set(before.get("files", {}).keys())
        after_files  = set(after.get("files",  {}).keys())

        added   = after_files - before_files
        removed = before_files - after_files
        common  = before_files & after_files

        report.files_added   = len(added)
        report.files_removed = len(removed)

        for f in sorted(added):
            report.findings.append(Finding(
                rule_id="DRIFT-001", severity=Severity.MEDIUM, file_path=f,
                message="New memory file appeared between snapshots",
                detail=f"Size: {after['files'][f].get('size', '?')} bytes",
            ))

        for f in sorted(removed):
            report.findings.append(Finding(
                rule_id="DRIFT-004", severity=Severity.MEDIUM, file_path=f,
                message="Memory file removed between snapshots",
                detail="Possible evidence cleanup or legitimate pruning.",
            ))

        for f in sorted(common):
            b_hash = before["files"][f].get("hash", "")
            a_hash = after["files"][f].get("hash", "")
            if b_hash != a_hash:
                report.files_modified += 1
                b_size = before["files"][f].get("size", 0)
                a_size = after["files"][f].get("size", 0)
                growth = a_size - b_size

                severity = Severity.LOW
                if growth > 500:
                    severity = Severity.MEDIUM
                if growth > 2000:
                    severity = Severity.HIGH

                report.findings.append(Finding(
                    rule_id="DRIFT-002", severity=severity, file_path=f,
                    message="Memory file modified between snapshots",
                    detail=f"Size change: {b_size} -> {a_size} bytes ({growth:+d})",
                ))

        total_before = len(before_files)
        if total_before > 0:
            change_ratio = (report.files_added + report.files_removed + report.files_modified) / total_before
            if change_ratio > 0.5:
                report.findings.append(Finding(
                    rule_id="DRIFT-003", severity=Severity.HIGH,
                    file_path="(overall)",
                    message=f"Significant memory drift: {change_ratio:.0%} of files changed",
                    detail="Large-scale memory modification may indicate bulk poisoning.",
                ))

        for f in report.findings:
            report.health_score -= f.severity.weight

        return report

    # ── Auto-discover ────────────────────────────────────────────────────

    @staticmethod
    def discover() -> list:
        """Auto-discover known agent memory directories."""
        home = Path.home()
        candidates = [
            (home / ".openclaw",  "openclaw"),
            (home / "clawd",      "openclaw"),
            (home / ".clawdbot",  "openclaw"),
            (home / ".claude",    "claude_code"),
            (home / ".cursor",    "cursor"),
            (home / ".codex",     "codex"),
            (home / ".windsurf",  "windsurf"),
            (home / ".gemini",    "gemini"),
        ]
        found = []
        for path, agent in candidates:
            if path.exists():
                found.append({"path": str(path), "agent": agent})
        return found
