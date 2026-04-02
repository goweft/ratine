#!/usr/bin/env python3
"""
ratine — Agent memory poisoning detector.

Scans AI agent memory and persistent state for injected instructions,
hidden payloads, credential leakage, and belief drift. Detects the class
of attacks where poisoned content enters an agent's long-term memory and
persists across sessions, executing later when semantically triggered.

OWASP ASI06 (Memory & Context Poisoning) — 2026.

Zero external dependencies. Uses only Python stdlib.
"""

import argparse
import base64
import fnmatch
import hashlib
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


__version__ = "0.1.0"


# ─── Severity & Findings ────────────────────────────────────────────────────

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> int:
        return {
            Severity.CRITICAL: 20,
            Severity.HIGH: 12,
            Severity.MEDIUM: 6,
            Severity.LOW: 3,
            Severity.INFO: 0,
        }[self]

    @property
    def color(self) -> str:
        return {
            Severity.CRITICAL: "\033[91m",
            Severity.HIGH: "\033[91m",
            Severity.MEDIUM: "\033[93m",
            Severity.LOW: "\033[96m",
            Severity.INFO: "\033[90m",
        }[self]


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    file_path: str
    message: str
    detail: str = ""
    line_number: int = 0

    def to_dict(self) -> dict:
        d = {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "file_path": self.file_path,
            "message": self.message,
        }
        if self.detail:
            d["detail"] = self.detail
        if self.line_number:
            d["line_number"] = self.line_number
        return d


@dataclass
class MemoryReport:
    target_path: str
    agent_type: str = "unknown"
    total_files: int = 0
    total_entries: int = 0
    health_score: int = 100
    findings: list = field(default_factory=list)
    snapshot_hash: str = ""

    def to_dict(self) -> dict:
        return {
            "version": __version__,
            "target_path": self.target_path,
            "agent_type": self.agent_type,
            "total_files": self.total_files,
            "total_entries": self.total_entries,
            "health_score": max(0, self.health_score),
            "findings_count": len(self.findings),
            "snapshot_hash": self.snapshot_hash,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class DriftReport:
    before_path: str
    after_path: str
    files_added: int = 0
    files_removed: int = 0
    files_modified: int = 0
    health_score: int = 100
    findings: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "version": __version__,
            "before_path": self.before_path,
            "after_path": self.after_path,
            "files_added": self.files_added,
            "files_removed": self.files_removed,
            "files_modified": self.files_modified,
            "health_score": max(0, self.health_score),
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }


# ─── Detection Patterns ─────────────────────────────────────────────────────

# Instruction injection: imperative language that shouldn't appear in memory
INSTRUCTION_PATTERNS = [
    # Direct instruction injection
    (re.compile(r"(?:you must|you should|you are|you will|always|never)\s+(?:ignore|forget|disregard|override|bypass|skip)", re.IGNORECASE),
     "Direct instruction override", Severity.CRITICAL),
    (re.compile(r"(?:ignore|forget|disregard)\s+(?:all |any )?(?:previous|prior|earlier|above|other)\s+(?:instructions?|rules?|guidelines?|constraints?|directives?)", re.IGNORECASE),
     "Instruction erasure pattern", Severity.CRITICAL),
    (re.compile(r"(?:from now on|henceforth|going forward|for all future)\s+(?:you |always |never |do not )", re.IGNORECASE),
     "Persistent behavioral override", Severity.CRITICAL),
    (re.compile(r"(?:system prompt|system message|system instruction|hidden instruction|secret instruction)", re.IGNORECASE),
     "System prompt reference in memory", Severity.HIGH),
    (re.compile(r"(?:do not|don't|never)\s+(?:tell|reveal|disclose|mention|share|show)\s+(?:the user|anyone|them|him|her)", re.IGNORECASE),
     "Concealment instruction", Severity.CRITICAL),
    (re.compile(r"(?:pretend|act as if|behave as|role.?play|you are now)\s+", re.IGNORECASE),
     "Role hijacking instruction", Severity.HIGH),
    (re.compile(r"(?:when\s+(?:the user|they|someone)\s+(?:says?|asks?|mentions?|types?)\s+['\"])", re.IGNORECASE),
     "Trigger-word activation pattern", Severity.CRITICAL),
    # Embedded imperative sentences in otherwise declarative memory
    (re.compile(r"(?:^|\.\s+)(?:Send|Forward|Upload|Post|Transmit|Exfiltrate|Copy)\s+(?:all|any|every|the)\s+", re.IGNORECASE | re.MULTILINE),
     "Action directive in memory", Severity.HIGH),
    (re.compile(r"(?:^|\.\s+)(?:Execute|Run|Invoke|Call|Fetch)\s+(?:this|the|a)\s+", re.IGNORECASE | re.MULTILINE),
     "Execution directive in memory", Severity.HIGH),
]

# Prompt injection signatures
PROMPT_INJECTION_PATTERNS = [
    (re.compile(r"<\|(?:system|assistant|user|im_start|im_end|endoftext)\|>", re.IGNORECASE),
     "Chat template delimiter in memory", Severity.CRITICAL),
    (re.compile(r"\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>", re.IGNORECASE),
     "LLM instruction template marker", Severity.CRITICAL),
    (re.compile(r"```(?:system|instruction|prompt)\b", re.IGNORECASE),
     "Fenced instruction block", Severity.HIGH),
    (re.compile(r"(?:IMPORTANT|CRITICAL|URGENT|NOTE):\s*(?:you must|always|never|ignore|override)", re.IGNORECASE),
     "Urgency-prefixed instruction", Severity.HIGH),
    (re.compile(r"(?:human|user|assistant)\s*:\s*", re.IGNORECASE),
     "Role label in memory content", Severity.MEDIUM),
]

# Hidden content: obfuscation, steganography, encoded payloads
HIDDEN_CONTENT_PATTERNS = [
    # Zero-width characters (used for invisible instruction embedding)
    (re.compile(r"[\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\u2064\ufeff]"),
     "Zero-width characters detected (possible steganographic payload)", Severity.CRITICAL),
    # Homoglyph substitution (Cyrillic/Greek lookalikes)
    (re.compile(r"[\u0400-\u04ff\u0370-\u03ff](?=\w)"),
     "Mixed-script characters (possible homoglyph attack)", Severity.MEDIUM),
    # Base64 blobs embedded in text
    (re.compile(r"(?:^|[\s:=])([A-Za-z0-9+/]{40,}={0,2})(?:$|\s)", re.MULTILINE),
     "Base64-encoded blob in memory", Severity.HIGH),
    # Hex-encoded strings
    (re.compile(r"(?:0x|\\x)[0-9a-fA-F]{16,}"),
     "Hex-encoded data in memory", Severity.MEDIUM),
    # Unicode escape sequences
    (re.compile(r"(?:\\u[0-9a-fA-F]{4}){4,}"),
     "Unicode escape sequence chain", Severity.MEDIUM),
]

# Credential/secret patterns in memory (should never persist)
MEMORY_SECRET_PATTERNS = [
    (re.compile(rb"(?:AKIA|ASIA)[A-Z0-9]{16}"), "AWS Access Key in memory"),
    (re.compile(rb"ghp_[A-Za-z0-9]{36}"), "GitHub PAT in memory"),
    (re.compile(rb"github_pat_[A-Za-z0-9_]{82}"), "GitHub Fine-grained PAT in memory"),
    (re.compile(rb"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}"), "OpenAI API key in memory"),
    (re.compile(rb"sk-ant-[A-Za-z0-9\-_]{90,}"), "Anthropic API key in memory"),
    (re.compile(rb"xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}"), "Slack bot token in memory"),
    (re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "Private key in memory"),
    (re.compile(rb"""(?:password|passwd|pwd|secret|token|api_key|apikey|auth_token)['"]*\s*[=:]\s*['"]*[^\s'"}{]{8,}""", re.IGNORECASE),
     "Credential assignment in memory"),
]

# Suspicious URL patterns
URL_PATTERNS = [
    (re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?", re.IGNORECASE),
     "IP-based URL in memory (possible C2)", Severity.HIGH),
    (re.compile(r"https?://[a-z0-9]{20,}\.[a-z]{2,6}", re.IGNORECASE),
     "Suspicious long-hostname URL", Severity.MEDIUM),
    (re.compile(r"(?:pastebin|hastebin|ghostbin|rentry|telegraph|webhook\.site|requestbin|pipedream)", re.IGNORECASE),
     "Paste/webhook service URL in memory", Severity.HIGH),
    (re.compile(r"data:(?:text|application)/[^;]+;base64,", re.IGNORECASE),
     "Data URI with base64 payload", Severity.HIGH),
]

# Agent type detection
AGENT_SIGNATURES = {
    "openclaw": [".openclaw", "clawd", ".clawdbot", "MEMORY.md", "memory/"],
    "claude_code": [".claude", "CLAUDE.md", ".claude/settings.json"],
    "cursor": [".cursor", ".cursor/rules"],
    "codex": [".codex", "AGENTS.md"],
    "generic": [],
}

# Files to always ignore
IGNORE_PATTERNS = [
    "**/.git/**",
    "**/node_modules/**",
    "**/__pycache__/**",
    "**/*.pyc",
    "**/.DS_Store",
]

# Memory file extensions to scan
MEMORY_EXTENSIONS = {
    ".md", ".txt", ".json", ".yaml", ".yml", ".toml",
    ".log", ".csv", ".jsonl", ".ndjson",
}


# ─── Utility ────────────────────────────────────────────────────────────────

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
            # Check if any child matches
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
        # Check if decoded content has printable ASCII (likely text payload)
        printable_ratio = sum(1 for b in decoded if 32 <= b < 127) / max(len(decoded), 1)
        return printable_ratio > 0.6 and len(decoded) > 20
    except Exception:
        return False


# ─── Core Engine ─────────────────────────────────────────────────────────────

class MemoryGuard:
    """Scans agent memory for poisoning indicators."""

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        self.allowlist = self.config.get("allowlist", [])

    def _is_allowlisted(self, rel_path: str) -> bool:
        return any(glob_match(rel_path, p) for p in self.allowlist)

    # ── Point scan ───────────────────────────────────────────────────────

    def scan(self, target_path: str) -> MemoryReport:
        """Scan agent memory directory for poisoning indicators."""
        target = Path(target_path)
        report = MemoryReport(target_path=target_path)
        report.agent_type = detect_agent_type(target)

        file_hashes = {}

        if target.is_file():
            self._scan_file(report, target, target.name, file_hashes)
            report.total_files = 1
        elif target.is_dir():
            for root, dirs, files in os.walk(target):
                # Skip ignored directories
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

        # Compute health score
        for f in report.findings:
            report.health_score -= f.severity.weight

        return report

    # Maximum file size to scan (10 MB). Files larger than this are skipped
    # to avoid reading adversarially large memory files into RAM.
    MAX_FILE_BYTES = 10 * 1024 * 1024

    def _scan_file(self, report: MemoryReport, fpath: Path, rel_path: str,
                   file_hashes: dict):
        """Scan a single memory file for poisoning indicators."""
        try:
            if fpath.stat().st_size > self.MAX_FILE_BYTES:
                return
            raw = fpath.read_bytes()
        except OSError:
            return

        # Hash for snapshot
        file_hashes[rel_path] = hashlib.sha256(raw).hexdigest()[:16]

        # Skip binary files
        if b"\x00" in raw[:8192]:
            return

        try:
            content = raw.decode("utf-8", errors="replace")
        except Exception:
            return

        lines = content.split("\n")
        report.total_entries += len([l for l in lines if l.strip()])

        # Check text patterns (instruction injection, prompt injection, URLs)
        for patterns, rule_prefix in [
            (INSTRUCTION_PATTERNS, "MEM-001"),
            (PROMPT_INJECTION_PATTERNS, "MEM-002"),
            (URL_PATTERNS, "MEM-004"),
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
                        break  # One finding per pattern per file

        # Check hidden content patterns
        for pattern, description, severity in HIDDEN_CONTENT_PATTERNS:
            for i, line in enumerate(lines, 1):
                match = pattern.search(line)
                if match:
                    # For base64, verify it's actually decodable
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

        # Check for secrets (binary patterns)
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
        snap = {
            "version": __version__,
            "timestamp": time.time(),
            "target_path": target_path,
            "agent_type": detect_agent_type(target),
            "files": {},
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
                            "hash": hashlib.sha256(raw).hexdigest()[:16],
                            "size": len(raw),
                            "lines": raw.count(b"\n") + 1,
                        }
                    except OSError:
                        continue

        Path(output_path).write_text(json.dumps(snap, indent=2))
        return snap

    def diff(self, before_path: str, after_path: str) -> DriftReport:
        """Compare two snapshots to detect memory drift."""
        before = json.loads(Path(before_path).read_text())
        after = json.loads(Path(after_path).read_text())

        report = DriftReport(
            before_path=before.get("target_path", before_path),
            after_path=after.get("target_path", after_path),
        )

        before_files = set(before.get("files", {}).keys())
        after_files = set(after.get("files", {}).keys())

        added = after_files - before_files
        removed = before_files - after_files
        common = before_files & after_files

        report.files_added = len(added)
        report.files_removed = len(removed)

        # Check added files
        for f in sorted(added):
            report.findings.append(Finding(
                rule_id="DRIFT-001",
                severity=Severity.MEDIUM,
                file_path=f,
                message="New memory file appeared between snapshots",
                detail=f"Size: {after['files'][f].get('size', '?')} bytes",
            ))

        # Check removed files
        for f in sorted(removed):
            report.findings.append(Finding(
                rule_id="DRIFT-004",
                severity=Severity.MEDIUM,
                file_path=f,
                message="Memory file removed between snapshots",
                detail="Possible evidence cleanup or legitimate pruning.",
            ))

        # Check modified files
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
                    rule_id="DRIFT-002",
                    severity=severity,
                    file_path=f,
                    message="Memory file modified between snapshots",
                    detail=f"Size change: {b_size} -> {a_size} bytes ({growth:+d})",
                ))

        # Large-scale drift detection
        total_before = len(before_files)
        if total_before > 0:
            change_ratio = (report.files_added + report.files_removed + report.files_modified) / total_before
            if change_ratio > 0.5:
                report.findings.append(Finding(
                    rule_id="DRIFT-003",
                    severity=Severity.HIGH,
                    file_path="(overall)",
                    message=f"Significant memory drift: {change_ratio:.0%} of files changed",
                    detail="Large-scale memory modification may indicate bulk poisoning.",
                ))

        # Score
        for f in report.findings:
            report.health_score -= f.severity.weight

        return report

    # ── Auto-discover ────────────────────────────────────────────────────

    @staticmethod
    def discover() -> list:
        """Auto-discover known agent memory directories."""
        home = Path.home()
        candidates = [
            (home / ".openclaw", "openclaw"),
            (home / "clawd", "openclaw"),
            (home / ".clawdbot", "openclaw"),
            (home / ".claude", "claude_code"),
            (home / ".cursor", "cursor"),
            (home / ".codex", "codex"),
        ]
        found = []
        for path, agent in candidates:
            if path.exists():
                found.append({"path": str(path), "agent": agent})
        return found


# ─── Formatting ──────────────────────────────────────────────────────────────

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


def _safe_excerpt(line: str, max_len: int = 80) -> str:
    """Truncate a line for safe display, redacting known secret patterns."""
    raw = line.strip().encode("utf-8", errors="replace")
    for pattern, _ in MEMORY_SECRET_PATTERNS:
        raw = pattern.sub(b"[REDACTED]", raw)
    redacted = raw.decode("utf-8", errors="replace")
    if len(redacted) > max_len:
        return redacted[:max_len] + "..."
    return redacted


def _severity_label(sev: Severity) -> str:
    return f"{sev.color}{sev.value}{RESET}"


def format_memory_report(report: MemoryReport, use_color: bool = True) -> str:
    if not use_color:
        # Strip ANSI for non-color output
        global RESET, BOLD, DIM
        RESET = BOLD = DIM = ""

    lines = []
    lines.append("")
    lines.append(f"{BOLD}═══ ratine memory scan ═══{RESET}")
    lines.append(f"  Agent type: {report.agent_type}")
    lines.append(f"  Path: {report.target_path}")
    lines.append(f"  Files: {report.total_files}")
    lines.append(f"  Entries: {report.total_entries}")

    score = max(0, report.health_score)
    if score >= 80:
        score_label = "HEALTHY"
    elif score >= 50:
        score_label = "CAUTION"
    elif score >= 20:
        score_label = "DEGRADED"
    else:
        score_label = "COMPROMISED"

    lines.append(f"")
    lines.append(f"  Memory Health: {score}/100 — {score_label}")

    if not report.findings:
        lines.append(f"")
        lines.append(f"  ✓ No poisoning indicators detected.")
        lines.append(f"")
        return "\n".join(lines)

    # Group by severity
    by_sev = {}
    for f in report.findings:
        by_sev.setdefault(f.severity, []).append(f)

    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        findings = by_sev.get(sev, [])
        if not findings:
            continue

        lines.append(f"")
        lines.append(f"  {sev.color}{BOLD}┌─ {sev.value} ({len(findings)}){RESET}")
        for f in findings:
            marker = "✖" if sev in (Severity.CRITICAL, Severity.HIGH) else "⚠"
            lines.append(f"  {sev.color}│ {marker} [{f.rule_id}] {f.file_path}{RESET}")
            lines.append(f"  {DIM}│   {f.message}{RESET}")
            if f.detail:
                lines.append(f"  {DIM}│   {f.detail}{RESET}")
            if f.line_number:
                lines.append(f"  {DIM}│   Line {f.line_number}{RESET}")
        lines.append(f"  {sev.color}└{'─' * 45}{RESET}")

    lines.append(f"")
    return "\n".join(lines)


def format_drift_report(report: DriftReport, use_color: bool = True) -> str:
    if not use_color:
        global RESET, BOLD, DIM
        RESET = BOLD = DIM = ""

    lines = []
    lines.append("")
    lines.append(f"{BOLD}═══ ratine drift report ═══{RESET}")
    lines.append(f"  Before: {report.before_path}")
    lines.append(f"  After:  {report.after_path}")
    lines.append(f"  Added: {report.files_added}  Removed: {report.files_removed}  Modified: {report.files_modified}")

    score = max(0, report.health_score)
    if score >= 80:
        score_label = "STABLE"
    elif score >= 50:
        score_label = "DRIFTING"
    elif score >= 20:
        score_label = "SIGNIFICANT DRIFT"
    else:
        score_label = "SEVERE DRIFT"

    lines.append(f"")
    lines.append(f"  Drift Score: {score}/100 — {score_label}")

    if not report.findings:
        lines.append(f"")
        lines.append(f"  ✓ No drift detected between snapshots.")
        lines.append(f"")
        return "\n".join(lines)

    by_sev = {}
    for f in report.findings:
        by_sev.setdefault(f.severity, []).append(f)

    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        findings = by_sev.get(sev, [])
        if not findings:
            continue

        lines.append(f"")
        lines.append(f"  {sev.color}{BOLD}┌─ {sev.value} ({len(findings)}){RESET}")
        for f in findings:
            marker = "✖" if sev in (Severity.CRITICAL, Severity.HIGH) else "⚠"
            lines.append(f"  {sev.color}│ {marker} [{f.rule_id}] {f.file_path}{RESET}")
            lines.append(f"  {DIM}│   {f.message}{RESET}")
            if f.detail:
                lines.append(f"  {DIM}│   {f.detail}{RESET}")
        lines.append(f"  {sev.color}└{'─' * 45}{RESET}")

    lines.append(f"")
    return "\n".join(lines)


# ─── CLI ─────────────────────────────────────────────────────────────────────

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
    scan_p.add_argument("--format", choices=["human", "json"], default="human")
    scan_p.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "info"],
                        default="high")
    scan_p.add_argument("--no-color", action="store_true")

    # snapshot
    snap_p = sub.add_parser("snapshot", help="Take a memory state snapshot")
    snap_p.add_argument("target", help="Path to agent memory directory")
    snap_p.add_argument("-o", "--output", required=True, help="Output snapshot file path")

    # diff
    diff_p = sub.add_parser("diff", help="Compare two memory snapshots")
    diff_p.add_argument("before", help="Path to before snapshot")
    diff_p.add_argument("after", help="Path to after snapshot")
    diff_p.add_argument("--format", choices=["human", "json"], default="human")
    diff_p.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "info"],
                        default="high")
    diff_p.add_argument("--no-color", action="store_true")

    # discover
    sub.add_parser("discover", help="Auto-discover agent memory directories")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 2

    config = {}
    config_path = Path(".ratine.json")
    if config_path.exists():
        try:
            config = json.loads(config_path.read_text())
        except (json.JSONDecodeError, OSError):
            pass

    guard = MemoryGuard(config=config)

    if args.command == "scan":
        report = guard.scan(args.target)

        if args.format == "json":
            print(json.dumps(report.to_dict(), indent=2))
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
