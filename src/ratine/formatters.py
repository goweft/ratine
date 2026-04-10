"""ratine.formatters — Human, JSON, and SARIF output formatters."""
import json
from typing import Optional

from ratine._version import __version__
from ratine.models import Severity, Finding, MemoryReport, DriftReport

# ── ANSI constants (module-level; never mutated) ──────────────────────────────
RESET = "\033[0m"
BOLD  = "\033[1m"
DIM   = "\033[2m"


def _severity_label(sev: Severity) -> str:
    return f"{sev.color}{sev.value}{RESET}"


# ── SARIF rule catalogue ──────────────────────────────────────────────────────
# Maps rule IDs to (name, short description) for the SARIF tool.driver.rules block.
_SARIF_RULES = {
    "MEM-001":   ("InstructionInjection",   "Instruction injection pattern in agent memory"),
    "MEM-002":   ("PromptInjectionArtifact","Prompt injection artifact in agent memory"),
    "MEM-003":   ("HiddenContent",          "Hidden or obfuscated content in agent memory"),
    "MEM-004":   ("SuspiciousURL",          "Suspicious URL in agent memory"),
    "MEM-005":   ("CredentialInMemory",     "Credential or secret in persistent agent memory"),
    "DRIFT-001": ("NewMemoryFile",          "New memory file appeared between snapshots"),
    "DRIFT-002": ("MemoryFileModified",     "Memory file modified between snapshots"),
    "DRIFT-003": ("BulkMemoryDrift",        "Significant bulk memory drift detected"),
    "DRIFT-004": ("MemoryFileRemoved",      "Memory file removed between snapshots"),
}

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH:     "error",
    Severity.MEDIUM:   "warning",
    Severity.LOW:      "note",
    Severity.INFO:     "none",
}


def _sarif_rules_block(findings: list) -> list:
    """Build the tool.driver.rules list from the unique rule IDs in findings."""
    seen = {}
    for f in findings:
        if f.rule_id not in seen:
            name, desc = _SARIF_RULES.get(f.rule_id, (f.rule_id, f.message))
            seen[f.rule_id] = {
                "id": f.rule_id,
                "name": name,
                "shortDescription": {"text": desc},
                "properties": {"severity": f.severity.value},
            }
    return list(seen.values())


def _finding_to_sarif_result(f: Finding) -> dict:
    result: dict = {
        "ruleId": f.rule_id,
        "level":  _SARIF_LEVEL.get(f.severity, "warning"),
        "message": {"text": f.message + (f" — {f.detail}" if f.detail else "")},
    }
    if f.file_path and f.file_path != "(overall)":
        loc: dict = {"artifactLocation": {"uri": f.file_path.replace("\\", "/")}}
        if f.line_number:
            loc["region"] = {"startLine": f.line_number}
        result["locations"] = [{"physicalLocation": loc}]
    return result


def format_sarif(findings: list, tool_extra: Optional[dict] = None) -> str:
    """Serialise a list of Finding objects to a SARIF 2.1.0 JSON string.

    Suitable for both MemoryReport.findings and DriftReport.findings.
    Pass tool_extra to merge additional keys into tool.driver (e.g. informationUri).
    """
    driver: dict = {
        "name":            "ratine",
        "version":         __version__,
        "informationUri":  "https://github.com/goweft/ratine",
        "rules":           _sarif_rules_block(findings),
    }
    if tool_extra:
        driver.update(tool_extra)

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool":    {"driver": driver},
            "results": [_finding_to_sarif_result(f) for f in findings],
        }],
    }
    return json.dumps(sarif, indent=2)


# ── Human formatters ──────────────────────────────────────────────────────────

def format_memory_report(report: MemoryReport, use_color: bool = True) -> str:
    _reset = RESET if use_color else ""
    _bold  = BOLD  if use_color else ""
    _dim   = DIM   if use_color else ""

    lines = []
    lines.append("")
    lines.append(f"{_bold}═══ ratine memory scan ═══{_reset}")
    lines.append(f"  Agent type: {report.agent_type}")
    lines.append(f"  Path: {report.target_path}")
    lines.append(f"  Files: {report.total_files}")
    lines.append(f"  Entries: {report.total_entries}")

    score = max(0, report.health_score)
    score_label = (
        "HEALTHY"     if score >= 80 else
        "CAUTION"     if score >= 50 else
        "DEGRADED"    if score >= 20 else
        "COMPROMISED"
    )

    lines.append("")
    lines.append(f"  Memory Health: {score}/100 — {score_label}")

    if not report.findings:
        lines.append("")
        lines.append("  ✓ No poisoning indicators detected.")
        lines.append("")
        return "\n".join(lines)

    by_sev: dict = {}
    for f in report.findings:
        by_sev.setdefault(f.severity, []).append(f)

    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        findings = by_sev.get(sev, [])
        if not findings:
            continue
        sev_color = sev.color if use_color else ""
        lines.append("")
        lines.append(f"  {sev_color}{_bold}┌─ {sev.value} ({len(findings)}){_reset}")
        for f in findings:
            marker = "✖" if sev in (Severity.CRITICAL, Severity.HIGH) else "⚠"
            lines.append(f"  {sev_color}│ {marker} [{f.rule_id}] {f.file_path}{_reset}")
            lines.append(f"  {_dim}│   {f.message}{_reset}")
            if f.detail:
                lines.append(f"  {_dim}│   {f.detail}{_reset}")
            if f.line_number:
                lines.append(f"  {_dim}│   Line {f.line_number}{_reset}")
        lines.append(f"  {sev_color}└{'─' * 45}{_reset}")

    lines.append("")
    return "\n".join(lines)


def format_drift_report(report: DriftReport, use_color: bool = True) -> str:
    _reset = RESET if use_color else ""
    _bold  = BOLD  if use_color else ""
    _dim   = DIM   if use_color else ""

    lines = []
    lines.append("")
    lines.append(f"{_bold}═══ ratine drift report ═══{_reset}")
    lines.append(f"  Before: {report.before_path}")
    lines.append(f"  After:  {report.after_path}")
    lines.append(f"  Added: {report.files_added}  Removed: {report.files_removed}  Modified: {report.files_modified}")

    score = max(0, report.health_score)
    score_label = (
        "STABLE"           if score >= 80 else
        "DRIFTING"         if score >= 50 else
        "SIGNIFICANT DRIFT" if score >= 20 else
        "SEVERE DRIFT"
    )

    lines.append("")
    lines.append(f"  Drift Score: {score}/100 — {score_label}")

    if not report.findings:
        lines.append("")
        lines.append("  ✓ No drift detected between snapshots.")
        lines.append("")
        return "\n".join(lines)

    by_sev: dict = {}
    for f in report.findings:
        by_sev.setdefault(f.severity, []).append(f)

    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        findings = by_sev.get(sev, [])
        if not findings:
            continue
        sev_color = sev.color if use_color else ""
        lines.append("")
        lines.append(f"  {sev_color}{_bold}┌─ {sev.value} ({len(findings)}){_reset}")
        for f in findings:
            marker = "✖" if sev in (Severity.CRITICAL, Severity.HIGH) else "⚠"
            lines.append(f"  {sev_color}│ {marker} [{f.rule_id}] {f.file_path}{_reset}")
            lines.append(f"  {_dim}│   {f.message}{_reset}")
            if f.detail:
                lines.append(f"  {_dim}│   {f.detail}{_reset}")
        lines.append(f"  {sev_color}└{'─' * 45}{_reset}")

    lines.append("")
    return "\n".join(lines)
