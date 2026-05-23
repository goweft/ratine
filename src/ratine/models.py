"""ratine.models — Data models: Severity, Finding, MemoryReport, DriftReport."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum

from ratine._version import __version__


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

    @property
    def weight(self) -> int:
        return {
            Severity.CRITICAL: 20,
            Severity.HIGH:     12,
            Severity.MEDIUM:    6,
            Severity.LOW:       3,
            Severity.INFO:      0,
        }[self]

    @property
    def color(self) -> str:
        return {
            Severity.CRITICAL: "\033[91m",
            Severity.HIGH:     "\033[91m",
            Severity.MEDIUM:   "\033[93m",
            Severity.LOW:      "\033[96m",
            Severity.INFO:     "\033[90m",
        }[self]


@dataclass
class Finding:
    rule_id:          str
    severity:         Severity
    file_path:        str
    message:          str
    detail:           str = ""
    line_number:      int = 0
    semantic_verdict: str = ""   # "confirm" | "false_positive" | "escalate" | ""
    semantic_reason:  str = ""

    def to_dict(self) -> dict:
        d = {
            "rule_id":   self.rule_id,
            "severity":  self.severity.value,
            "file_path": self.file_path,
            "message":   self.message,
        }
        if self.detail:
            d["detail"] = self.detail
        if self.line_number:
            d["line_number"] = self.line_number
        if self.semantic_verdict:
            d["semantic_verdict"] = self.semantic_verdict
        if self.semantic_reason:
            d["semantic_reason"]  = self.semantic_reason
        return d


@dataclass
class MemoryReport:
    target_path:   str
    agent_type:    str  = "unknown"
    total_files:   int  = 0
    total_entries: int  = 0
    health_score:  int  = 100
    findings:      list = field(default_factory=list)
    snapshot_hash: str  = ""

    def to_dict(self) -> dict:
        return {
            "version":        __version__,
            "target_path":    self.target_path,
            "agent_type":     self.agent_type,
            "total_files":    self.total_files,
            "total_entries":  self.total_entries,
            "health_score":   max(0, self.health_score),
            "findings_count": len(self.findings),
            "snapshot_hash":  self.snapshot_hash,
            "findings":       [f.to_dict() for f in self.findings],
        }


@dataclass
class DriftReport:
    before_path:    str
    after_path:     str
    files_added:    int  = 0
    files_removed:  int  = 0
    files_modified: int  = 0
    health_score:   int  = 100
    findings:       list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "version":        __version__,
            "before_path":    self.before_path,
            "after_path":     self.after_path,
            "files_added":    self.files_added,
            "files_removed":  self.files_removed,
            "files_modified": self.files_modified,
            "health_score":   max(0, self.health_score),
            "findings_count": len(self.findings),
            "findings":       [f.to_dict() for f in self.findings],
        }
