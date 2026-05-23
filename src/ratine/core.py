#!/usr/bin/env python3
"""
ratine.core — Public re-export module.

All symbols are defined in their respective sub-modules:
  ratine._version  — __version__
  ratine.models    — Severity, Finding, MemoryReport, DriftReport
  ratine.patterns  — detection pattern constants
  ratine.scanner   — MemoryGuard + utility functions
  ratine.formatters — format_memory_report, format_drift_report, format_sarif
  ratine.cli       — main()

This file exists for backwards compatibility so that
``from ratine.core import MemoryGuard`` continues to work.
"""
from ratine._version import __version__                                     # noqa: F401
from ratine.models import Severity, Finding, MemoryReport, DriftReport     # noqa: F401
from ratine.patterns import (                                                # noqa: F401
    INSTRUCTION_PATTERNS, PROMPT_INJECTION_PATTERNS, HIDDEN_CONTENT_PATTERNS,
    MEMORY_SECRET_PATTERNS, URL_PATTERNS,
    AGENT_SIGNATURES, IGNORE_PATTERNS, MEMORY_EXTENSIONS,
)
from ratine.scanner import (                                                 # noqa: F401
    MemoryGuard,
    glob_match, should_ignore, is_memory_file,
    detect_agent_type, compute_snapshot_hash, is_base64_valid,
)
from ratine.formatters import (                                              # noqa: F401
    RESET, BOLD, DIM,
    format_memory_report, format_drift_report, format_sarif,
)
from ratine.cli import main                                                  # noqa: F401
from ratine.semantic import SemanticAnalyzer  # noqa: F401
