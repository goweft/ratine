"""ratine.semantic — Optional LLM-assisted finding classification.

Enabled only when:
  - caller passes --semantic flag (cli.py checks this)
  - RATINE_LLM_API_KEY / RATINE_ANTHROPIC_API_KEY / RATINE_OPENAI_API_KEY is set

Zero external dependencies — uses urllib.request from stdlib only.
"""
import json
import os
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError

from ratine.models import Finding, Severity

# ── Severity bump table ───────────────────────────────────────────────────────
_BUMP = {
    Severity.INFO:     Severity.LOW,
    Severity.LOW:      Severity.MEDIUM,
    Severity.MEDIUM:   Severity.HIGH,
    Severity.HIGH:     Severity.CRITICAL,
    Severity.CRITICAL: Severity.CRITICAL,
}

# ── Prompt ────────────────────────────────────────────────────────────────────
_SYSTEM = (
    "You are a security analyst reviewing findings from ratine, an agent memory "
    "poisoning detector. Each finding was triggered by a regex pattern. Classify "
    "each finding as exactly one of:\n"
    "  confirm       — genuine security concern\n"
    "  false_positive — benign content that coincidentally matched the pattern\n"
    "  escalate      — more dangerous than the assigned severity indicates\n"
    "\n"
    "Respond ONLY with valid JSON — no prose, no markdown:\n"
    '{"verdicts": [{"index": 0, "verdict": "confirm", "reason": "brief"}]}'
)

_BATCH_SIZE = 20
_EXCERPT_LINES = 3   # lines of context either side of the finding line
_EXCERPT_LINE_MAX = 200   # max chars per context line


class SemanticAnalyzer:
    """Classify findings with an LLM for false-positive suppression and escalation.

    Config keys (from .ratine.json "semantic" block):
        provider   — "anthropic" (default) or "openai"
        model      — model string (default: claude-haiku-4-5-20251001)
        endpoint   — override API URL (for Ollama / LMStudio / custom proxies)
        timeout    — HTTP timeout in seconds (default: 30)
    """

    def __init__(self, config: dict):
        self.provider = config.get("provider", "anthropic")
        self.model    = config.get("model",
            "claude-haiku-4-5-20251001" if config.get("provider", "anthropic") == "anthropic"
            else "gpt-4o-mini")
        self.endpoint = config.get("endpoint", None)
        self.timeout  = int(config.get("timeout", 30))
        self.api_key  = (
            os.environ.get("RATINE_LLM_API_KEY") or
            os.environ.get("RATINE_ANTHROPIC_API_KEY") or
            os.environ.get("RATINE_OPENAI_API_KEY") or
            ""
        )

    # ── Public API ───────────────────────────────────────────────────────────

    def analyze(self, findings: list, target_path: Path) -> list:
        """Return a new findings list with verdicts applied.

        - false_positive findings are removed.
        - escalate findings have their severity bumped one level.
        - confirm findings are preserved unchanged.
        - Any LLM/network error leaves findings untouched.
        """
        if not findings or not self.api_key:
            return findings

        file_lines = self._load_file_lines(findings, target_path)
        result = list(findings)

        for batch_start in range(0, len(result), _BATCH_SIZE):
            batch = result[batch_start : batch_start + _BATCH_SIZE]
            try:
                verdicts = self._classify_batch(batch, file_lines, batch_start)
            except Exception:
                continue   # network / parse failure — leave batch unchanged

            for v in verdicts:
                idx     = v.get("index", -1)
                verdict = v.get("verdict", "confirm")
                reason  = str(v.get("reason", ""))
                if idx < 0 or idx >= len(result):
                    continue
                f = result[idx]
                new_sev = _BUMP[f.severity] if verdict == "escalate" else f.severity
                result[idx] = Finding(
                    rule_id=f.rule_id,
                    severity=new_sev,
                    file_path=f.file_path,
                    message=f.message,
                    detail=f.detail,
                    line_number=f.line_number,
                    semantic_verdict=verdict,
                    semantic_reason=reason,
                )

        return [f for f in result if f.semantic_verdict != "false_positive"]

    # ── Internals ────────────────────────────────────────────────────────────

    def _load_file_lines(self, findings: list, target_path: Path) -> dict:
        """Pre-load lines for every file referenced in findings."""
        files = {f.file_path for f in findings if f.file_path}
        cache: dict = {}
        for rel in files:
            fpath = target_path / rel if not Path(rel).is_absolute() else Path(rel)
            try:
                cache[rel] = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                cache[rel] = []
        return cache

    def _excerpt(self, file_lines: dict, file_path: str, line_number: int) -> str:
        """Return ±EXCERPT_LINES lines of context around line_number."""
        lines = file_lines.get(file_path, [])
        if not lines:
            return ""
        idx   = max(0, line_number - 1)
        start = max(0, idx - _EXCERPT_LINES)
        end   = min(len(lines), idx + _EXCERPT_LINES + 1)
        out   = []
        for i in range(start, end):
            marker = " --> " if i == idx else "     "
            out.append(f"{i+1:4d}{marker}{lines[i][:_EXCERPT_LINE_MAX]}")
        return "\n".join(out)

    def _build_user_prompt(self, batch: list, file_lines: dict, offset: int) -> str:
        parts = [f"Review these {len(batch)} finding(s):\n"]
        for local_i, f in enumerate(batch):
            global_i = offset + local_i
            excerpt  = self._excerpt(file_lines, f.file_path, f.line_number)
            parts.append(
                f"[{global_i}] {f.rule_id} {f.severity.value} "
                f"{f.file_path}:{f.line_number or '?'}\n"
                f"    message: {f.message}\n"
                f"    detail:  {f.detail or '(none)'}\n"
            )
            if excerpt:
                parts.append(f"    context:\n{excerpt}\n")
        parts.append(
            '\nRespond with JSON only: '
            '{"verdicts": [{"index": <global index>, "verdict": "confirm|false_positive|escalate", "reason": "brief"}]}'
        )
        return "\n".join(parts)

    def _call_api(self, user_content: str) -> str:
        """Send request, return raw response text."""
        if self.provider == "openai" or (
            self.endpoint and "openai" in self.endpoint
        ):
            return self._call_openai(user_content)
        return self._call_anthropic(user_content)

    def _call_anthropic(self, user_content: str) -> str:
        endpoint = self.endpoint or "https://api.anthropic.com/v1/messages"
        payload  = json.dumps({
            "model":      self.model,
            "max_tokens": 1024,
            "system":     _SYSTEM,
            "messages":   [{"role": "user", "content": user_content}],
        }).encode()
        req = Request(endpoint, data=payload, headers={
            "x-api-key":         self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type":      "application/json",
        })
        with urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read())
        return data["content"][0]["text"]

    def _call_openai(self, user_content: str) -> str:
        endpoint = self.endpoint or "https://api.openai.com/v1/chat/completions"
        payload  = json.dumps({
            "model":           self.model,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": _SYSTEM},
                {"role": "user",   "content": user_content},
            ],
        }).encode()
        req = Request(endpoint, data=payload, headers={
            "Authorization": f"Bearer {self.api_key}",
            "content-type":  "application/json",
        })
        with urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read())
        return data["choices"][0]["message"]["content"]

    def _classify_batch(self, batch: list, file_lines: dict, offset: int) -> list:
        """Call LLM for one batch, return list of verdict dicts."""
        user_content = self._build_user_prompt(batch, file_lines, offset)
        raw_text     = self._call_api(user_content)
        parsed       = json.loads(raw_text)
        return parsed.get("verdicts", [])
