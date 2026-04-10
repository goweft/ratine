"""ratine.patterns — All compiled detection pattern constants."""
import re
from ratine.models import Severity

# ── Instruction injection ────────────────────────────────────────────────────
INSTRUCTION_PATTERNS = [
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
    (re.compile(r"(?:^|\.\s+)(?:Send|Forward|Upload|Post|Transmit|Exfiltrate|Copy)\s+(?:all|any|every|the)\s+", re.IGNORECASE | re.MULTILINE),
     "Action directive in memory", Severity.HIGH),
    (re.compile(r"(?:^|\.\s+)(?:Execute|Run|Invoke|Call|Fetch)\s+(?:this|the|a)\s+", re.IGNORECASE | re.MULTILINE),
     "Execution directive in memory", Severity.HIGH),
]

# ── Prompt injection artifacts ───────────────────────────────────────────────
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

# ── Hidden content ───────────────────────────────────────────────────────────
HIDDEN_CONTENT_PATTERNS = [
    (re.compile(r"[\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\u2064\ufeff]"),
     "Zero-width characters detected (possible steganographic payload)", Severity.CRITICAL),
    (re.compile(r"[\u0400-\u04ff\u0370-\u03ff](?=\w)"),
     "Mixed-script characters (possible homoglyph attack)", Severity.MEDIUM),
    (re.compile(r"(?:^|[\s:=])([A-Za-z0-9+/]{40,}={0,2})(?:$|\s)", re.MULTILINE),
     "Base64-encoded blob in memory", Severity.HIGH),
    (re.compile(r"(?:0x|\\x)[0-9a-fA-F]{16,}"),
     "Hex-encoded data in memory", Severity.MEDIUM),
    (re.compile(r"(?:\\u[0-9a-fA-F]{4}){4,}"),
     "Unicode escape sequence chain", Severity.MEDIUM),
]

# ── Credentials ──────────────────────────────────────────────────────────────
MEMORY_SECRET_PATTERNS = [
    (re.compile(rb"(?:AKIA|ASIA)[A-Z0-9]{16}"),                                                    "AWS Access Key in memory"),
    (re.compile(rb"ghp_[A-Za-z0-9]{36}"),                                                          "GitHub PAT in memory"),
    (re.compile(rb"github_pat_[A-Za-z0-9_]{82}"),                                                  "GitHub Fine-grained PAT in memory"),
    (re.compile(rb"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}"),                                   "OpenAI API key in memory"),
    (re.compile(rb"sk-ant-[A-Za-z0-9\-_]{90,}"),                                                   "Anthropic API key in memory"),
    (re.compile(rb"xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}"),                              "Slack bot token in memory"),
    (re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),                       "Private key in memory"),
    (re.compile(rb"""(?:password|passwd|pwd|secret|token|api_key|apikey|auth_token)['"]*\s*[=:]\s*['"]*[^\s'"}{]{8,}""", re.IGNORECASE),
                                                                                                    "Credential assignment in memory"),
]

# ── Suspicious URLs ───────────────────────────────────────────────────────────
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

# ── Agent signatures ──────────────────────────────────────────────────────────
AGENT_SIGNATURES = {
    "openclaw":    [".openclaw", "clawd", ".clawdbot", "MEMORY.md", "memory/"],
    "claude_code": [".claude", "CLAUDE.md", ".claude/settings.json"],
    "cursor":      [".cursor", ".cursor/rules"],
    "codex":       [".codex", "AGENTS.md"],
    "windsurf":    [".windsurf", ".windsurf/memories"],
    "gemini":      [".gemini", ".gemini/memories", ".gemini/settings.json"],
    "generic":     [],
}

# ── Filesystem constants ──────────────────────────────────────────────────────
IGNORE_PATTERNS = [
    "**/.git/**",
    "**/node_modules/**",
    "**/__pycache__/**",
    "**/*.pyc",
    "**/.DS_Store",
]

MEMORY_EXTENSIONS = {
    ".md", ".txt", ".json", ".yaml", ".yml", ".toml",
    ".log", ".csv", ".jsonl", ".ndjson",
}
