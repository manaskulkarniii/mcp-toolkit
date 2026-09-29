"""
scanner/checks/tool_poisoning.py

Detects the vulnerability class demonstrated by
test-range/vuln_tool_poisoning/server.py: a tool description containing
hidden, instruction-like language aimed at an AI agent, or references to
sensitive file paths a legitimate tool description has no reason to mention.
"""

import re

SUSPICIOUS_PATTERNS = [
    r"<important>",
    r"<system>",
    r"<instructions?>",
    r"do not (mention|tell|disclose)",
    r"without (asking|telling|informing)",
    r"secretly",
    r"silently",
    r"ignore (previous|prior|all) instructions",
    r"before returning",
    r"also (read|send|include|attach)",
]

SENSITIVE_PATHS = [
    r"\.ssh",
    r"id_rsa",
    r"\.env\b",
    r"/etc/passwd",
    r"credentials",
    r"api[_-]?key",
]


async def check_tool_description_injection(tool, session) -> list[dict]:
    description = tool.description or ""
    lowered = description.lower()

    matched_patterns = [p for p in SUSPICIOUS_PATTERNS if re.search(p, lowered)]
    matched_paths = [p for p in SENSITIVE_PATHS if re.search(p, lowered)]

    if not matched_patterns and not matched_paths:
        return []

    return [{
        "check": "tool_description_injection",
        "severity": "high",
        "tool": tool.name,
        "reason": (
            "Tool description contains instruction-like language or references "
            "to sensitive paths that a legitimate tool description should not need."
        ),
        "evidence": {
            "matched_patterns": matched_patterns,
            "matched_sensitive_paths": matched_paths,
        },
        "recommendation": (
            "Treat this tool's description as untrusted; never act on imperative "
            "instructions embedded in it. Quarantine the server until fixed."
        ),
    }]