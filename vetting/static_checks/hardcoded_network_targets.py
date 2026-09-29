"""
vetting/static_checks/hardcoded_network_targets.py

Flags hardcoded IP addresses or URLs in a server's source that aren't
loopback/localhost -- the signature of a hidden exfiltration endpoint
or callback baked into the code rather than configured openly. This
can't tell a legitimate integration from a backdoor by itself; it's a
lead for a human reviewer, which is exactly what a static vetting
tool is for.

Only scans STRING tokens (via `tokenize`), not raw source lines --
otherwise an address mentioned in a comment (explaining what the check
looks for, say) reads as a finding just as loudly as one actually
embedded in a string literal the running code uses.
"""

import io
import re
import tokenize

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_RE = re.compile(r"https?://[^\s\"'<>]+")
LOOPBACK_PREFIXES = ("127.", "0.0.0.0", "255.255.255.255")


def _string_tokens(source_text: str):
    try:
        for tok in tokenize.generate_tokens(io.StringIO(source_text).readline):
            if tok.type == tokenize.STRING:
                yield tok.start[0], tok.string
    except (tokenize.TokenizeError, SyntaxError, IndentationError):
        return


def check_hardcoded_network_targets(source_path: str, source_text: str, tools: list) -> list[dict]:
    findings = []
    seen = set()

    for lineno, literal in _string_tokens(source_text):
        for match in IP_RE.findall(literal):
            if match.startswith(LOOPBACK_PREFIXES) or match in seen:
                continue
            seen.add(match)
            findings.append(_finding("hardcoded IP address", match, lineno, source_path))

        for match in URL_RE.findall(literal):
            host = match.split("//", 1)[-1].split("/", 1)[0]
            if host in ("localhost",) or host.startswith("127.") or match in seen:
                continue
            seen.add(match)
            findings.append(_finding("hardcoded URL", match, lineno, source_path))

    return findings


def _finding(kind: str, value: str, lineno: int, source_path: str) -> dict:
    return {
        "check": "hardcoded_network_targets",
        "severity": "medium",
        "tool": "(source-level)",
        "reason": (
            f"Found a {kind} baked directly into the source at line {lineno}: '{value}'. A network "
            "destination hardcoded in source rather than configured openly is worth a human look -- it "
            "could be a legitimate integration, or a hidden exfiltration/callback target."
        ),
        "evidence": {"value": value, "line": lineno, "file": source_path},
        "recommendation": (
            "Move network destinations to documented configuration, and confirm every hardcoded host "
            "against the server's stated purpose before trusting it."
        ),
    }