"""
scanner/checks/secret_leakage.py

Detects the vulnerability class demonstrated by
test-range/vuln_secret_leakage/server.py: a tool whose response text
contains secret-shaped data -- API keys, passwords embedded in
connection strings -- typically leaked through overly verbose error
handling.

This is an ACTIVE check: it calls each tool with a few simple probing
values for every string parameter (values unlikely to be valid, to
encourage an error/fallback code path) and scans whatever text comes
back for secret-like patterns.
"""

import re

SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "stripe_style_key": re.compile(r"sk_(live|test)_[A-Za-z0-9]{10,}"),
    "generic_api_key_assignment": re.compile(r"api[_-]?key['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9\-_]{16,}", re.IGNORECASE),
    "password_in_url": re.compile(r"://[^:\s]+:[^@\s]+@"),
    "password_assignment": re.compile(r"password['\"]?\s*[:=]\s*['\"]?\S{4,}", re.IGNORECASE),
}

PROBE_VALUES = ["___mcp_scanner_probe___", "", "nonexistent"]


async def check_secret_leakage(tool, session) -> list[dict]:
    schema = getattr(tool, "inputSchema", None) or getattr(tool, "input_schema", None) or {}
    properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
    required = set(schema.get("required", [])) if isinstance(schema, dict) else set()

    string_params = [
        name for name, spec in properties.items()
        if isinstance(spec, dict) and spec.get("type") == "string"
    ]

    findings = []
    seen = set()

    for probe in PROBE_VALUES:
        arguments = {name: probe for name in string_params}
        for other in required:
            if other not in arguments:
                arguments[other] = "1"

        try:
            result = await session.call_tool(tool.name, arguments=arguments)
        except Exception:
            continue

        result_text = "".join(getattr(block, "text", "") for block in getattr(result, "content", []))
        if not result_text:
            continue

        for label, pattern in SECRET_PATTERNS.items():
            match = pattern.search(result_text)
            if match and (tool.name, label) not in seen:
                seen.add((tool.name, label))
                findings.append({
                    "check": "secret_leakage",
                    "severity": "critical",
                    "tool": tool.name,
                    "reason": (
                        f"Calling '{tool.name}' returned text matching a {label.replace('_', ' ')} "
                        "pattern -- likely a secret leaked through verbose output or error handling."
                    ),
                    "evidence": {"matched_pattern": label, "sample": match.group(0)[:40] + "..."},
                    "recommendation": (
                        "Never include internal configuration, credentials, or connection strings "
                        "in tool output or error messages. Return a generic error instead."
                    ),
                })

    return findings