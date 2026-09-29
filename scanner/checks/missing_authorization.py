"""
scanner/checks/missing_authorization.py

Detects the vulnerability class demonstrated by
test-range/vuln_missing_auth/server.py: a tool whose name or description
suggests a sensitive or destructive operation, but whose parameters
include no credential, token, or confirmation field at all.

Note: this check is intentionally static/heuristic only -- it does NOT
actively call the tool to prove the flaw (unlike the excessive-permissions
check), because doing so could mean automatically triggering a real
destructive action on whatever server is being scanned. That's a
deliberate safety trade-off worth being able to explain: this scanner
avoids ever executing an action that looks destructive, even against
its own test range.
"""

SENSITIVE_VERBS = [
    "delete", "remove", "drop", "wipe", "purge", "reset",
    "revoke", "grant", "admin", "shutdown", "kill", "destroy",
]

AUTH_PARAM_NAMES = {
    "api_key", "apikey", "token", "auth", "authorization",
    "password", "credential", "secret", "confirm", "force",
}


async def check_missing_authorization(tool, session) -> list[dict]:
    name_and_desc = f"{tool.name} {tool.description or ''}".lower()
    looks_sensitive = any(verb in name_and_desc for verb in SENSITIVE_VERBS)
    if not looks_sensitive:
        return []

    schema = getattr(tool, "inputSchema", None) or getattr(tool, "input_schema", None) or {}
    properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
    has_auth_param = any(p.lower() in AUTH_PARAM_NAMES for p in properties)

    if has_auth_param:
        return []

    return [{
        "check": "missing_authorization",
        "severity": "high",
        "tool": tool.name,
        "reason": (
            "Tool name/description suggests a sensitive or destructive operation, "
            "but its parameters include no credential, token, or confirmation field."
        ),
        "evidence": {"parameters": list(properties.keys())},
        "recommendation": (
            "Require an authorization token or explicit confirmation parameter "
            "before performing this action, and verify it server-side."
        ),
    }]