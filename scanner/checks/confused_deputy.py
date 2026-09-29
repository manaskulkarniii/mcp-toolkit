"""
scanner/checks/confused_deputy.py

Detects the vulnerability class demonstrated by
test-range/vuln_confused_deputy/server.py: a tool that performs a
mutating action on a resource identified by an explicit "target
identity" parameter (a user id, account id, owner id) supplied by the
caller, with no visible check that the caller is authorized to act on
THAT specific target rather than only their own.

This is a static, heuristic check only. Unlike command injection or
excessive filesystem scope, this class of flaw generally can't be
proven by a black-box active probe alone -- confirming it would need
knowledge of which identity is legitimately allowed to call the tool,
which a scanner with no caller context doesn't have. This check flags
the SHAPE of the risk (a mutating tool that takes someone else's
identity as a plain parameter) for a human to review, rather than
claiming certainty the way the active checks do.
"""

MUTATING_VERBS = ["update", "change", "modify", "set", "edit", "assign", "transfer", "grant"]
TARGET_IDENTITY_PARAM_NAMES = {
    "user_id", "account_id", "owner_id", "target_user", "customer_id", "member_id",
}


async def check_confused_deputy(tool, session) -> list[dict]:
    name_and_desc = f"{tool.name} {tool.description or ''}".lower()
    is_mutating = any(verb in name_and_desc for verb in MUTATING_VERBS)
    if not is_mutating:
        return []

    schema = getattr(tool, "inputSchema", None) or getattr(tool, "input_schema", None) or {}
    properties = schema.get("properties", {}) if isinstance(schema, dict) else {}

    identity_params = [name for name in properties if name.lower() in TARGET_IDENTITY_PARAM_NAMES]
    if not identity_params:
        return []

    return [{
        "check": "confused_deputy",
        "severity": "medium",
        "tool": tool.name,
        "reason": (
            f"Tool performs a mutating action and accepts a target identity parameter "
            f"({', '.join(identity_params)}) chosen by the caller, with no visible restriction "
            "to the caller's own identity. This is the classic shape of a confused-deputy / "
            "insecure-direct-object-reference flaw: the tool may use its own elevated privilege "
            "to act on any target the caller names, not just the caller's own resource."
        ),
        "evidence": {"identity_parameters": identity_params},
        "recommendation": (
            "Verify server-side that the caller is authorized to act on the specific target "
            "identity requested, not just that the call is well-formed. Needs human review -- "
            "this check flags the risk shape but cannot prove exploitation the way an active "
            "probe would."
        ),
    }]