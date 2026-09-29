"""
scanner/checks/excessive_permissions.py

Detects the vulnerability class demonstrated by
test-range/vuln_excessive_permissions/server.py: a tool that accepts a
filesystem path parameter with no indication it's restricted to a safe
root. Unlike the tool-poisoning check (which only reads text), this one
also actively PROVES the flaw by calling the tool with a canary file
placed outside any reasonable project scope and checking whether the
tool actually reads it.
"""

import os
import tempfile
import uuid

PATH_LIKE_PARAM_NAMES = {"path", "file", "filepath", "file_path", "dir", "directory", "filename"}
SCOPE_HINT_WORDS = ["sandbox", "restricted", "within the project", "allowed directory", "jailed", "confined"]


async def check_excessive_filesystem_scope(tool, session) -> list[dict]:
    # Be defensive about the schema attribute name -- different SDK
    # versions have used inputSchema and input_schema.
    schema = getattr(tool, "inputSchema", None) or getattr(tool, "input_schema", None) or {}
    properties = schema.get("properties", {}) if isinstance(schema, dict) else {}

    path_params = [name for name in properties if name.lower() in PATH_LIKE_PARAM_NAMES]
    if not path_params:
        return []

    description = (tool.description or "").lower()
    mentions_scoping = any(hint in description for hint in SCOPE_HINT_WORDS)

    findings = []

    if not mentions_scoping:
        findings.append({
            "check": "excessive_filesystem_scope",
            "severity": "medium",
            "tool": tool.name,
            "reason": (
                f"Tool accepts a filesystem path parameter ({', '.join(path_params)}) "
                "with no mention of any directory restriction in its description."
            ),
            "evidence": {"path_parameters": path_params},
            "recommendation": "Verify the tool enforces an allowed root directory before trusting it with agent-supplied paths.",
        })

    # Active proof: call the tool with a canary file placed outside the
    # project directory and see if its contents come back.
    canary_marker = f"MCP-SCANNER-CANARY-{uuid.uuid4().hex}"
    canary_path = os.path.join(tempfile.gettempdir(), f"mcp_scanner_canary_{uuid.uuid4().hex}.txt")

    try:
        with open(canary_path, "w", encoding="utf-8") as f:
            f.write(canary_marker)

        for param in path_params:
            try:
                result = await session.call_tool(tool.name, arguments={param: canary_path})
            except Exception:
                continue

            result_text = "".join(getattr(block, "text", "") for block in getattr(result, "content", []))

            if canary_marker in result_text:
                findings.append({
                    "check": "excessive_filesystem_scope",
                    "severity": "high",
                    "tool": tool.name,
                    "reason": (
                        f"Confirmed by active test: calling '{tool.name}' with a path outside the "
                        "project directory successfully returned file contents from that unrelated location."
                    ),
                    "evidence": {"canary_path": canary_path, "parameter": param},
                    "recommendation": "Restrict this tool to a specific allowed directory and reject any path that resolves outside it.",
                })
    finally:
        if os.path.exists(canary_path):
            os.remove(canary_path)

    return findings