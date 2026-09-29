"""
scanner/checks/path_traversal.py

Detects a tool that accepts a file/path parameter and does not confine
the resolved path to an intended directory, allowing a caller to read
arbitrary files elsewhere on disk.

This is an ACTIVE check: it plants a temporary canary file, containing
a unique random marker, somewhere clearly outside any directory a tool
should legitimately need (the OS temp directory). It then calls the
tool once per string parameter with several traversal-style payloads
that all resolve to that canary file -- relative ../ and ..\\ climbs,
their URL-encoded forms, and the file's bare absolute path -- and
checks whether the marker comes back in the tool's response. Because
the marker is random and never appears in the payload itself, seeing
it in the output can only mean the tool actually opened and returned
the canary file's contents, not that it echoed its input back.
"""

import os
import tempfile
import uuid


def _traversal_payloads(canary_path: str) -> list[str]:
    abs_path = os.path.abspath(canary_path)
    drive, tail = os.path.splitdrive(abs_path)
    tail_posix = tail.replace("\\", "/").lstrip("/")

    depths = [4, 8, 12]
    payloads = [abs_path]

    for depth in depths:
        payloads.append("../" * depth + tail_posix)
        payloads.append("..\\" * depth + tail.lstrip("\\"))
        payloads.append("%2e%2e%2f" * depth + tail_posix)

    return payloads


async def check_path_traversal(tool, session) -> list[dict]:
    schema = getattr(tool, "inputSchema", None) or getattr(tool, "input_schema", None) or {}
    properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
    required = set(schema.get("required", [])) if isinstance(schema, dict) else set()

    string_params = [
        name for name, spec in properties.items()
        if isinstance(spec, dict) and spec.get("type") == "string"
    ]
    if not string_params:
        return []

    marker = f"MCP-SCANNER-TRAVERSAL-{uuid.uuid4().hex}"
    canary_dir = tempfile.mkdtemp(prefix="mcp-scanner-canary-")
    canary_path = os.path.join(canary_dir, "canary.txt")
    with open(canary_path, "w") as f:
        f.write(marker)

    findings = []

    try:
        for param in string_params:
            found = False
            for payload in _traversal_payloads(canary_path):
                if found:
                    break

                arguments = {param: payload}
                for other in required:
                    if other != param and other not in arguments:
                        arguments[other] = "1"

                try:
                    result = await session.call_tool(tool.name, arguments=arguments)
                except Exception:
                    continue

                result_text = "".join(getattr(block, "text", "") for block in getattr(result, "content", []))

                if marker in result_text:
                    found = True
                    findings.append({
                        "check": "path_traversal",
                        "severity": "critical",
                        "tool": tool.name,
                        "reason": (
                            f"Confirmed by active test: calling '{tool.name}' with a traversal payload "
                            f"in parameter '{param}' returned the contents of a canary file planted "
                            "outside any directory this tool should have access to."
                        ),
                        "evidence": {"parameter": param, "payload": payload},
                        "recommendation": (
                            "Resolve the path against a fixed allowed root with os.path.realpath, then "
                            "verify the result is still inside that root before opening it. Reject any "
                            "path containing '..' segments or an absolute path outright."
                        ),
                    })
    finally:
        try:
            os.remove(canary_path)
            os.rmdir(canary_dir)
        except OSError:
            pass

    return findings