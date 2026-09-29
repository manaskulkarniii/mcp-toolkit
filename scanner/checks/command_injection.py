"""
scanner/checks/command_injection.py

Detects the vulnerability class demonstrated by
test-range/vuln_input_injection/server.py: a tool that builds a shell
command directly from a string parameter with no sanitization.

This is an ACTIVE check: for every string parameter a tool exposes, it
calls the tool with a value containing a shell metacharacter sequence
plus a unique canary "echo" command, and checks whether the canary text
comes back WITHOUT the original payload text still being present
verbatim. That distinction matters: a tool that just echoes its input
back in an error message (reflection) will contain the canary too, but
it will also still contain the whole original payload string intact --
a shell that actually executed the injected command consumes the
payload and only the canary's own output survives. Checking for the
canary alone caused a false positive on a tool that merely reflected
its input; requiring the original payload to be GONE is what tells
real execution apart from simple reflection.
"""

import uuid

INJECTION_TEMPLATES = [
    "test && echo {marker}",
    "test; echo {marker}",
    "test | echo {marker}",
]


async def check_command_injection(tool, session) -> list[dict]:
    schema = getattr(tool, "inputSchema", None) or getattr(tool, "input_schema", None) or {}
    properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
    required = set(schema.get("required", [])) if isinstance(schema, dict) else set()

    string_params = [
        name for name, spec in properties.items()
        if isinstance(spec, dict) and spec.get("type") == "string"
    ]
    if not string_params:
        return []

    findings = []

    for param in string_params:
        marker = f"MCP-SCANNER-INJECT-{uuid.uuid4().hex}"
        found = False

        for template in INJECTION_TEMPLATES:
            if found:
                break

            payload = template.format(marker=marker)
            arguments = {param: payload}
            for other in required:
                if other != param and other not in arguments:
                    arguments[other] = "1"

            try:
                result = await session.call_tool(tool.name, arguments=arguments)
            except Exception:
                continue

            result_text = "".join(getattr(block, "text", "") for block in getattr(result, "content", []))

            marker_present = marker in result_text
            payload_reflected_whole = payload in result_text

            if marker_present and not payload_reflected_whole:
                found = True
                findings.append({
                    "check": "command_injection",
                    "severity": "critical",
                    "tool": tool.name,
                    "reason": (
                        f"Confirmed by active test: calling '{tool.name}' with shell metacharacters "
                        f"in parameter '{param}' caused an injected command to actually execute -- the "
                        "canary output appeared without the original payload text surviving intact, "
                        "meaning a shell processed and split it rather than just echoing it back."
                    ),
                    "evidence": {"parameter": param, "payload": payload},
                    "recommendation": (
                        "Never build shell commands by string concatenation. Use subprocess with a "
                        "list of arguments and shell=False, and validate/allowlist input."
                    ),
                })

    return findings