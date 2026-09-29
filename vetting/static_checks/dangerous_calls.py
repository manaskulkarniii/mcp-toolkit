"""
vetting/static_checks/dangerous_calls.py

Flags a tool function whose body calls eval/exec, os.system/os.popen,
or subprocess with shell=True (or without it, but still worth a look).
This is the static counterpart to the scanner's ACTIVE
command_injection check: it can't prove exploitability without
running the server, but calling eval/exec or a shell command on any
caller-influenced string is close enough to a certainty that it's
worth flagging on the call shape alone.
"""

import ast

DANGEROUS_CALL_NAMES = {"eval": "critical", "exec": "critical"}
DANGEROUS_DOTTED_CALLS = {"os.system": "critical", "os.popen": "critical"}
SUBPROCESS_CALLS = {"subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output"}


def _dotted_name(node: ast.expr):
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return f"{node.value.id}.{node.attr}"
    return None


def check_dangerous_calls(source_path: str, source_text: str, tools: list) -> list[dict]:
    findings = []

    for tool in tools:
        for node in ast.walk(tool.node):
            if not isinstance(node, ast.Call):
                continue

            call_name, severity = None, None

            if isinstance(node.func, ast.Name) and node.func.id in DANGEROUS_CALL_NAMES:
                call_name = node.func.id
                severity = DANGEROUS_CALL_NAMES[call_name]
            else:
                dotted = _dotted_name(node.func)
                if dotted in DANGEROUS_DOTTED_CALLS:
                    call_name, severity = dotted, DANGEROUS_DOTTED_CALLS[dotted]
                elif dotted in SUBPROCESS_CALLS:
                    shell_true = any(
                        kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                        for kw in node.keywords
                    )
                    call_name = dotted
                    severity = "critical" if shell_true else "high"

            if call_name is None:
                continue

            findings.append({
                "check": "dangerous_calls",
                "severity": severity,
                "tool": tool.name,
                "reason": (
                    f"Tool '{tool.name}' calls '{call_name}' at line {node.lineno}. "
                    "If any part of the arguments traces back to a tool parameter, this is directly "
                    "exploitable for command injection or arbitrary code execution."
                ),
                "evidence": {"call": call_name, "line": node.lineno},
                "recommendation": (
                    "Avoid eval/exec and shell=True entirely. Use subprocess with a list of arguments and "
                    "shell=False, and validate/allowlist all input before it reaches a system call."
                ),
            })

    return findings