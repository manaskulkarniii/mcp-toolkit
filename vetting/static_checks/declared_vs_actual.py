"""
vetting/static_checks/declared_vs_actual.py

Flags a tool whose description/docstring gives no hint of a capability
its code actually uses -- filesystem access, subprocess/shell
execution, or outbound network calls. This is the static counterpart
to the runtime scanner's confused_deputy check: it can't see silent
internal privilege escalation without running the server, but it can
catch the cheaper, more common version of the same problem -- a tool
whose stated purpose ("summarize this text") says nothing about also
touching disk, the network, or a subprocess.
"""

import ast

FS_CALLS = {"open", "os.remove", "os.rename", "os.listdir", "os.walk", "shutil.copy", "shutil.rmtree"}
NET_CALLS = {"urllib.request.urlopen", "requests.get", "requests.post", "socket.socket", "httpx.get", "httpx.post"}
PROC_CALLS = {"subprocess.run", "subprocess.call", "subprocess.Popen", "os.system", "os.popen"}

FS_HINTS = ("file", "path", "directory", "disk", "read", "write", "save")
NET_HINTS = ("url", "http", "fetch", "request", "web", "network", "download")
PROC_HINTS = ("command", "shell", "execute", "run", "process", "ping")

CATEGORIES = [
    ("filesystem access", FS_CALLS, FS_HINTS),
    ("outbound network calls", NET_CALLS, NET_HINTS),
    ("subprocess/shell execution", PROC_CALLS, PROC_HINTS),
]


def _dotted_name(node: ast.expr):
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return f"{node.value.id}.{node.attr}"
    if isinstance(node, ast.Name):
        return node.id
    return None


def _touches(tool_node: ast.AST, call_set: set) -> bool:
    return any(
        isinstance(node, ast.Call) and _dotted_name(node.func) in call_set
        for node in ast.walk(tool_node)
    )


def check_declared_vs_actual(source_path: str, source_text: str, tools: list) -> list[dict]:
    findings = []

    for tool in tools:
        docstring_lower = tool.docstring.lower()

        for label, call_set, hints in CATEGORIES:
            if not _touches(tool.node, call_set):
                continue
            if any(hint in docstring_lower for hint in hints):
                continue

            findings.append({
                "check": "declared_vs_actual",
                "severity": "high",
                "tool": tool.name,
                "reason": (
                    f"Tool '{tool.name}' is described as: \"{tool.docstring.strip() or '(no docstring)'}\" -- "
                    f"which gives no hint that it performs {label}, but its code does."
                ),
                "evidence": {"category": label, "docstring": tool.docstring.strip()},
                "recommendation": (
                    "Update the tool's description to accurately state every capability it uses, so an "
                    "agent -- and a human reviewing the grant -- can make an informed trust decision."
                ),
            })

    return findings