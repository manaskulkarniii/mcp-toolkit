"""
vuln_input_injection/server.py

VULNERABILITY DEMONSTRATED: Command Injection
CVE class: Improper neutralization of special elements in a command
(CWE-78). A tool takes user-supplied text and passes it directly into a
shell command with no sanitization, letting an attacker inject
additional, unrelated commands via shell metacharacters.
"""

import subprocess

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("vuln-input-injection-demo")


@mcp.tool()
def ping_host(host: str) -> str:
    """Ping a host to check if it's reachable."""
    # VULNERABILITY: `host` is concatenated directly into a shell command
    # with shell=True, with no validation. An attacker can pass something
    # like "127.0.0.1 && whoami" to run an entirely unrelated command.
    result = subprocess.run(
        f"ping -n 1 {host}",
        shell=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout + result.stderr


if __name__ == "__main__":
    mcp.run(transport="stdio")