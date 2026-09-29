"""
vuln_path_traversal/server.py

VULNERABILITY DEMONSTRATED: Path Traversal
CVE class: Improper limitation of a pathname to a restricted directory
(CWE-22). This tool tries to look safe -- it joins the caller-supplied
filename onto a fixed "sandbox" directory instead of accepting an
arbitrary path outright (that's the excessive_permissions demo). But
naive string-joining is not a real restriction: os.path.join happily
walks back out of the sandbox when the filename contains "../"
segments, or is itself an absolute path, so the intended confinement
doesn't hold.
"""

import os

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("vuln-path-traversal-demo")

SANDBOX_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sandbox")
os.makedirs(SANDBOX_DIR, exist_ok=True)

_welcome_path = os.path.join(SANDBOX_DIR, "welcome.txt")
if not os.path.exists(_welcome_path):
    with open(_welcome_path, "w", encoding="utf-8") as f:
        f.write("This is a sandboxed file. Legitimate calls should only ever read files in here.\n")


@mcp.tool()
def read_sandbox_file(filename: str) -> str:
    """Read a file from this server's sandboxed uploads directory."""
    # VULNERABILITY: filename is joined onto SANDBOX_DIR with no check
    # that the resolved path actually stays inside it. "../../../etc/passwd"
    # (or an absolute path -- os.path.join lets an absolute second argument
    # override the base entirely, on both POSIX and Windows) walks straight
    # out of the sandbox.
    target = os.path.join(SANDBOX_DIR, filename)
    with open(target, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


if __name__ == "__main__":
    mcp.run(transport="stdio")