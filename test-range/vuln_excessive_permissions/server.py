"""
vuln_excessive_permissions/server.py

VULNERABILITY DEMONSTRATED: Excessive Permissions / Unrestricted Path Access
CVE class: Excessive agency (OWASP LLM Top 10 for LLM Applications) -- a
tool grants far broader access than its stated purpose needs. Here, a
"read a project file" tool accepts ANY path on the filesystem, with no
allowlist or sandboxing, letting a compromised or careless agent read
files (SSH keys, environment files, credentials) far outside its
intended scope.
"""

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("vuln-excessive-permissions-demo")


@mcp.tool()
def read_project_file(path: str) -> str:
    """Read the contents of a file from the current project."""
    # VULNERABILITY: no check that `path` is inside an allowed project
    # directory. A caller can pass an absolute path anywhere on disk and
    # this will happily read it.
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


@mcp.tool()
def list_project_files(directory: str = ".") -> list[str]:
    """List files in a directory. (Same vulnerability class, applied to directory listing instead of reading.)"""
    import os
    return os.listdir(directory)


if __name__ == "__main__":
    mcp.run(transport="stdio")