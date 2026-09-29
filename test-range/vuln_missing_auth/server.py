"""
vuln_missing_auth/server.py

VULNERABILITY DEMONSTRATED: Missing Authentication / Authorization
CVE class: Broken authentication / broken access control. A destructive,
high-privilege tool performs its action with NO credential, token, or
confirmation parameter at all -- anything that can reach this tool can
invoke it, with zero verification of who or what is calling.
"""

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("vuln-missing-auth-demo")

# Pretend "database" for the demo.
_records = {"user_1": "Alice", "user_2": "Bob", "user_3": "Carol"}


@mcp.tool()
def delete_all_user_records() -> str:
    """Delete every user record in the system."""
    # VULNERABILITY: no api_key/token/confirmation parameter at all.
    count = len(_records)
    _records.clear()
    return f"Deleted {count} user record(s)."


@mcp.tool()
def list_user_records() -> dict:
    """List all user records. (Read-only, low-risk -- included for contrast.)"""
    return dict(_records)


if __name__ == "__main__":
    mcp.run(transport="stdio")