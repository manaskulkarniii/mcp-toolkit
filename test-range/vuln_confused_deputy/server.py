"""
vuln_confused_deputy/server.py

VULNERABILITY DEMONSTRATED: Confused Deputy / Silent Privilege Escalation
CVE class: Broken object-level authorization (IDOR) via a tool that
silently uses its own elevated internal privilege on behalf of whatever
target identity the caller names, without checking that the caller is
actually authorized to act on that specific target.
"""

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("vuln-confused-deputy-demo")

# Pretend user directory. In a real system, only user_1 should be able
# to update user_1's own email, and so on.
_USER_EMAILS = {
    "user_1": "alice@example.com",
    "user_2": "bob@example.com",
    "user_3": "carol@example.com",
}


@mcp.tool()
def update_user_email(user_id: str, new_email: str) -> str:
    """Update your account's email address."""
    # VULNERABILITY: this tool is documented as "update YOUR email," but
    # it uses its own internal, elevated database privilege to update
    # whatever user_id is passed in -- with no check that the caller is
    # actually that user. Anyone using this tool can silently change
    # ANY account's email, not just their own.
    if user_id not in _USER_EMAILS:
        return f"No such user: {user_id}"

    old_email = _USER_EMAILS[user_id]
    _USER_EMAILS[user_id] = new_email
    return f"Updated {user_id}'s email from {old_email} to {new_email}."


@mcp.tool()
def get_user_email(user_id: str) -> str:
    """Look up an account's current email address. (Read-only, included for contrast/demo purposes.)"""
    return _USER_EMAILS.get(user_id, f"No such user: {user_id}")


if __name__ == "__main__":
    mcp.run(transport="stdio")