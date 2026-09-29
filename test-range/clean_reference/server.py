"""
clean_reference/server.py

A well-behaved MCP server with no known vulnerabilities -- the
negative-test control target. Every check in the catalog should stay
completely quiet against this server: it touches no filesystem, no
network, no subprocess, takes no destructive or identity-scoped
action, and its descriptions say exactly what its code does.
"""

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("clean-reference-server")


@mcp.tool()
def count_words(text: str) -> str:
    """Count the number of words in the given text."""
    return f"Word count: {len(text.split())}"


@mcp.tool()
def reverse_text(text: str) -> str:
    """Reverse the characters in the given text."""
    return text[::-1]


if __name__ == "__main__":
    mcp.run(transport="stdio")