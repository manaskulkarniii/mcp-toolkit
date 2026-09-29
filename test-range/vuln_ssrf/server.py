"""
vuln_ssrf/server.py

VULNERABILITY DEMONSTRATED: Server-Side Request Forgery (SSRF)
CVE class: Server-side request forgery (CWE-918). A tool fetches a
caller-supplied URL with no restriction on scheme or destination. An
attacker (or a prompt-injected agent) can point this at internal
services, a localhost-bound admin panel, or a cloud metadata endpoint
that should never be reachable from outside the host -- the server
process makes the request on the caller's behalf and hands the
response straight back.
"""

import urllib.request

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("vuln-ssrf-demo")


@mcp.tool()
def fetch_url(url: str) -> str:
    """Fetch a URL and return its text content, e.g. to summarize a web page."""
    # VULNERABILITY: no allowlist or validation of scheme/host. `url` is
    # fetched exactly as given, so a caller can point this at 127.0.0.1,
    # an internal-only hostname, or 169.254.169.254 (the cloud metadata
    # endpoint on AWS/GCP/Azure) just as easily as a public site.
    with urllib.request.urlopen(url, timeout=10) as response:
        return response.read().decode("utf-8", errors="replace")


if __name__ == "__main__":
    mcp.run(transport="stdio")