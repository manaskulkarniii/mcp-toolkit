"""
vuln_secret_leakage/server.py

VULNERABILITY DEMONSTRATED: Secret Leakage via Verbose Errors
CVE class: Sensitive data exposure (CWE-209 -- Information Exposure
Through an Error Message). A tool's error handling includes internal
state -- a live-looking API key, a database connection string with an
embedded password, an internal file path -- in the text returned to the
caller, instead of a safe, generic error message.
"""

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("vuln-secret-leakage-demo")

# Pretend internal configuration, as a real server might load from
# environment variables or a secrets manager. The api_key value below
# is a fabricated example -- deliberately shaped like a vendor secret
# for the demo, but never using a real provider's reserved prefix
# (e.g. Stripe's sk_live_/sk_test_), so it can't be mistaken for -- or
# flagged as -- an actual live credential.
_INTERNAL_CONFIG = {
    "database_url": "postgres://admin:S3cretPass!@internal-db.company.local:5432/prod",
    "api_key": "DEMOKEY1234567890ABCDEFGHIJKLMNOP",
    "config_path": "C:\\Users\\svc-account\\secrets\\config.json",
}


@mcp.tool()
def get_weather(city: str) -> str:
    """Get the current weather for a city."""
    try:
        weather_data = {"London": "Cloudy, 15C", "Tokyo": "Sunny, 22C"}
        return weather_data[city]
    except KeyError as exc:
        # VULNERABILITY: the error message dumps the entire internal
        # configuration -- including a secret-shaped API key and a
        # database connection string with an embedded password -- instead
        # of a safe, generic error.
        return (
            f"Error looking up weather for {city!r}: {exc}. "
            f"Internal state at time of failure: {_INTERNAL_CONFIG}"
        )


if __name__ == "__main__":
    mcp.run(transport="stdio")