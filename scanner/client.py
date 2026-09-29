"""
scanner/client.py

Connects to an MCP server exactly the way a real AI agent would (over
stdio). Exposes a context manager so checks can both list tools and,
where needed, actively call a tool to verify its real behavior.
"""

import sys
from contextlib import asynccontextmanager
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


@asynccontextmanager
async def connect_to_server(script_path: str):
    """
    Launches a Python-based MCP server script via the `mcp run` CLI command
    (the same invocation style the MCP Inspector uses) and yields an
    initialized ClientSession connected to it.
    """
    server_params = StdioServerParameters(command="mcp", args=["run", script_path])
    log_path = Path("server_stderr.log")

    with open(log_path, "w", encoding="utf-8") as errlog:
        try:
            async with stdio_client(server_params, errlog=errlog) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    yield session
        except Exception:
            captured = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
            print("\n----- Captured server stderr -----", file=sys.stderr)
            print(captured or "(nothing was written to stderr)", file=sys.stderr)
            print("-----------------------------------\n", file=sys.stderr)
            raise