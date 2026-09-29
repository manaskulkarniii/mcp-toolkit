"""
tests/_helpers.py

Shared helpers for the scanner/vetting test suite. No test_ prefix --
pytest won't collect this as a test module.
"""

import asyncio

from scanner.client import connect_to_server


async def _run_check_async(check_fn, server_path: str) -> list:
    findings = []
    async with connect_to_server(server_path) as session:
        tools_response = await session.list_tools()
        for tool in tools_response.tools:
            findings.extend(await check_fn(tool, session))
    return findings


def run_check(check_fn, server_path: str) -> list:
    """Run a single async scanner check against every tool a server exposes."""
    return asyncio.run(_run_check_async(check_fn, server_path))