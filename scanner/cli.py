import argparse
import asyncio

from scanner.client import connect_to_server
from scanner.checks import ALL_CHECKS
from scanner.report import build_report, print_report, save_report_json


async def run_scan(script_path: str) -> dict:
    findings = []
    async with connect_to_server(script_path) as session:
        tools_response = await session.list_tools()
        for tool in tools_response.tools:
            for check in ALL_CHECKS:
                findings.extend(await check(tool, session))

    return build_report(server_target=script_path, findings=findings)


def main():
    parser = argparse.ArgumentParser(prog="mcp-scan", description="Runtime security scanner for MCP servers.")
    parser.add_argument("server_script", help="Path to the Python MCP server script to scan")
    parser.add_argument("--json", dest="json_path", help="Also write the report as JSON to this path")
    parsed = parser.parse_args()

    report = asyncio.run(run_scan(parsed.server_script))
    print_report(report)
    if parsed.json_path:
        save_report_json(report, parsed.json_path)


if __name__ == "__main__":
    main()