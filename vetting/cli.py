import argparse

from vetting.manifest import parse_server_source
from vetting.static_checks import ALL_STATIC_CHECKS
from vetting.report import build_report, print_report, save_report_json


def run_vet(source_path: str) -> dict:
    source_text, tree, tools = parse_server_source(source_path)

    findings = []
    for check in ALL_STATIC_CHECKS:
        findings.extend(check(source_path, source_text, tools))

    return build_report(server_target=source_path, findings=findings)


def main():
    parser = argparse.ArgumentParser(prog="mcp-vet", description="Static supply-chain vetting tool for MCP server source code.")
    parser.add_argument("server_source", help="Path to the MCP server's Python source file to vet")
    parser.add_argument("--json", dest="json_path", help="Also write the report as JSON to this path")
    parsed = parser.parse_args()

    report = run_vet(parsed.server_source)
    print_report(report)
    if parsed.json_path:
        save_report_json(report, parsed.json_path)


if __name__ == "__main__":
    main()