import json


def build_report(server_target: str, findings: list[dict]) -> dict:
    return {
        "server": server_target,
        "findings_count": len(findings),
        "findings": findings,
    }


def print_report(report: dict) -> None:
    print(f"\nMCP Security Scan Report")
    print(f"Target: {report['server']}")
    print(f"Findings: {report['findings_count']}\n")

    if not report["findings"]:
        print("No issues detected by current checks.")
        return

    for i, f in enumerate(report["findings"], start=1):
        print(f"[{i}] {f['severity'].upper()} - {f['check']} - tool: {f['tool']}")
        print(f"    {f['reason']}")
        print(f"    Evidence: {f['evidence']}")
        print(f"    Fix: {f['recommendation']}\n")


def save_report_json(report: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)