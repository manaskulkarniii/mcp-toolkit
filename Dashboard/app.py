"""
dashboard/app.py

A small local web dashboard for the MCP Security Toolkit's scanner.
Pick a server from test-range/ (or type any path) and see the scan
results rendered as a styled report instead of raw terminal output.
Reuses the exact same scanning logic as scanner/cli.py -- this is just
a different way to view the same results.
"""

import asyncio
import os
from datetime import datetime

from flask import Flask, render_template, request

from scanner.client import connect_to_server
from scanner.checks import ALL_CHECKS
from scanner.report import build_report

app = Flask(__name__)

TEST_RANGE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "test-range")


def discover_test_servers():
    """Find every server.py under test-range/ for the quick-pick list."""
    servers = []
    if os.path.isdir(TEST_RANGE_DIR):
        for folder in sorted(os.listdir(TEST_RANGE_DIR)):
            candidate = os.path.join(TEST_RANGE_DIR, folder, "server.py")
            if os.path.isfile(candidate):
                servers.append(os.path.relpath(candidate, start=os.path.dirname(TEST_RANGE_DIR)))
    return servers


async def run_scan_async(script_path: str) -> dict:
    findings = []
    async with connect_to_server(script_path) as session:
        tools_response = await session.list_tools()
        for tool in tools_response.tools:
            for check in ALL_CHECKS:
                findings.extend(await check(tool, session))
    return build_report(server_target=script_path, findings=findings)


@app.route("/", methods=["GET", "POST"])
def index():
    report = None
    error = None
    selected_path = ""

    if request.method == "POST":
        selected_path = request.form.get("script_path", "").strip()
        if not selected_path:
            error = "Please choose or enter a server script path."
        elif not os.path.isfile(selected_path):
            error = f"File not found: {selected_path}"
        else:
            try:
                report = asyncio.run(run_scan_async(selected_path))
                severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
                report["findings"].sort(key=lambda f: severity_order.get(f.get("severity", "low"), 4))
                report["scanned_at"] = datetime.now().strftime("%b %d, %Y \u00b7 %I:%M %p")
            except Exception as exc:
                error = f"Scan failed: {exc}"

    return render_template(
        "index.html",
        servers=discover_test_servers(),
        report=report,
        error=error,
        selected_path=selected_path,
    )


if __name__ == "__main__":
    app.run(debug=True, port=5000)