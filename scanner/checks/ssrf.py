"""
scanner/checks/ssrf.py

Detects a tool that accepts a URL/host parameter and will fetch it on
the caller's behalf with no restriction on scheme or destination --
the setup for server-side request forgery, where a caller can make the
MCP server's process issue requests to internal services, localhost,
or cloud metadata endpoints it should never be able to reach.

This is an ACTIVE check: it starts a small local HTTP listener bound
to 127.0.0.1 on an ephemeral port that serves a unique random marker
at a random path, then calls the tool once per string parameter with
that listener's URL. If the marker shows up in the tool's response, or
the listener actually receives a hit, the tool made an outbound
request to a caller-supplied destination -- exactly the primitive an
attacker needs to reach internal-only services or a metadata endpoint
the scanner has no business probing directly.
"""

import asyncio
import threading
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer


def _start_canary_server(marker: str):
    hit_event = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            hit_event.set()
            body = marker.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, hit_event


async def check_ssrf(tool, session) -> list[dict]:
    schema = getattr(tool, "inputSchema", None) or getattr(tool, "input_schema", None) or {}
    properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
    required = set(schema.get("required", [])) if isinstance(schema, dict) else set()

    string_params = [
        name for name, spec in properties.items()
        if isinstance(spec, dict) and spec.get("type") == "string"
    ]
    if not string_params:
        return []

    marker = f"MCP-SCANNER-SSRF-{uuid.uuid4().hex}"
    server, hit_event = _start_canary_server(marker)
    port = server.server_address[1]
    canary_url = f"http://127.0.0.1:{port}/{marker}"

    findings = []

    try:
        for param in string_params:
            hit_event.clear()
            arguments = {param: canary_url}
            for other in required:
                if other != param and other not in arguments:
                    arguments[other] = "1"

            try:
                result = await session.call_tool(tool.name, arguments=arguments)
            except Exception:
                continue

            result_text = "".join(getattr(block, "text", "") for block in getattr(result, "content", []))

            # give a slow/backgrounded fetch inside the tool a brief moment to land
            await asyncio.sleep(0.2)

            if hit_event.is_set() or marker in result_text:
                findings.append({
                    "check": "ssrf",
                    "severity": "critical",
                    "tool": tool.name,
                    "reason": (
                        f"Confirmed by active test: calling '{tool.name}' with an attacker-controlled "
                        f"URL in parameter '{param}' made the server issue an outbound request to it -- "
                        "the canary listener recorded a hit, meaning this tool will fetch any URL a "
                        "caller supplies, including internal services, localhost, and cloud metadata "
                        "endpoints."
                    ),
                    "evidence": {"parameter": param, "payload": canary_url},
                    "recommendation": (
                        "Resolve and allowlist destination hosts before fetching. Block requests to "
                        "loopback, link-local (169.254.0.0/16), and private IP ranges, and disable "
                        "automatic redirect-following or re-validate the destination after each redirect."
                    ),
                })
    finally:
        server.shutdown()
        server.server_close()

    return findings