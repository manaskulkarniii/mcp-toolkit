# MCP Security Toolkit

A hands-on security toolkit for the Model Context Protocol (MCP): a deliberately vulnerable test range of MCP servers, a runtime security scanner, a static supply-chain vetting tool, and a small web dashboard to view results.

> ⚠️ **Safety note:** The `test-range/` servers are intentionally vulnerable (path traversal, SSRF, command injection, secret leakage, and more). They exist only to validate the scanner and vetting tool. Run them locally only — never expose them to the internet or a real network.

## Architecture

\`\`\`mermaid
flowchart LR
    subgraph Test Range
        TR[Vulnerable MCP Servers]
    end

    subgraph Runtime Scanner
        S[scanner/client.py] -->|MCP stdio| TR
        S --> SC[scanner/checks/*]
        SC --> SR[scanner/report.py]
    end

    subgraph Static Vetting Tool
        V[vetting/manifest.py] -->|AST parse, no execution| TR
        V --> VC[vetting/static_checks/*]
        VC --> VR[vetting/report.py]
    end

    subgraph Web Dashboard
        D[Dashboard/app.py]
    end

    SR --> D
    VR --> D
\`\`\`

## Quickstart

\`\`\`bash
git clone https://github.com/manaskulkarniii/mcp-toolkit.git
cd mcp-toolkit
python -m venv .venv
.venv\\Scripts\\activate   # on Windows
pip install -r requirements.txt

# Run the runtime scanner against a vulnerable test-range server
python -m scanner.cli test-range/vuln_ssrf/server.py

# Run the static vetting tool against a vulnerable test-range server
python -m vetting.cli test-range/vuln_secret_leakage/server.py

# Launch the dashboard
python Dashboard/app.py
\`\`\`

## Detection Rule Catalog

### Runtime Scanner (dynamic — connects to a live MCP server)

| Check | Severity | What it detects |
|---|---|---|
| tool_poisoning | critical | Hidden instructions embedded in tool docstrings/descriptions |
| excessive_permissions | high | Tools requesting broader capability than their stated purpose needs |
| missing_authorization | critical | Sensitive/destructive tools with no auth/identity parameter |
| confused_deputy | high | Tools that can be tricked into acting on behalf of an unintended target |
| secret_leakage | critical | Secrets/credentials reflected back in tool output |
| command_injection | critical | Unsanitized input reaching a shell/subprocess call |
| path_traversal | critical | Unsanitized file paths allowing access outside an intended sandbox |
| ssrf | critical | Server-side requests to attacker-controlled URLs |

### Static Vetting Tool (static — AST analysis only, never executes the target)

| Check | Severity | What it detects |
|---|---|---|
| dangerous_calls | critical/high | Use of `eval`/`exec`, `os.system`/`os.popen`, or `subprocess.*` (escalated if `shell=True`) |
| hardcoded_network_targets | high | Hardcoded IPs/URLs embedded in source (e.g. telemetry/callback endpoints) |
| declared_vs_actual | high | Code touches filesystem/network/process APIs the tool's docstring never discloses |

## Testing

A pytest suite (`tests/`) validates every check: one positive test confirming each check fires on its matching vulnerable test-range server, and one parametrized negative test confirming all checks stay quiet on `test-range/clean_reference/server.py`.

\`\`\`bash
pytest
\`\`\`

## Project structure

\`\`\`
.
├── README.md
├── requirements.txt
├── Dashboard/
│   ├── app.py
│   └── templates/index.html
├── scanner/
│   ├── cli.py
│   ├── client.py
│   ├── report.py
│   └── checks/
│       ├── command_injection.py
│       ├── confused_deputy.py
│       ├── excessive_permissions.py
│       ├── missing_authorization.py
│       ├── path_traversal.py
│       ├── secret_leakage.py
│       ├── ssrf.py
│       └── tool_poisoning.py
├── vetting/
│   ├── cli.py
│   ├── manifest.py
│   ├── report.py
│   └── static_checks/
│       ├── dangerous_calls.py
│       ├── declared_vs_actual.py
│       └── hardcoded_network_targets.py
├── test-range/
│   ├── clean_reference/
│   ├── vuln_confused_deputy/
│   ├── vuln_excessive_permissions/
│   ├── vuln_hardcoded_callback/
│   ├── vuln_hidden_capability/
│   ├── vuln_input_injection/
│   ├── vuln_missing_auth/
│   ├── vuln_path_traversal/
│   ├── vuln_secret_leakage/
│   ├── vuln_ssrf/
│   └── vuln_tool/
└── tests/
    ├── _helpers.py
    ├── test_scanner_checks.py
    └── test_vetting_checks.py
\`\`\`

## License

MIT