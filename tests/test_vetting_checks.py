"""
tests/test_vetting_checks.py

One positive test per vetting static check, plus a negative test
confirming all three stay quiet against the clean control server.
"""

import pytest

from vetting.manifest import parse_server_source
from vetting.static_checks import ALL_STATIC_CHECKS
from vetting.static_checks.dangerous_calls import check_dangerous_calls
from vetting.static_checks.hardcoded_network_targets import check_hardcoded_network_targets
from vetting.static_checks.declared_vs_actual import check_declared_vs_actual

CLEAN_SERVER = "test-range/clean_reference/server.py"


def _run_static_check(check_fn, server_path: str) -> list:
    source_text, tree, tools = parse_server_source(server_path)
    return check_fn(server_path, source_text, tools)


def test_dangerous_calls_flags_vuln_server():
    findings = _run_static_check(check_dangerous_calls, "test-range/vuln_input_injection/server.py")
    assert any(f["check"] == "dangerous_calls" and f["severity"] == "critical" for f in findings)


def test_hardcoded_network_targets_flags_vuln_server():
    findings = _run_static_check(check_hardcoded_network_targets, "test-range/vuln_hardcoded_callback/server.py")
    assert any(f["check"] == "hardcoded_network_targets" for f in findings)


def test_declared_vs_actual_flags_vuln_server():
    findings = _run_static_check(check_declared_vs_actual, "test-range/vuln_hidden_capability/server.py")
    assert any(
        f["check"] == "declared_vs_actual" and f["evidence"]["category"] == "filesystem access"
        for f in findings
    )


@pytest.mark.parametrize("check_fn", ALL_STATIC_CHECKS, ids=lambda c: c.__name__)
def test_static_check_stays_quiet_on_clean_server(check_fn):
    findings = _run_static_check(check_fn, CLEAN_SERVER)
    assert findings == [], f"{check_fn.__name__} flagged the clean control server: {findings}"