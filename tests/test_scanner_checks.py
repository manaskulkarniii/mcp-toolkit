"""
tests/test_scanner_checks.py

One positive test per scanner check -- does it correctly flag its
matching vulnerable test-range server -- plus one shared negative test
confirming every check stays quiet against the clean control server.
"""

import pytest

from scanner.checks.tool_poisoning import check_tool_description_injection
from scanner.checks.excessive_permissions import check_excessive_filesystem_scope
from scanner.checks.missing_authorization import check_missing_authorization
from scanner.checks.command_injection import check_command_injection
from scanner.checks.secret_leakage import check_secret_leakage
from scanner.checks.confused_deputy import check_confused_deputy
from scanner.checks.path_traversal import check_path_traversal
from scanner.checks.ssrf import check_ssrf

from ._helpers import run_check

CLEAN_SERVER = "test-range/clean_reference/server.py"

ALL_CHECKS = [
    check_tool_description_injection,
    check_excessive_filesystem_scope,
    check_missing_authorization,
    check_command_injection,
    check_secret_leakage,
    check_confused_deputy,
    check_path_traversal,
    check_ssrf,
]


def test_tool_description_injection_flags_vuln_server():
    findings = run_check(check_tool_description_injection, "test-range/vuln_tool/server.py")
    assert any(f["check"] == "tool_description_injection" for f in findings)

def test_excessive_filesystem_scope_flags_vuln_server():
    findings = run_check(check_excessive_filesystem_scope, "test-range/vuln_excessive_permissions/server.py")
    assert any(f["check"] == "excessive_filesystem_scope" and f["severity"] == "high" for f in findings)


def test_missing_authorization_flags_vuln_server():
    findings = run_check(check_missing_authorization, "test-range/vuln_missing_auth/server.py")
    assert any(f["check"] == "missing_authorization" for f in findings)

def test_command_injection_flags_vuln_server():
    findings = run_check(check_command_injection, "test-range/vuln_input_injection/server.py")
    assert any(f["check"] == "command_injection" and f["severity"] == "critical" for f in findings)


def test_secret_leakage_flags_vuln_server():
    findings = run_check(check_secret_leakage, "test-range/vuln_secret_leakage/server.py")
    assert any(f["check"] == "secret_leakage" for f in findings)


def test_confused_deputy_flags_vuln_server():
    findings = run_check(check_confused_deputy, "test-range/vuln_confused_deputy/server.py")
    assert any(f["check"] == "confused_deputy" for f in findings)


def test_path_traversal_flags_vuln_server():
    findings = run_check(check_path_traversal, "test-range/vuln_path_traversal/server.py")
    assert any(f["check"] == "path_traversal" and f["severity"] == "critical" for f in findings)


def test_ssrf_flags_vuln_server():
    findings = run_check(check_ssrf, "test-range/vuln_ssrf/server.py")
    assert any(f["check"] == "ssrf" and f["severity"] == "critical" for f in findings)


@pytest.mark.parametrize("check_fn", ALL_CHECKS, ids=lambda c: c.__name__)
def test_check_stays_quiet_on_clean_server(check_fn):
    findings = run_check(check_fn, CLEAN_SERVER)
    assert findings == [], f"{check_fn.__name__} flagged the clean control server: {findings}"