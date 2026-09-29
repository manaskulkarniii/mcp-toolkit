from .tool_poisoning import check_tool_description_injection
from .excessive_permissions import check_excessive_filesystem_scope
from .missing_authorization import check_missing_authorization
from .command_injection import check_command_injection
from .secret_leakage import check_secret_leakage
from .confused_deputy import check_confused_deputy
from .path_traversal import check_path_traversal
from .ssrf import check_ssrf

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