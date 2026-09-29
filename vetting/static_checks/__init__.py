from .dangerous_calls import check_dangerous_calls
from .hardcoded_network_targets import check_hardcoded_network_targets
from .declared_vs_actual import check_declared_vs_actual

ALL_STATIC_CHECKS = [
    check_dangerous_calls,
    check_hardcoded_network_targets,
    check_declared_vs_actual,
]