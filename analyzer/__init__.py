"""
ENIGMA Analyzer Package
Explainable Password Risk Analysis Workbench
DecodeLabs Industrial Training Kit 2026
"""

from .engine import (
    PasswordAnalyzer,
    AnalysisResult,
    RiskLevel,
    PolicyResult,
    CharacterMetrics,
    EntropyEstimate,
    VerdictStep,
)
from .patterns import (
    Finding,
    Severity,
    run_all_pattern_detectors,
)
from .common_passwords import (
    is_common_password,
    get_dataset_size,
    secure_compare_digest,
)
from .generator import (
    generate_random_password,
    generate_passphrase,
)
from .timing import (
    run_timing_demonstration,
    evaluate_gatekeeper_rule,
)

__all__ = [
    "PasswordAnalyzer",
    "AnalysisResult",
    "RiskLevel",
    "PolicyResult",
    "CharacterMetrics",
    "EntropyEstimate",
    "VerdictStep",
    "Finding",
    "Severity",
    "run_all_pattern_detectors",
    "is_common_password",
    "get_dataset_size",
    "secure_compare_digest",
    "generate_random_password",
    "generate_passphrase",
    "run_timing_demonstration",
    "evaluate_gatekeeper_rule",
]
