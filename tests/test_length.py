"""
Tests for length boundary checks, policy enforcement, and input size constraints.
"""

import pytest
from analyzer import RiskLevel


def test_empty_password_handling(analyzer):
    result = analyzer.analyze("")
    assert result.metrics.length == 0
    assert result.policy_result.compliant is False
    assert result.risk_level == RiskLevel.WEAK
    assert len(result.recommendations) > 0


def test_none_password_handling(analyzer):
    result = analyzer.analyze(None)
    assert result.metrics.length == 0
    assert result.policy_result.compliant is False
    assert result.risk_level == RiskLevel.WEAK


def test_sub_eight_characters_immediate_fail(analyzer):
    # Fails DecodeLabs baseline policy (< 8 chars)
    for length in (1, 2, 4, 7):
        pwd = "A1!" + "x" * (length - 3) if length >= 3 else "x" * length
        result = analyzer.analyze(pwd)
        assert result.metrics.length == length
        assert result.policy_result.compliant is False
        assert result.risk_level == RiskLevel.WEAK


def test_eight_character_boundary(analyzer):
    # Exactly 8 characters with 3 character classes (e.g. Upper, Lower, Digit)
    # Using non-sequential, non-common characters
    pwd = "Km7#pQ9x"
    result = analyzer.analyze(pwd)
    assert result.metrics.length == 8
    assert result.policy_result.compliant is True
    # Length 8 without severe patterns sits in MEDIUM
    assert result.risk_level == RiskLevel.MEDIUM


def test_twelve_plus_character_progression(analyzer):
    # 14 characters with all 4 classes and zero patterns
    pwd = "K7#m$P2!vL9&qX"
    result = analyzer.analyze(pwd)
    assert result.metrics.length == 14
    assert result.policy_result.compliant is True
    assert result.risk_level == RiskLevel.STRONG


def test_max_input_length_boundary_accepted(analyzer):
    # Exactly 512 code points should succeed without error
    pwd = "aB9!" * 128
    result = analyzer.analyze(pwd)
    assert result.metrics.length == 512


def test_max_input_length_exceeded_raises_error(analyzer):
    # 513 code points should raise ValueError to prevent resource exhaustion / ReDoS
    pwd = "a" * 513
    with pytest.raises(ValueError, match="exceeds maximum supported limit"):
        analyzer.analyze(pwd)
