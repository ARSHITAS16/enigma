"""
Tests for character class detection (uppercase, lowercase, digits, symbols)
and policy compliance combinations.
"""

from analyzer import RiskLevel


def test_single_class_only_fails_policy(analyzer):
    # Only lowercase (8+ chars)
    res_lower = analyzer.analyze("abcdefghij")
    assert res_lower.policy_result.compliant is False
    assert res_lower.policy_result.classes_satisfied == 1
    assert res_lower.policy_result.has_lower is True
    assert res_lower.policy_result.has_upper is False

    # Only uppercase (8+ chars)
    res_upper = analyzer.analyze("ABCDEFGHIJ")
    assert res_upper.policy_result.compliant is False
    assert res_upper.policy_result.classes_satisfied == 1
    assert res_upper.policy_result.has_upper is True

    # Only digits (8+ chars)
    res_digit = analyzer.analyze("8492048291")
    assert res_digit.policy_result.compliant is False
    assert res_digit.policy_result.classes_satisfied == 1
    assert res_digit.policy_result.has_digit is True

    # Only symbols (8+ chars)
    res_symbols = analyzer.analyze("!@#$%^&*()_")
    assert res_symbols.policy_result.compliant is False
    assert res_symbols.policy_result.classes_satisfied == 1
    assert res_symbols.policy_result.has_symbol is True


def test_two_classes_fails_three_class_policy(analyzer):
    # Upper + Lower only (8+ chars)
    res = analyzer.analyze("AbCdEfGhIjKl")
    assert res.policy_result.classes_satisfied == 2
    assert res.policy_result.compliant is False


def test_three_classes_satisfies_policy(analyzer):
    # Lower + Upper + Digit (no symbols)
    res = analyzer.analyze("Kx7mP9vL2qX8")
    assert res.policy_result.classes_satisfied == 3
    assert res.policy_result.compliant is True


def test_four_classes_satisfies_policy(analyzer):
    # Lower + Upper + Digit + Symbol
    res = analyzer.analyze("Kx7#mP9!vL2&")
    assert res.policy_result.classes_satisfied == 4
    assert res.policy_result.compliant is True
    assert res.metrics.upper_count > 0
    assert res.metrics.lower_count > 0
    assert res.metrics.digit_count > 0
    assert res.metrics.symbol_count > 0


def test_embedded_whitespace_handling(analyzer):
    # Password with internal space
    res = analyzer.analyze("Kx7# mP9! vL2&")
    assert res.metrics.whitespace_count == 2
    assert res.policy_result.compliant is True
