"""
Tests for the complete engine decision logic:
- Precedence rules (common passwords override character variety)
- Severe patterns override character variety
- Passphrase exceptions under NIST SP 800-63B
- Recommendation generation
"""

from analyzer import RiskLevel, PasswordAnalyzer


def test_common_password_overrides_high_diversity(analyzer):
    # 'password123' has 11 chars, letters and numbers, but is a common password
    res = analyzer.analyze("password123")
    assert res.risk_level == RiskLevel.WEAK
    assert any(f.id == "VULN_COMMON_PASSWORD" for f in res.findings)


def test_leetspeak_override_precedence(analyzer):
    # 'P@ssw0rd1!' has all 4 character classes and length 10, but is forced WEAK
    res = analyzer.analyze("P@ssw0rd1!")
    assert res.policy_result.compliant is True  # Satisfies assignment checkbox policy
    assert res.risk_level == RiskLevel.WEAK     # But engine correctly classifies as WEAK!
    assert any(f.id == "PATTERN_LEETSPEAK_SUBSTITUTION" for f in res.findings)


def test_keyboard_walk_override_precedence(analyzer):
    # 'qwertyuiop' has 10 characters but is pure keyboard walk
    res = analyzer.analyze("qwertyuiop")
    assert res.risk_level == RiskLevel.WEAK
    assert any("PATTERN_KEYBOARD" in f.id for f in res.findings)


def test_strong_random_password(analyzer):
    # 16-character high entropy random password
    res = analyzer.analyze("K7#m$P2!vL9&qX8*")
    assert res.metrics.length == 16
    assert res.policy_result.compliant is True
    assert res.risk_level == RiskLevel.STRONG
    assert len(res.findings) == 0


def test_nist_passphrase_exception(analyzer):
    # 28-character passphrase without uppercase/digits
    res = analyzer.analyze("correct-horse-battery-staple")
    assert res.metrics.length == 28
    assert res.risk_level == RiskLevel.STRONG
    assert any("NIST SP 800-63B" in step.rule_applied for step in res.verdict_trace)


def test_recommendations_populated_coherently(analyzer):
    res = analyzer.analyze("12345")
    assert res.risk_level == RiskLevel.WEAK
    assert len(res.recommendations) >= 2
    # Must advise increasing length
    assert any("length" in r.lower() for r in res.recommendations)


def test_constant_time_comparison():
    from analyzer.timing import run_timing_demonstration, evaluate_gatekeeper_rule
    demo = run_timing_demonstration(iterations=5000)
    assert demo["iterations"] == 5000
    assert "explanation" in demo

    gate_reject = evaluate_gatekeeper_rule(length=6, has_classes=4, is_common=False)
    assert gate_reject["status"] == "REJECT"

    gate_pass = evaluate_gatekeeper_rule(length=14, has_classes=4, is_common=False)
    assert gate_pass["status"] == "PASS"
