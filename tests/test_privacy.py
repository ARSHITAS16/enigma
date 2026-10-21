"""
Tests for local-first privacy, secret redaction, error message safety,
and deterministic reproduction.
"""

import pytest
from analyzer import PasswordAnalyzer, RiskLevel
from analyzer.patterns import _redact_token


def test_redact_token_masks_content():
    # Long token masked with ellipsis
    assert _redact_token("supersecretpassword", max_visible=3) == "sup..."
    # Short token
    assert _redact_token("abc", max_visible=3) == "a..."
    assert _redact_token("a", max_visible=3) == "a..."


def test_findings_never_reveal_full_secret(analyzer):
    # Secret password with patterns
    secret = "TopSecretPassword123!@#"
    result = analyzer.analyze(secret)

    for finding in result.findings:
        # Full secret must never be in title, description, or evidence
        assert secret not in finding.title
        assert secret not in finding.description
        assert secret not in finding.evidence_redacted
        assert secret not in finding.recommendation


def test_verdict_trace_never_reveals_secret(analyzer):
    secret = "SuperSecretAdmin2026!"
    result = analyzer.analyze(secret)

    for step in result.verdict_trace:
        assert secret not in step.stage
        assert secret not in step.rule_applied
        assert secret not in step.outcome
        assert secret not in step.security_reasoning


def test_oversized_input_error_does_not_leak_input_payload(analyzer):
    long_secret = "ConfidentialPasswordPayload" * 30
    with pytest.raises(ValueError) as excinfo:
        analyzer.analyze(long_secret)

    err_msg = str(excinfo.value)
    # Error message must specify length, but NOT echo the confidential string payload
    assert long_secret not in err_msg
    assert "exceeds maximum supported limit" in err_msg


def test_deterministic_reproducibility(analyzer):
    # Multiple identical runs must return identical structures
    pwd = "RandomSecret123#$!@Alpha"
    res1 = analyzer.analyze(pwd)
    res2 = analyzer.analyze(pwd)

    assert res1.risk_level == res2.risk_level
    assert res1.policy_result.compliant == res2.policy_result.compliant
    assert res1.entropy.bits == res2.entropy.bits
    assert len(res1.findings) == len(res2.findings)
    assert len(res1.verdict_trace) == len(res2.verdict_trace)
