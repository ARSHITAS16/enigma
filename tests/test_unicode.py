"""
Tests for Unicode code point counting, non-ASCII scripts,
accents, combining marks, emojis, and normalization behavior.
"""

import unicodedata
from analyzer import RiskLevel


def test_unicode_code_point_counting(analyzer):
    # 'Café' has 4 code points, but 5 bytes in UTF-8
    pwd = "Café123!"
    result = analyzer.analyze(pwd)
    assert result.metrics.length == 8
    assert result.metrics.unicode_non_ascii_count == 1


def test_cyrillic_script_handling(analyzer):
    # 'Пароль' (Russian for 'Password') + 2026!#
    pwd = "Пароль2026!#"
    result = analyzer.analyze(pwd)
    assert result.metrics.unicode_non_ascii_count == 6
    assert result.metrics.upper_count >= 1
    assert result.metrics.lower_count >= 5
    assert result.metrics.digit_count == 4
    assert result.metrics.symbol_count == 2
    assert result.policy_result.compliant is True


def test_emoji_code_point_measurement(analyzer):
    # Multi-byte emoji: '🔐' (U+1F510, 4 bytes UTF-8, 1 Python code point)
    pwd = "🔐MyVault2026!"
    result = analyzer.analyze(pwd)
    # 1 emoji + 7 alpha + 4 digits + 1 symbol = 13 code points
    assert result.metrics.length == 13
    assert result.metrics.symbol_count >= 2  # emoji counted as symbol/graphic
    assert result.metrics.unicode_non_ascii_count >= 1


def test_unicode_combining_characters(analyzer):
    # 'e' + combining acute accent U+0301 (NFD) vs 'é' (NFC)
    decomposed = "Cafe\u0301123!"
    composed = "Café123!"

    res_decomposed = analyzer.analyze(decomposed)
    res_composed = analyzer.analyze(composed)

    assert res_decomposed.metrics.combining_marks_count >= 1
    assert res_decomposed.metrics.has_unicode_normalization_difference is True
    assert res_composed.metrics.has_unicode_normalization_difference is False


def test_passwords_are_not_silently_normalized(analyzer):
    # Ensure analyzer does NOT mutate the original string
    raw_nfd = "Cafe\u0301123!"
    result = analyzer.analyze(raw_nfd)
    assert result.metrics.combining_marks_count == 1
    # Check that length is exactly the code point length of the raw input
    assert result.metrics.length == len(raw_nfd)
