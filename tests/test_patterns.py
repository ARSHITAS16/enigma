"""
Tests for predictable pattern detection:
- Repeated characters and character dominance
- Alphabetical and numerical ascending/descending sequences
- Repetitive n-gram chunks
- Spatial keyboard walks (horizontal rows, reverse rows, diagonals)
- Leetspeak substitutions
- Date and calendar year patterns
"""

from analyzer.patterns import (
    detect_repeated_characters,
    detect_sequences,
    detect_repeated_chunks,
    detect_keyboard_walks,
    detect_leetspeak_substitutions,
    detect_date_or_year_patterns,
    Severity,
)
from analyzer.common_passwords import is_common_password


def test_repeated_characters_run():
    # 4 consecutive 'a's
    findings = detect_repeated_characters("K9#aaaaP2!")
    assert len(findings) >= 1
    assert any(f.id == "PATTERN_REPEAT_RUN" for f in findings)
    assert any("repeated 4 times" in f.evidence_redacted for f in findings)


def test_single_character_dominance():
    # 'a' is 7 out of 10 chars (70% dominance)
    findings = detect_repeated_characters("a1a2a3aaaa")
    assert any(f.id in ("PATTERN_REPEAT_RUN", "PATTERN_REPEAT_DOMINANCE") for f in findings)


def test_alphabetical_sequences():
    # Ascending 'abcdef'
    findings_asc = detect_sequences("K9#abcdef!2")
    assert any(f.id == "PATTERN_SEQ_ALPHA_ASC" for f in findings_asc)

    # Descending 'fedcba'
    findings_desc = detect_sequences("K9#fedcba!2")
    assert any(f.id == "PATTERN_SEQ_ALPHA_DESC" for f in findings_desc)


def test_numerical_sequences():
    # Ascending '123456'
    findings_asc = detect_sequences("Pass123456!")
    assert any(f.id == "PATTERN_SEQ_NUM_ASC" for f in findings_asc)

    # Descending '654321'
    findings_desc = detect_sequences("Pass654321!")
    assert any(f.id == "PATTERN_SEQ_NUM_DESC" for f in findings_desc)


def test_repeated_chunks():
    # 'abc' repeated 3 times
    findings = detect_repeated_chunks("abcabcabc!9")
    assert any(f.id == "PATTERN_CHUNK_REPEAT" for f in findings)


def test_keyboard_walks_horizontal():
    # QWERTY horizontal row walk
    findings = detect_keyboard_walks("Myqwerty!2026")
    assert any(f.id == "PATTERN_KEYBOARD_WALK" for f in findings)

    # ASDFGH walk
    findings_asdf = detect_keyboard_walks("Secasdfgh#99")
    assert any(f.id == "PATTERN_KEYBOARD_WALK" for f in findings_asdf)


def test_keyboard_walks_diagonal():
    # Diagonal walk '1qaz'
    findings = detect_keyboard_walks("Test1qaz!9")
    assert any(f.id == "PATTERN_KEYBOARD_DIAGONAL" for f in findings)


def test_leetspeak_substitutions():
    # P@ssw0rd1! decodes to password
    findings = detect_leetspeak_substitutions("P@ssw0rd1!")
    assert any(f.id == "PATTERN_LEETSPEAK_SUBSTITUTION" for f in findings)
    assert any(f.severity == Severity.HIGH for f in findings)


def test_common_password_dataset_lookup():
    is_match, reason = is_common_password("password")
    assert is_match is True
    assert reason is not None

    is_match2, _ = is_common_password("12345678")
    assert is_match2 is True

    is_match3, _ = is_common_password("k9X#m2$pL8&qZ")
    assert is_match3 is False


def test_calendar_year_detection():
    # Boundary year 2024
    findings = detect_date_or_year_patterns("Password2024!")
    assert any(f.id == "PATTERN_CALENDAR_YEAR" for f in findings)


def test_full_calendar_date_detection():
    # 8-digit date format 20261020
    findings = detect_date_or_year_patterns("Pass_20261020_Key")
    assert any(f.id == "PATTERN_CALENDAR_DATE" for f in findings)
