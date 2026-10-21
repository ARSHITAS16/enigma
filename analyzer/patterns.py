"""
Predictable Pattern Detection Module for ENIGMA
Identifies structured vulnerabilities and human predictability patterns in passwords.

All detectors are designed to be efficient (O(n) where n is password length)
and return structured findings with REDACTED evidence that never leaks secret credentials.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional
from .common_passwords import is_common_password


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass(frozen=True)
class Finding:
    """Represents a discrete security finding produced by the analyzer."""
    id: str
    title: str
    severity: Severity
    description: str
    evidence_redacted: str
    recommendation: str

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence_redacted,
            "recommendation": self.recommendation,
        }


# Standard QWERTY keyboard sequences for spatial walk detection
_KEYBOARD_ROWS = [
    "1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./",
]

# Diagonal walks on standard QWERTY
_KEYBOARD_DIAGONALS = [
    "1qaz", "2wsx", "3edc", "4rfv", "5tgb",
    "6yhn", "7ujm", "8ik,", "9ol.", "0p;/"
]

# Leetspeak translation table (targeting vowels and common consonants)
_LEET_MAP = {
    '@': 'a', '4': 'a',
    '8': 'b',
    '(': 'c', '<': 'c',
    '3': 'e',
    '1': 'i', '!': 'i', '|': 'i',
    '0': 'o',
    '5': 's', '$': 's',
    '7': 't', '+': 't',
}


def _redact_token(token: str, max_visible: int = 3) -> str:
    """Returns a privacy-safe preview of a substring (e.g. 'qwe...')."""
    if len(token) <= max_visible:
        return f"{token[0]}..."
    return f"{token[:max_visible]}..."


def detect_repeated_characters(password: str) -> List[Finding]:
    """
    Detects runs of identical characters (e.g., 'aaaa' or '1111')
    and single-character dominance over the whole string.
    """
    findings: List[Finding] = []
    if len(password) < 3:
        return findings

    # 1. Consecutive identical character runs of 3 or more
    pattern = re.compile(r'(.)\1{2,}')
    for match in pattern.finditer(password):
        char = match.group(1)
        run_len = len(match.group(0))
        sev = Severity.HIGH if run_len >= 4 else Severity.MEDIUM
        findings.append(Finding(
            id="PATTERN_REPEAT_RUN",
            title="Consecutive Character Repetition",
            severity=sev,
            description=f"Contains {run_len} identical consecutive characters.",
            evidence_redacted=f"Character '{char}' repeated {run_len} times consecutively.",
            recommendation="Avoid repeating identical characters consecutively. Use varied, independent characters."
        ))

    # 2. String dominance: one character accounts for >= 50% of the entire password
    counts: dict[str, int] = {}
    for ch in password:
        counts[ch] = counts.get(ch, 0) + 1

    max_char, max_count = max(counts.items(), key=lambda item: item[1])
    dominance_ratio = max_count / len(password)
    if dominance_ratio >= 0.5 and len(password) >= 6 and not any(f.id == "PATTERN_REPEAT_RUN" and f.severity == Severity.HIGH for f in findings):
        findings.append(Finding(
            id="PATTERN_REPEAT_DOMINANCE",
            title="Single Character Dominance",
            severity=Severity.HIGH,
            description=f"A single character comprises {int(dominance_ratio * 100)}% of the entire password.",
            evidence_redacted=f"Character '{max_char}' appears {max_count} times across {len(password)} characters.",
            recommendation="Distribute character selection across independent sets rather than reusing a dominant symbol."
        ))

    return findings


def detect_sequences(password: str) -> List[Finding]:
    """
    Detects alphabetical and numerical ascending/descending sequences
    (e.g., '123', '12345', '987', 'abcdef', 'fedcba') in O(n) time.
    """
    findings: List[Finding] = []
    if len(password) < 3:
        return findings

    lowered = password.lower()
    n = len(lowered)

    # Scan for alphabetical sequences
    i = 0
    while i < n - 2:
        # Check ascending alpha
        if lowered[i].isalpha() and lowered[i+1].isalpha():
            asc_len = 1
            while (i + asc_len < n and lowered[i + asc_len].isalpha() and
                   ord(lowered[i + asc_len]) - ord(lowered[i + asc_len - 1]) == 1):
                asc_len += 1
            if asc_len >= 3:
                sample = _redact_token(password[i:i + asc_len])
                findings.append(Finding(
                    id="PATTERN_SEQ_ALPHA_ASC",
                    title="Ascending Alphabetical Sequence",
                    severity=Severity.HIGH if asc_len >= 5 else Severity.MEDIUM,
                    description=f"Contains an ascending alphabetical sequence of length {asc_len}.",
                    evidence_redacted=f"Alphabetical run '{sample}' of length {asc_len} at offset {i}.",
                    recommendation="Avoid contiguous alphabetical progressions (e.g. abcde). Attackers test these systematically."
                ))
                i += asc_len
                continue

            # Check descending alpha
            desc_len = 1
            while (i + desc_len < n and lowered[i + desc_len].isalpha() and
                   ord(lowered[i + desc_len - 1]) - ord(lowered[i + desc_len]) == 1):
                desc_len += 1
            if desc_len >= 3:
                sample = _redact_token(password[i:i + desc_len])
                findings.append(Finding(
                    id="PATTERN_SEQ_ALPHA_DESC",
                    title="Descending Alphabetical Sequence",
                    severity=Severity.HIGH if desc_len >= 5 else Severity.MEDIUM,
                    description=f"Contains a descending alphabetical sequence of length {desc_len}.",
                    evidence_redacted=f"Reverse alphabetical run '{sample}' of length {desc_len} at offset {i}.",
                    recommendation="Avoid reverse alphabetical progressions (e.g. fedcb)."
                ))
                i += desc_len
                continue

        # Check numerical sequences
        if lowered[i].isdigit() and lowered[i+1].isdigit():
            asc_len = 1
            while (i + asc_len < n and lowered[i + asc_len].isdigit() and
                   ord(lowered[i + asc_len]) - ord(lowered[i + asc_len - 1]) == 1):
                asc_len += 1
            if asc_len >= 3:
                sample = _redact_token(password[i:i + asc_len])
                findings.append(Finding(
                    id="PATTERN_SEQ_NUM_ASC",
                    title="Ascending Numerical Sequence",
                    severity=Severity.HIGH if asc_len >= 5 else Severity.MEDIUM,
                    description=f"Contains an ascending numerical progression of length {asc_len}.",
                    evidence_redacted=f"Numeric sequence '{sample}' of length {asc_len} at offset {i}.",
                    recommendation="Avoid consecutive counting numbers (e.g. 123456). These are standard in dictionary attacks."
                ))
                i += asc_len
                continue

            desc_len = 1
            while (i + desc_len < n and lowered[i + desc_len].isdigit() and
                   ord(lowered[i + desc_len - 1]) - ord(lowered[i + desc_len]) == 1):
                desc_len += 1
            if desc_len >= 3:
                sample = _redact_token(password[i:i + desc_len])
                findings.append(Finding(
                    id="PATTERN_SEQ_NUM_DESC",
                    title="Descending Numerical Sequence",
                    severity=Severity.HIGH if desc_len >= 5 else Severity.MEDIUM,
                    description=f"Contains a descending numerical progression of length {desc_len}.",
                    evidence_redacted=f"Reverse numeric run '{sample}' of length {desc_len} at offset {i}.",
                    recommendation="Avoid reverse counting sequences (e.g. 654321)."
                ))
                i += desc_len
                continue

        i += 1

    return findings


def detect_repeated_chunks(password: str) -> List[Finding]:
    """
    Detects repeated chunks/n-grams (e.g. 'abcabcabc', '121212', 'passpass').
    Scans for chunk sizes 2, 3, 4 repeated 2 or more times.
    """
    findings: List[Finding] = []
    if len(password) < 4:
        return findings

    lowered = password.lower()
    for chunk_size in (2, 3, 4, 5):
        pattern = re.compile(rf'(.{{{chunk_size}}})\1+')
        for match in pattern.finditer(lowered):
            full_match = match.group(0)
            chunk = match.group(1)
            repetitions = len(full_match) // chunk_size
            if repetitions >= 2:
                sample = _redact_token(chunk)
                findings.append(Finding(
                    id="PATTERN_CHUNK_REPEAT",
                    title="Repetitive Substring Chunk",
                    severity=Severity.MEDIUM if repetitions == 2 else Severity.HIGH,
                    description=f"Chunk of {chunk_size} characters repeated {repetitions} times.",
                    evidence_redacted=f"Pattern '{sample}' repeated {repetitions} times.",
                    recommendation="Avoid repeating the same phrase or syllable to inflate length."
                ))
                return findings

    return findings


def detect_keyboard_walks(password: str) -> List[Finding]:
    """
    Detects spatial keyboard walks along QWERTY rows, reverse rows, and diagonals.
    e.g., 'qwerty', 'asdfgh', '1qaz', 'zxcvbn'.
    """
    findings: List[Finding] = []
    if len(password) < 4:
        return findings

    lowered = password.lower()
    
    # Check horizontal rows (forward and reverse)
    for row in _KEYBOARD_ROWS:
        rev_row = row[::-1]
        for candidate_row in (row, rev_row):
            for window in range(len(candidate_row), 3, -1):
                for start in range(len(candidate_row) - window + 1):
                    walk = candidate_row[start:start + window]
                    if walk in lowered:
                        sample = _redact_token(walk)
                        findings.append(Finding(
                            id="PATTERN_KEYBOARD_WALK",
                            title="Keyboard Spatial Walk (QWERTY)",
                            severity=Severity.HIGH if window >= 5 else Severity.MEDIUM,
                            description=f"Contains a {window}-key keyboard walk along adjacent keys.",
                            evidence_redacted=f"Adjacent key sequence '{sample}' ({window} keys).",
                            recommendation="Avoid sliding across physical keyboard rows. Attackers prioritize keyboard walks."
                        ))
                        return findings

    # Check diagonals (forward and reverse)
    for diag in _KEYBOARD_DIAGONALS:
        rev_diag = diag[::-1]
        for d in (diag, rev_diag):
            if d in lowered:
                sample = _redact_token(d)
                findings.append(Finding(
                    id="PATTERN_KEYBOARD_DIAGONAL",
                    title="Diagonal Keyboard Walk",
                    severity=Severity.HIGH,
                    description=f"Contains a diagonal keyboard walk ('{sample}').",
                    evidence_redacted=f"Diagonal walk '{sample}' detected.",
                    recommendation="Avoid diagonal keyboard columns (e.g., 1qaz, 2wsx). Standard cracking dictionaries include these."
                ))
                return findings

    return findings


def detect_leetspeak_substitutions(password: str) -> List[Finding]:
    """
    Detects common character substitutions (e.g. '@' -> 'a', '0' -> 'o', '3' -> 'e', '$' -> 's').
    Checks whether the de-leeted string or its core root word matches a known weak password.
    """
    findings: List[Finding] = []
    if len(password) < 4:
        return findings

    lowered = password.lower()
    has_leet_chars = any(ch in _LEET_MAP for ch in lowered)
    if not has_leet_chars:
        return findings

    # 1. Full string translation
    translated_full = "".join(_LEET_MAP.get(ch, ch) for ch in lowered)

    # 2. Raw core extraction (strip leading/trailing digits, punctuation, and underscores)
    raw_core = re.sub(r'^[\d\W_]+|[\d\W_]+$', '', lowered)
    translated_core = "".join(_LEET_MAP.get(ch, ch) for ch in raw_core) if raw_core else ""

    match_found = False
    matched_word = ""

    # Check full translation first
    is_match_full, _ = is_common_password(translated_full)
    if is_match_full and translated_full != lowered:
        match_found = True
        matched_word = translated_full
    elif translated_core and len(translated_core) >= 4 and translated_core != raw_core:
        # Check core root word translation
        is_match_core, _ = is_common_password(translated_core)
        if is_match_core:
            match_found = True
            matched_word = translated_core

    if match_found:
        used_subs = sorted(list({f"'{ch}' -> '{_LEET_MAP[ch]}'" for ch in lowered if ch in _LEET_MAP}))
        sample_root = _redact_token(matched_word)
        findings.append(Finding(
            id="PATTERN_LEETSPEAK_SUBSTITUTION",
            title="Predictable Leetspeak Substitution",
            severity=Severity.HIGH,
            description="Uses predictable character substitutions on a known common password base.",
            evidence_redacted=f"Substitutions [{', '.join(used_subs)}] decode to weak base '{sample_root}'.",
            recommendation="Do not rely on simple substitutions (e.g. '@' for 'a', '0' for 'o'). Modern cracking rulesets unmask these instantly."
        ))

    return findings


def detect_date_or_year_patterns(password: str) -> List[Finding]:
    """
    Detects 4-digit years (1940-2035) and common date formats (YYYYMMDD, DDMMYYYY).
    """
    findings: List[Finding] = []
    if len(password) < 4:
        return findings

    # 1. 4-digit year at end, start, or boundary
    year_match = re.search(r'(19[4-9]\d|20[0-3]\d)', password)
    if year_match:
        year_str = year_match.group(1)
        start_idx = year_match.start()
        end_idx = year_match.end()
        is_boundary = (start_idx == 0 or end_idx == len(password) or 
                       password[start_idx - 1] in "_-@.!#" or 
                       (end_idx < len(password) and password[end_idx] in "_-@.!#"))
        
        findings.append(Finding(
            id="PATTERN_CALENDAR_YEAR",
            title="Calendar Year Pattern",
            severity=Severity.MEDIUM if is_boundary else Severity.LOW,
            description="Contains a recognizable four-digit calendar year (1940-2035).",
            evidence_redacted=f"Year '{year_str}' detected at position {start_idx}.",
            recommendation="Avoid appending birth years or current years to passwords. Attackers prioritize year masks."
        ))

    # 2. Standard 8-digit date pattern (YYYYMMDD or DDMMYYYY) bounded by non-digits or string ends
    date_match = re.search(r'(?:^|\D)(19\d\d|20\d\d)(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])(?:\D|$)', password)
    if not date_match:
        date_match = re.search(r'(?:^|\D)(0[1-9]|[12]\d|3[01])(0[1-9]|1[0-2])(19\d\d|20\d\d)(?:\D|$)', password)

    if date_match:
        findings.append(Finding(
            id="PATTERN_CALENDAR_DATE",
            title="Full Calendar Date Pattern",
            severity=Severity.HIGH,
            description="Contains a full 8-digit formatted calendar date.",
            evidence_redacted=f"Date sequence detected at offset {date_match.start()}.",
            recommendation="Do not use birthdates, anniversary dates, or formatted calendar timestamps."
        ))

    return findings


def run_all_pattern_detectors(password: str) -> List[Finding]:
    """
    Executes all pattern detectors sequentially and aggregates findings.
    Each detector is linear in input length O(n).
    """
    findings: List[Finding] = []
    findings.extend(detect_repeated_characters(password))
    findings.extend(detect_sequences(password))
    findings.extend(detect_repeated_chunks(password))
    findings.extend(detect_keyboard_walks(password))
    findings.extend(detect_leetspeak_substitutions(password))
    findings.extend(detect_date_or_year_patterns(password))
    return findings
