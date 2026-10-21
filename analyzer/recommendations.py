"""
Context-Aware Recommendations Engine for ENIGMA
Generates prioritized, defensible, actionable guidance based on detected vulnerabilities.

Avoids simplistic advice (such as "just append !1 to the end") which creates
false senses of security against modern rule-based cracking tools.
"""

from __future__ import annotations

from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    from .engine import AnalysisResult


def generate_recommendations(result: AnalysisResult) -> List[str]:
    """
    Produces prioritized security recommendations tailored to the specific findings.
    """
    recs: List[str] = []

    # 1. Critical common password match
    if any(f.id == "VULN_COMMON_PASSWORD" for f in result.findings):
        recs.append(
            "CRITICAL: Replace this password entirely. It appears in public lists of known weak "
            "or compromised passwords and will be cracked instantly by standard dictionary attacks."
        )

    # 2. Length deficiencies
    if result.metrics.length == 0:
        return ["Enter a password to initiate explainable risk analysis."]

    if result.metrics.length < 8:
        recs.append(
            "Increase length to at least 12–16 characters. Passwords shorter than 8 characters "
            "can be exhausted via offline brute force in seconds regardless of character complexity."
        )
    elif result.metrics.length < 12 and result.risk_level.value != "STRONG":
        recs.append(
            "Expand length toward 14+ characters. Adding length provides exponential resistance "
            "to brute-force attacks compared to merely swapping character cases."
        )

    # 3. Leetspeak substitutions
    if any(f.id == "PATTERN_LEETSPEAK_SUBSTITUTION" for f in result.findings):
        recs.append(
            "Avoid predictable substitutions (e.g., '@' for 'a', '0' for 'o', '$' for 's'). "
            "Cracking software like Hashcat and John the Ripper applies rule engines (e.g., best64.rule) "
            "that reverse these patterns in the first pass."
        )

    # 4. Keyboard walks and sequences
    if any(f.id in ("PATTERN_KEYBOARD_WALK", "PATTERN_KEYBOARD_DIAGONAL") for f in result.findings):
        recs.append(
            "Eliminate keyboard sweeps (e.g., 'qwerty', 'asdf', '1qaz'). Spatial walks have "
            "near-zero search entropy and are checked immediately by attackers."
        )

    if any("PATTERN_SEQ" in f.id for f in result.findings):
        recs.append(
            "Remove numerical or alphabetical runs (e.g., '123456', 'abcdef'). Sequences "
            "substantially decrease real-world guessability."
        )

    # 5. Repeated characters or chunks
    if any(f.id in ("PATTERN_REPEAT_RUN", "PATTERN_REPEAT_DOMINANCE", "PATTERN_CHUNK_REPEAT") for f in result.findings):
        recs.append(
            "Eliminate repeated characters or syllables. Repetition inflates character count "
            "without contributing real cryptographic uncertainty."
        )

    # 6. Calendar dates or years
    if any(f.id in ("PATTERN_CALENDAR_YEAR", "PATTERN_CALENDAR_DATE") for f in result.findings):
        recs.append(
            "Avoid appending birth years, graduation years, or calendar dates (e.g., '2024', '1998'). "
            "Year and date masks are among the first combinatorial attacks executed."
        )

    # 7. Character set diversity (if length is otherwise acceptable)
    if result.metrics.length >= 8 and not result.policy_result.compliant:
        missing = []
        if not result.policy_result.has_upper:
            missing.append("uppercase letters")
        if not result.policy_result.has_lower:
            missing.append("lowercase letters")
        if not result.policy_result.has_digit:
            missing.append("numbers")
        if not result.policy_result.has_symbol:
            missing.append("special symbols")
        if missing:
            recs.append(
                f"Policy compliance: Incorporate {', '.join(missing)} to satisfy organizational gatekeeper policies."
            )

    # 8. General passphrase advice for strong or improving passwords
    if result.risk_level.value in ("MEDIUM", "STRONG") and len(recs) <= 1:
        recs.append(
            "Consider using a multi-word passphrase (e.g., 4 or 5 random dictionary words separated by hyphens). "
            "Passphrases offer high search spaces while remaining easy for humans to recall."
        )

    # 9. Operational hygiene (always applicable)
    recs.append(
        "Operational Security: Never reuse passwords across different services. Store credentials "
        "in an encrypted local or audited password manager, and enable multi-factor authentication (MFA)."
    )

    return recs
