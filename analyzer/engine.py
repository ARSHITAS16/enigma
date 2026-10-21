"""
Explainable Password Risk Engine for ENIGMA
Implements the core Input-Process-Output (IPO) architecture for local-first risk analysis.

Design Principles:
- Deterministic rules engine with documented precedence.
- Pure string analysis without external network transmission.
- Unicode-aware code point measurement.
- Explicit decoupling of Policy Compliance from true Risk Assessment.
- Explainable Verdict Trace detailing every stage of evaluation.
"""

from __future__ import annotations

import math
import string
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

from .common_passwords import is_common_password, get_dataset_size
from .patterns import (
    Finding,
    Severity,
    run_all_pattern_detectors
)
from .recommendations import generate_recommendations


class RiskLevel(Enum):
    WEAK = "WEAK"
    MEDIUM = "MEDIUM"
    STRONG = "STRONG"


@dataclass(frozen=True)
class PolicyResult:
    """Represents the explicit assignment policy compliance check."""
    compliant: bool
    min_length_required: int
    actual_length: int
    has_upper: bool
    has_lower: bool
    has_digit: bool
    has_symbol: bool
    classes_satisfied: int
    min_classes_required: int
    summary_message: str


@dataclass(frozen=True)
class CharacterMetrics:
    """Detailed composition metrics measured across Unicode code points."""
    length: int
    upper_count: int
    lower_count: int
    digit_count: int
    symbol_count: int
    whitespace_count: int
    unicode_non_ascii_count: int
    combining_marks_count: int
    unique_char_count: int
    estimated_charset_pool_size: int
    has_unicode_normalization_difference: bool


@dataclass(frozen=True)
class EntropyEstimate:
    """
    Theoretical pool entropy calculation with transparent educational limitations.
    Formula: E = L * log2(R) where L is length and R is pool size.
    """
    bits: float
    pool_size: int
    formula_description: str
    educational_caveat: str


@dataclass(frozen=True)
class VerdictStep:
    """Single step in the explainable decision audit pipeline."""
    stage: str
    rule_applied: str
    outcome: str
    impact: str
    security_reasoning: str


@dataclass
class AnalysisResult:
    """Comprehensive, structured evaluation result returned by the ENIGMA engine."""
    risk_level: RiskLevel
    policy_result: PolicyResult
    metrics: CharacterMetrics
    entropy: EntropyEstimate
    findings: List[Finding]
    positive_observations: List[str]
    limitations: List[str]
    verdict_trace: List[VerdictStep]
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "risk_level": self.risk_level.value,
            "policy_compliant": self.policy_result.compliant,
            "length": self.metrics.length,
            "classes_satisfied": self.policy_result.classes_satisfied,
            "entropy_bits": round(self.entropy.bits, 1),
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "positive_observations": self.positive_observations,
            "recommendations": self.recommendations,
            "verdict_trace": [
                {
                    "stage": s.stage,
                    "rule": s.rule_applied,
                    "outcome": s.outcome,
                    "reasoning": s.security_reasoning
                }
                for s in self.verdict_trace
            ]
        }


class PasswordAnalyzer:
    """
    The main analyzer engine implementing the DecodeLabs Defensive Logic curriculum.
    Deterministic, linear-time, and privacy-preserving.
    """

    def __init__(
        self,
        min_length_policy: int = 8,
        min_classes_policy: int = 3,
        max_input_length: int = 512
    ):
        self.min_length_policy = min_length_policy
        self.min_classes_policy = min_classes_policy
        self.max_input_length = max_input_length

    def analyze(self, password: Optional[str]) -> AnalysisResult:
        """
        Executes the end-to-end Explainable Risk Analysis pipeline.
        
        Pipeline:
        1. Input Validation & Bounds Check
        2. Unicode Code Point & Character Set Metric Extraction
        3. Assignment Policy Compliance Verification
        4. Offline Common-Password & Predictable Pattern Detection
        5. Decision Precedence Rules Arbitration
        6. Theoretical Entropy Estimation
        7. Verdict Trace Construction ('Decode the Verdict')
        8. Context-Aware Recommendations Generation
        """
        # --- Stage 1: Input Validation ---
        if password is None:
            password = ""

        # Guard against denial of service / memory abuse
        if len(password) > self.max_input_length:
            raise ValueError(
                f"Password length ({len(password)}) exceeds maximum supported limit "
                f"of {self.max_input_length} code points."
            )

        # Empty password check
        if len(password) == 0:
            return self._build_empty_result()

        # --- Stage 2: Character Metrics & Unicode Inspection ---
        metrics = self._inspect_character_composition(password)

        # --- Stage 3: Policy Compliance Check ---
        policy_res = self._evaluate_policy(metrics)

        # --- Stage 4: Pattern Detection & Common Passwords ---
        findings: List[Finding] = []
        positive_observations: List[str] = []

        # Check offline weak credentials dataset
        is_common, reason = is_common_password(password)
        if is_common:
            findings.append(Finding(
                id="VULN_COMMON_PASSWORD",
                title="Known Weak / Common Password",
                severity=Severity.CRITICAL,
                description=f"Identified in the offline weak credentials dataset ({reason}).",
                evidence_redacted="Credential matches a top-ranked weak/leaked password entry.",
                recommendation="Do not use known common passwords. Automated attack bots test these immediately."
            ))
        else:
            positive_observations.append(
                f"No match in the offline database of {get_dataset_size():,} commonly targeted passwords."
            )

        # Run linear-time pattern detectors
        pattern_findings = run_all_pattern_detectors(password)
        findings.extend(pattern_findings)

        # Positive observations for good composition
        if metrics.length >= 14:
            positive_observations.append("Length meets or exceeds modern enterprise recommendations (>= 14 chars).")
        elif metrics.length >= 8:
            positive_observations.append("Length satisfies standard minimum baseline policy (>= 8 chars).")

        if policy_res.classes_satisfied >= 4:
            positive_observations.append("Utilizes all four primary character classes (upper, lower, digits, symbols).")
        elif policy_res.classes_satisfied >= 3:
            positive_observations.append(f"Demonstrates multi-class diversity ({policy_res.classes_satisfied}/4 classes).")

        if metrics.unicode_non_ascii_count > 0:
            positive_observations.append(
                f"Contains {metrics.unicode_non_ascii_count} non-ASCII Unicode code point(s), "
                f"substantially expanding the attacker search space."
            )

        if not any("PATTERN_KEYBOARD" in f.id for f in pattern_findings):
            positive_observations.append("Free of spatial keyboard walk patterns.")

        if not any("PATTERN_SEQ" in f.id for f in pattern_findings):
            positive_observations.append("No contiguous alphabetical or numeric progressions detected.")

        # --- Stage 5: Decision Precedence Rules & Verdict Trace ---
        risk_level, verdict_trace = self._evaluate_precedence(
            password=password,
            metrics=metrics,
            policy_res=policy_res,
            findings=findings
        )

        # --- Stage 6: Theoretical Entropy ---
        entropy = self._calculate_entropy(metrics)

        # --- Stage 7: Standard Limitations ---
        limitations = [
            "Local offline static analysis: cannot detect whether this credential exists in newly leaked breach databases.",
            "Personal context limitation: cannot identify personal identifiers (such as birth dates, pet names, or usernames) unless structured like generic years.",
            "Host memory boundary: Python string immutability means secret remnants may linger in heap memory until CPython garbage collection occurs.",
            "Evaluation scope: Password strength validation does not replace multi-factor authentication (MFA) or secure transport (TLS)."
        ]

        # --- Stage 8: Assemble Result & Recommendations ---
        result = AnalysisResult(
            risk_level=risk_level,
            policy_result=policy_res,
            metrics=metrics,
            entropy=entropy,
            findings=findings,
            positive_observations=positive_observations,
            limitations=limitations,
            verdict_trace=verdict_trace,
        )
        result.recommendations = generate_recommendations(result)
        return result

    def _inspect_character_composition(self, password: str) -> CharacterMetrics:
        """Measures length and character classes using Unicode-aware inspections."""
        upper = 0
        lower = 0
        digit = 0
        symbol = 0
        whitespace = 0
        non_ascii = 0
        combining = 0
        unique_chars = set(password)

        for ch in password:
            cat = unicodedata.category(ch)

            if ord(ch) > 127:
                non_ascii += 1

            if cat.startswith("M"):
                combining += 1

            if ch.isspace():
                whitespace += 1
            elif ch.isupper() or cat.startswith("Lu"):
                upper += 1
            elif ch.islower() or cat.startswith("Ll"):
                lower += 1
            elif ch.isdigit() or cat.startswith("Nd"):
                digit += 1
            elif (ch in string.punctuation) or cat.startswith("P") or cat.startswith("S"):
                symbol += 1
            else:
                # Other characters (emojis, uncategorized symbols)
                symbol += 1

        # Calculate estimated pool size
        pool = 0
        if lower > 0:
            pool += 26
        if upper > 0:
            pool += 26
        if digit > 0:
            pool += 10
        if symbol > 0:
            pool += 33
        if whitespace > 0:
            pool += 1
        if non_ascii > 0:
            # Add reasonable search space for international scripts
            pool += 128

        pool = max(pool, 1)

        # Check if the input deviates from canonical NFC normalization form
        nfc = unicodedata.normalize("NFC", password)
        has_norm_diff = (nfc != password)

        return CharacterMetrics(
            length=len(password),
            upper_count=upper,
            lower_count=lower,
            digit_count=digit,
            symbol_count=symbol,
            whitespace_count=whitespace,
            unicode_non_ascii_count=non_ascii,
            combining_marks_count=combining,
            unique_char_count=len(unique_chars),
            estimated_charset_pool_size=pool,
            has_unicode_normalization_difference=has_norm_diff
        )

    def _evaluate_policy(self, metrics: CharacterMetrics) -> PolicyResult:
        """Evaluates compliance against organizational baseline policy (DecodeLabs standard)."""
        has_upper = metrics.upper_count > 0
        has_lower = metrics.lower_count > 0
        has_digit = metrics.digit_count > 0
        has_symbol = metrics.symbol_count > 0

        classes_satisfied = sum([has_upper, has_lower, has_digit, has_symbol])
        length_ok = metrics.length >= self.min_length_policy
        classes_ok = classes_satisfied >= self.min_classes_policy

        compliant = length_ok and classes_ok

        if compliant:
            msg = f"Complies with organizational baseline policy (Length: {metrics.length}/{self.min_length_policy}, Classes: {classes_satisfied}/{self.min_classes_policy})."
        elif not length_ok and not classes_ok:
            msg = f"Non-compliant: Fails minimum length ({metrics.length}/{self.min_length_policy}) and character diversity ({classes_satisfied}/{self.min_classes_policy})."
        elif not length_ok:
            msg = f"Non-compliant: Length {metrics.length} is below required minimum of {self.min_length_policy} code points."
        else:
            msg = f"Non-compliant: Satisfies only {classes_satisfied} of {self.min_classes_policy} required character categories."

        return PolicyResult(
            compliant=compliant,
            min_length_required=self.min_length_policy,
            actual_length=metrics.length,
            has_upper=has_upper,
            has_lower=has_lower,
            has_digit=has_digit,
            has_symbol=has_symbol,
            classes_satisfied=classes_satisfied,
            min_classes_required=self.min_classes_policy,
            summary_message=msg
        )

    def _evaluate_precedence(
        self,
        password: str,
        metrics: CharacterMetrics,
        policy_res: PolicyResult,
        findings: List[Finding]
    ) -> Tuple[RiskLevel, List[VerdictStep]]:
        """
        Executes strict precedence arbitration.
        Critical predictability rules OVERRIDE character diversity.
        """
        trace: List[VerdictStep] = []

        # Step 1: Input Validation
        trace.append(VerdictStep(
            stage="1. Input Validation",
            rule_applied="Unicode Code Point Ingestion",
            outcome=f"Ingested {metrics.length} code points",
            impact="NEUTRAL",
            security_reasoning="Password processed locally without truncation or silent modification."
        ))

        # Step 2: Policy Compliance
        pol_outcome = "PASS" if policy_res.compliant else "FAIL"
        trace.append(VerdictStep(
            stage="2. Policy Verification",
            rule_applied=f"DecodeLabs Baseline ({self.min_length_policy}+ chars, {self.min_classes_policy}+ classes)",
            outcome=pol_outcome,
            impact="POSITIVE" if policy_res.compliant else "NEGATIVE",
            security_reasoning=policy_res.summary_message
        ))

        # Step 3: Pattern Analysis
        sev_counts = {sev: sum(1 for f in findings if f.severity == sev) for sev in Severity}
        pattern_summary = f"{len(findings)} finding(s): {sev_counts[Severity.CRITICAL]} critical, {sev_counts[Severity.HIGH]} high, {sev_counts[Severity.MEDIUM]} medium."
        trace.append(VerdictStep(
            stage="3. Pattern Detection",
            rule_applied="Linear Scan for Predictable Structures",
            outcome=pattern_summary,
            impact="NEGATIVE" if findings else "POSITIVE",
            security_reasoning="Detects spatial walks, sequences, repetitions, and leetspeak substitutions."
        ))

        # --- PRECEDENCE RULE ARBITRATION ---

        # Precedence Rule 1: Known Common Password Match
        has_common = any(f.id == "VULN_COMMON_PASSWORD" for f in findings)
        if has_common:
            trace.append(VerdictStep(
                stage="4. Precedence Arbitration",
                rule_applied="PRECEDENCE_RULE_1: Known Weak Match Override",
                outcome="FORCED_WEAK",
                impact="CRITICAL",
                security_reasoning=(
                    "Credential appears in public offline weak password dictionaries. "
                    "In accordance with NIST SP 800-63B guidelines, known weak passwords "
                    "must be rejected regardless of length or character class variety."
                )
            ))
            return RiskLevel.WEAK, trace

        # Precedence Rule 2: Critical / Severe Length Failure (< 8)
        if metrics.length < 8:
            trace.append(VerdictStep(
                stage="4. Precedence Arbitration",
                rule_applied="PRECEDENCE_RULE_2: Sub-8 Character Floor",
                outcome="FORCED_WEAK",
                impact="HIGH_RISK",
                security_reasoning=(
                    f"Length ({metrics.length}) is strictly under the 8-character minimum. "
                    "Passwords shorter than 8 characters can be completely exhausted via GPU brute-force "
                    "in minutes, regardless of character composition."
                )
            ))
            return RiskLevel.WEAK, trace

        # Precedence Rule 3: High-Severity Pattern Domination
        has_high_pattern = any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)
        if has_high_pattern:
            # Even if length is >= 8 and classes are high, severe pattern forces Weak or Medium
            if metrics.length < 14:
                trace.append(VerdictStep(
                    stage="4. Precedence Arbitration",
                    rule_applied="PRECEDENCE_RULE_3: Severe Predictability Override",
                    outcome="FORCED_WEAK",
                    impact="HIGH_RISK",
                    security_reasoning=(
                        "Contains high-severity predictability patterns (such as obvious leetspeak substitution, "
                        "extensive repetition, or long keyboard sweeps). Character variety cannot compensate for structural predictability."
                    )
                ))
                return RiskLevel.WEAK, trace
            else:
                trace.append(VerdictStep(
                    stage="4. Precedence Arbitration",
                    rule_applied="PRECEDENCE_RULE_3B: Length Mitigated Pattern",
                    outcome="DEGRADED_TO_MEDIUM",
                    impact="MODERATE_RISK",
                    security_reasoning=(
                        "Substantial length (>= 14 chars) provides keyspace volume, but detected predictability "
                        "prevents qualification for STRONG status."
                    )
                ))
                return RiskLevel.MEDIUM, trace

        # Precedence Rule 4: Passphrase Exception (NIST SP 800-63B)
        # If length >= 18, with zero high/medium findings, qualify as STRONG even if legacy 3-class rule fails
        has_any_pattern = bool(findings)
        if metrics.length >= 18 and not has_any_pattern:
            trace.append(VerdictStep(
                stage="4. Precedence Arbitration",
                rule_applied="PRECEDENCE_RULE_4A: NIST SP 800-63B Long Passphrase Qualification",
                outcome="CLASSIFIED_STRONG",
                impact="POSITIVE",
                security_reasoning=(
                    f"Extensive length ({metrics.length} code points) delivers immense search space resistance. "
                    "Under NIST SP 800-63B guidelines, long passphrases (>= 18 chars) achieve high entropy "
                    "without requiring artificial uppercase or digit substitutions."
                )
            ))
            return RiskLevel.STRONG, trace

        # Precedence Rule 4B: Moderate Pattern / Policy Non-Compliance
        has_medium_pattern = any(f.severity == Severity.MEDIUM for f in findings)
        if not policy_res.compliant or has_medium_pattern or metrics.length < 12:
            trace.append(VerdictStep(
                stage="4. Precedence Arbitration",
                rule_applied="PRECEDENCE_RULE_4B: Moderate Risk Balance",
                outcome="CLASSIFIED_MEDIUM",
                impact="MODERATE_RISK",
                security_reasoning=(
                    "Password satisfies minimum threshold without critical flaws, but fails either "
                    "the diversity policy, contains moderate patterns, or has length under 12 characters."
                )
            ))
            return RiskLevel.MEDIUM, trace

        # Precedence Rule 5: Strong Qualification
        trace.append(VerdictStep(
            stage="4. Precedence Arbitration",
            rule_applied="PRECEDENCE_RULE_5: Clean High-Entropy Qualification",
            outcome="CLASSIFIED_STRONG",
            impact="POSITIVE",
            security_reasoning=(
                f"Password demonstrates robust length ({metrics.length} code points), passes organizational diversity "
                f"policy, and exhibits no detectable sequences, spatial sweeps, or dictionary substitutions."
            )
        ))
        return RiskLevel.STRONG, trace

    def _calculate_entropy(self, metrics: CharacterMetrics) -> EntropyEstimate:
        """
        Computes theoretical pool entropy: E = L * log2(R).
        Includes educational explanations of theoretical vs real-world entropy.
        """
        if metrics.length == 0 or metrics.estimated_charset_pool_size <= 1:
            return EntropyEstimate(
                bits=0.0,
                pool_size=0,
                formula_description="0 bits (Empty input)",
                educational_caveat="No characters entered."
            )

        bits = metrics.length * math.log2(metrics.estimated_charset_pool_size)

        caveat = (
            f"Theoretical pool entropy calculated as L({metrics.length}) × log₂(R={metrics.estimated_charset_pool_size}) = {bits:.1f} bits. "
            "IMPORTANT: This formula assumes each character is independently and uniformly chosen at random. "
            "Human passwords exhibit strong non-uniformity (common words, predictable substitutions, predictable suffixes). "
            "Therefore, theoretical entropy represents a mathematical upper bound, NOT true guessability."
        )

        return EntropyEstimate(
            bits=round(bits, 2),
            pool_size=metrics.estimated_charset_pool_size,
            formula_description=f"{metrics.length} chars × log₂({metrics.estimated_charset_pool_size} pool)",
            educational_caveat=caveat
        )

    def _build_empty_result(self) -> AnalysisResult:
        """Returns clean empty state when no input is provided."""
        metrics = CharacterMetrics(
            length=0, upper_count=0, lower_count=0, digit_count=0,
            symbol_count=0, whitespace_count=0, unicode_non_ascii_count=0,
            combining_marks_count=0, unique_char_count=0,
            estimated_charset_pool_size=0,
            has_unicode_normalization_difference=False
        )
        policy_res = PolicyResult(
            compliant=False, min_length_required=self.min_length_policy,
            actual_length=0, has_upper=False, has_lower=False,
            has_digit=False, has_symbol=False, classes_satisfied=0,
            min_classes_required=self.min_classes_policy,
            summary_message="No password entered."
        )
        entropy = EntropyEstimate(
            bits=0.0, pool_size=0, formula_description="0 bits",
            educational_caveat="Awaiting password input."
        )
        return AnalysisResult(
            risk_level=RiskLevel.WEAK,
            policy_result=policy_res,
            metrics=metrics,
            entropy=entropy,
            findings=[],
            positive_observations=[],
            limitations=["Enter a password above to begin analysis."],
            verdict_trace=[],
            recommendations=["Enter a candidate password into the input console to begin explainable analysis."]
        )
