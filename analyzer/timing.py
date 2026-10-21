"""
Timing Attack Demonstrator and Gatekeeper Pipeline for ENIGMA
Implements themes from Slide 11 and Slide 12 of the DecodeLabs Curriculum:

- Slide 11: Timing Attacks & Constant-Time Verification (hmac.compare_digest)
- Slide 12: Gatekeeper Rule ("You cannot hash what is weak. Filter entropy before Argon2id.")
"""

from __future__ import annotations

import hmac
import time
from typing import Dict, Any


def run_timing_demonstration(iterations: int = 20000) -> Dict[str, Any]:
    """
    Demonstrates the difference between standard string comparison ('==')
    and constant-time comparison ('hmac.compare_digest').

    Educational Demonstration:
    - Target secret: 32-character token
    - Test candidate A fails on character 0 (early exit in naive '==')
    - Test candidate B fails on character 31 (late exit in naive '==')
    - Constant-time comparison ensures identical execution profile regardless of mismatch offset.
    """
    secret = "a" * 32
    early_fail = "b" + "a" * 31  # Fails at index 0
    late_fail = "a" * 31 + "b"   # Fails at index 31

    # Standard equality (non-constant time)
    start_early = time.perf_counter_ns()
    for _ in range(iterations):
        _ = (secret == early_fail)
    elapsed_early_ns = time.perf_counter_ns() - start_early

    start_late = time.perf_counter_ns()
    for _ in range(iterations):
        _ = (secret == late_fail)
    elapsed_late_ns = time.perf_counter_ns() - start_late

    # Constant-time comparison (hmac.compare_digest)
    secret_bytes = secret.encode("utf-8")
    early_bytes = early_fail.encode("utf-8")
    late_bytes = late_fail.encode("utf-8")

    start_ct_early = time.perf_counter_ns()
    for _ in range(iterations):
        _ = hmac.compare_digest(secret_bytes, early_bytes)
    elapsed_ct_early_ns = time.perf_counter_ns() - start_ct_early

    start_ct_late = time.perf_counter_ns()
    for _ in range(iterations):
        _ = hmac.compare_digest(secret_bytes, late_bytes)
    elapsed_ct_late_ns = time.perf_counter_ns() - start_ct_late

    return {
        "iterations": iterations,
        "standard_early_ns": elapsed_early_ns,
        "standard_late_ns": elapsed_late_ns,
        "standard_diff_ns": abs(elapsed_late_ns - elapsed_early_ns),
        "constant_early_ns": elapsed_ct_early_ns,
        "constant_late_ns": elapsed_ct_late_ns,
        "constant_diff_ns": abs(elapsed_ct_late_ns - elapsed_ct_early_ns),
        "explanation": (
            "Standard comparison ('==') terminates immediately upon the first byte mismatch, "
            "leaking position information via execution latency. In contrast, 'hmac.compare_digest' "
            "inspects all bytes in constant time (using OpenSSL CRYPTO_memcmp), eliminating the timing side-channel."
        )
    }


def evaluate_gatekeeper_rule(length: int, has_classes: int, is_common: bool) -> Dict[str, Any]:
    """
    Evaluates the 'Gatekeeper Rule' (Slide 12: 'Validation Before Encryption').

    Principle:
    - KDFs like Argon2id or bcrypt are intentionally computationally intensive (cost parameters).
    - Hashing weak passwords wastes server resources and leaves credentials susceptible to dictionary precomputations.
    - The Gatekeeper filters low-entropy or common inputs before any KDF computation occurs.
    """
    if is_common:
        return {
            "status": "REJECT",
            "action": "HALT_BEFORE_HASHING",
            "message": "Known weak credential. Immediate rejection prior to KDF execution.",
            "kdf_cycles_saved": True
        }

    if length < 8:
        return {
            "status": "REJECT",
            "action": "HALT_BEFORE_HASHING",
            "message": "Length below 8 characters. Fails gatekeeper minimum policy.",
            "kdf_cycles_saved": True
        }

    if has_classes < 3:
        return {
            "status": "WARN",
            "action": "POLICY_EXCEPTION",
            "message": "Acceptable length, but insufficient character diversity.",
            "kdf_cycles_saved": False
        }

    return {
        "status": "PASS",
        "action": "PROCEED_TO_ARGON2ID",
        "message": "Input passed gatekeeper entropy filtration. Cleared for Argon2id key derivation.",
        "kdf_cycles_saved": False
    }
