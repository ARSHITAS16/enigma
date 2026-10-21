"""
Common Passwords Module for ENIGMA
Provides offline, local-first detection of known weak and commonly compromised passwords.

SECURITY NOTE:
- This is an offline dictionary check against a locally bundled list.
- It does NOT transmit passwords over any network.
- It does NOT claim to represent every breached credential in existence.
"""

from __future__ import annotations

import hmac
import hashlib
from pathlib import Path
from typing import Optional, Set

# Path to the offline common passwords dataset
_DATA_PATH = Path(__file__).parent.parent / "data" / "common_passwords.txt"
_COMMON_PASSWORDS: Optional[Set[str]] = None


def _load_common_passwords() -> Set[str]:
    """Loads common passwords into a memory-efficient set for O(1) lookup."""
    global _COMMON_PASSWORDS
    if _COMMON_PASSWORDS is not None:
        return _COMMON_PASSWORDS

    loaded: set[str] = set()
    if _DATA_PATH.exists():
        with open(_DATA_PATH, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                item = line.strip().lower()
                if item:
                    loaded.add(item)
    _COMMON_PASSWORDS = frozenset(loaded)
    return _COMMON_PASSWORDS


def is_common_password(candidate: str) -> tuple[bool, Optional[str]]:
    """
    Checks if a password (or its normalized lowercase/trimmed form) matches
    the offline common passwords list.
    
    Returns:
        (is_match, matched_pattern_label)
    """
    if not candidate:
        return False, None

    dictionary = _load_common_passwords()
    lowered = candidate.lower()
    trimmed = lowered.strip()

    # Exact match or lowercase match
    if lowered in dictionary:
        return True, "Exact match in top offline weak passwords dataset"

    if trimmed != lowered and trimmed in dictionary:
        return True, "Match in top offline weak passwords dataset (ignoring surrounding whitespace)"

    return False, None


def get_dataset_size() -> int:
    """Returns the number of entries in the local offline common passwords dataset."""
    return len(_load_common_passwords())


def secure_compare_digest(secret_a: str, secret_b: str) -> bool:
    """
    Performs constant-time comparison of two strings using hmac.compare_digest.
    
    Used when comparing sensitive authentication tokens, password hashes, or HMAC digests
    to mitigate timing side-channel attacks (Slide 11 of DecodeLabs assignment).
    """
    return hmac.compare_digest(secret_a.encode("utf-8"), secret_b.encode("utf-8"))
