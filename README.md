# ENIGMA — Explainable Password Risk Analysis Workbench
### DecodeLabs Industrial Training Kit 2026 | Project 1: Password Strength Checker

> *"Decode the pattern. Reveal the risk. Protect the secret."*

[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.14-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)]()
[![Tests](https://img.shields.io/badge/tests-42%20passed%20(100%25)-brightgreen.svg)]()
[![Security](https://img.shields.io/badge/privacy-100%25%20local--first-blueviolet.svg)]()

---

## 1. Executive Summary & Problem Statement

Conventional password strength checkers evaluate credentials using superficial criteria: awarding arbitrary points for uppercase letters, digits, and punctuation marks. This approach creates a critical security illusion: a password like `P@ssw0rd1!` passes typical enterprise complexity rules (10 characters, 4 character classes) while being broken in seconds by modern cracking tools like Hashcat using basic mutation rulesets (e.g., `best64.rule`).

**ENIGMA** transforms the standard assignment into an **Explainable Password Risk Analysis Workbench**. Rather than returning an opaque numerical score, ENIGMA produces a structured, evidence-based audit explaining:
1. **What characteristics were detected** (code point length, Unicode character categories, pool entropy).
2. **Which characteristics increase or mitigate real-world risk**.
3. **What predictable structures were identified** (spatial keyboard walks, sequences, repetitive chunks, leetspeak substitutions, and common password matches).
4. **Why precedence rules override cosmetic variety** (a common password or severe pattern is classified as `WEAK` regardless of character diversity).
5. **What actionable, prioritized steps** the user should take to secure their credential.

---

## 2. DecodeLabs Curriculum Themes

ENIGMA directly addresses the architectural and defensive security themes established in the DecodeLabs Cyber Security Project 1 curriculum:

- **Slide 7 — The Unicode Curveball:** Expanded search space from 95 standard ASCII printable characters to 149,000+ Unicode code points. Unicode-aware classification (`unicodedata.category`) across international alphabets (Cyrillic, Latin-extended) and combining marks (NFC/NFD).
- **Slide 8 & 9 — Linear-Time IPO Model & Computational Efficiency:** $O(n)$ single-pass scanning without polynomial regular expressions, short-circuit execution, and ReDoS protection (512 code point cap).
- **Slide 10 — Volatile Security Trap (HINNOP Heap Analysis):** Documentation and architectural awareness of CPython heap memory, string immutability, garbage collection lifecycles, and RAM scraping threats (e.g. BlackPOS).
- **Slide 11 — Timing Attacks & Constant-Time Verification:** Live demonstration of latency side-channels in standard string equality (`==`) and constant-time mitigation using `hmac.compare_digest` (OpenSSL `CRYPTO_memcmp`).
- **Slide 12 — The Gatekeeper Rule:** *"You cannot hash what is weak. Filter entropy before Argon2id."* Pre-filtering weak inputs before invoking expensive Key Derivation Functions (KDFs).

---

## 3. Core Architecture & Project Layout

```
enigma/
├── app.py                      # Interactive Streamlit cybersecurity workbench
├── requirements.txt            # Pinned dependencies
├── README.md                   # Comprehensive project documentation
├── .gitignore                  # Git exclusions
├── analyzer/
│   ├── __init__.py             # Public API exports
│   ├── engine.py               # Deterministic Explainable Risk Engine & Precedence Rules
│   ├── patterns.py             # Linear-time detectors (sequences, walks, repeats, leetspeak)
│   ├── common_passwords.py     # Offline lookup for 4,200+ curated weak password signatures
│   ├── recommendations.py      # Context-aware remediation engine
│   ├── generator.py            # CSPRNG-based password & Diceware passphrase generator
│   └── timing.py               # Gatekeeper pipeline & timing attack demonstrator
├── data/
│   └── common_passwords.txt    # Curated offline signature dataset (deduplicated, privacy-safe)
├── docs/
│   ├── SECURITY_DESIGN.md      # Security architecture, IPO model, Unicode, & precedence rules
│   ├── THREAT_MODEL.md         # STRIDE threat model, boundaries, & residual risks
│   └── TESTING.md              # Test execution records, benchmarks, & SLA verification
└── tests/
    ├── conftest.py             # Pytest fixtures
    ├── test_length.py          # Boundary and policy tests
    ├── test_character_classes.py # Composition and diversity tests
    ├── test_patterns.py        # Predictable pattern detectors
    ├── test_unicode.py         # Code points, Cyrillic, emojis, normalization
    ├── test_privacy.py         # Redaction, zero-retention, safe error handling
    ├── test_engine.py          # Precedence rules, NIST passphrase exceptions, timing
    └── test_benchmark.py       # Linear time complexity & generator SLA
```

---

## 4. Key Features & Workbench Capabilities

### 🎮 Xbox PC App-Inspired UI/UX Shell
A modern, dark gaming-dashboard interface tailored for cybersecurity analysts:
- **Charcoal & Xbox Green Palette:** Deep charcoal backgrounds (`#101210`, `#191C19`), rounded cards (`#202420`), subtle grey-green borders (`#343A34`), and Xbox-inspired green interactive accents (`#80CC14`).
- **Compact Vertical Navigation:** 6-screen left sidebar featuring Home, Password Analyzer, Pattern Lab, Secure Generator, Security Insights, and Settings.

### 🏠 Home Dashboard
Landing screen featuring:
- Hero banner: **PASSWORD SECURITY CENTER** with quick-launch "Analyze a Password" action.
- Three interactive game-tile style cards leading directly into Analyzer, Pattern Lab, and Generator.

### 🔍 Password Analyzer (The Centerpiece)
- Central analysis card with default masked input, show/hide toggle, primary green "Analyze Password" button, and RAM memory purge action.
- Executive verdict banner, segmented horizontal strength meter, 4 key metrics, detected risks, positive observations, and prioritized recommendations.
- **"Decode the Verdict":** Transparent step-by-step audit trace detailing every rule executed from input ingestion to precedence arbitration.

### 🎮 Pattern Lab (Game-Library-Style Presentation)
Curated synthetic examples presented as game tiles:
- Displays categories (Repeated runs, Keyboard walks, Leetspeak mutation, Date masks, NIST passphrases).
- Direct "Inspect in Analyzer" action that loads and analyzes each case with one click.

### ⚡ Secure Generator
- Generates high-entropy random character tokens (12–64 chars) with guaranteed multi-class representation via Python's `secrets` module (CSPRNG).
- Generates memorable EFF-inspired Diceware multi-word passphrases with custom separators.
- Direct "Analyze in Analyzer" action.

### 📊 Security Insights & ⚙️ Settings
- Educational modules covering Gatekeeper rule pre-filtering (Slide 12), live constant-time `hmac.compare_digest` benchmark (Slide 11), CPython heap immutability (Slide 10), and Unicode keyspaces (Slide 7).
- Dedicated Settings screen for baseline length and character class policies with immediate engine updates.

---

## 5. Local Installation & Run Commands

### Prerequisites
- Python 3.10+ (Tested on Python 3.14)
- Git

### Setup Instructions

```bash
# 1. Clone or navigate to the project directory
cd C:\Users\ARSHITA\.gemini\antigravity-ide\scratch\enigma

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the automated test suite
python -m pytest tests/ -v

# 4. Launch the ENIGMA Workbench
streamlit run app.py
```

The interactive application will launch in your browser at `http://localhost:8501`.

---

## 6. Automated Test Suite Results

The test suite contains **42 comprehensive automated tests** validating every layer of defensive logic:

```bash
python -m pytest tests/ -v
```

```
tests/test_benchmark.py::test_linear_time_complexity_benchmark PASSED    [  2%]
tests/test_benchmark.py::test_generator_performance PASSED               [  4%]
tests/test_character_classes.py::test_single_class_only_fails_policy PASSED [  7%]
tests/test_character_classes.py::test_two_classes_fails_three_class_policy PASSED [  9%]
tests/test_character_classes.py::test_three_classes_satisfies_policy PASSED [ 11%]
tests/test_character_classes.py::test_four_classes_satisfies_policy PASSED [ 14%]
tests/test_character_classes.py::test_embedded_whitespace_handling PASSED [ 16%]
tests/test_engine.py::test_common_password_overrides_high_diversity PASSED [ 19%]
tests/test_engine.py::test_leetspeak_override_precedence PASSED          [ 21%]
tests/test_engine.py::test_keyboard_walk_override_precedence PASSED      [ 23%]
tests/test_engine.py::test_strong_random_password PASSED                 [ 26%]
tests/test_engine.py::test_nist_passphrase_exception PASSED              [ 28%]
tests/test_engine.py::test_recommendations_populated_coherently PASSED   [ 30%]
tests/test_engine.py::test_constant_time_comparison PASSED               [ 33%]
tests/test_length.py::test_empty_password_handling PASSED                [ 35%]
tests/test_length.py::test_none_password_handling PASSED                 [ 38%]
tests/test_length.py::test_sub_eight_characters_immediate_fail PASSED    [ 40%]
tests/test_length.py::test_eight_character_boundary PASSED               [ 42%]
tests/test_length.py::test_twelve_plus_character_progression PASSED      [ 45%]
tests/test_length.py::test_max_input_length_boundary_accepted PASSED     [ 47%]
tests/test_length.py::test_max_input_length_exceeded_raises_error PASSED [ 50%]
tests/test_patterns.py::test_repeated_characters_run PASSED              [ 52%]
tests/test_patterns.py::test_single_character_dominance PASSED           [ 54%]
tests/test_patterns.py::test_alphabetical_sequences PASSED               [ 57%]
tests/test_patterns.py::test_numerical_sequences PASSED                  [ 59%]
tests/test_patterns.py::test_repeated_chunks PASSED                      [ 61%]
tests/test_patterns.py::test_keyboard_walks_horizontal PASSED            [ 64%]
tests/test_patterns.py::test_keyboard_walks_diagonal PASSED              [ 66%]
tests/test_patterns.py::test_leetspeak_substitutions PASSED              [ 69%]
tests/test_patterns.py::test_common_password_dataset_lookup PASSED       [ 71%]
tests/test_patterns.py::test_calendar_year_detection PASSED              [ 73%]
tests/test_patterns.py::test_full_calendar_date_detection PASSED         [ 76%]
tests/test_privacy.py::test_redact_token_masks_content PASSED            [ 78%]
tests/test_privacy.py::test_findings_never_reveal_full_secret PASSED     [ 80%]
tests/test_privacy.py::test_verdict_trace_never_reveals_secret PASSED    [ 83%]
tests/test_privacy.py::test_oversized_input_error_does_not_leak_input_payload PASSED [ 85%]
tests/test_privacy.py::test_deterministic_reproducibility PASSED         [ 88%]
tests/test_unicode.py::test_unicode_code_point_counting PASSED           [ 90%]
tests/test_unicode.py::test_cyrillic_script_handling PASSED              [ 92%]
tests/test_unicode.py::test_emoji_code_point_measurement PASSED          [ 95%]
tests/test_unicode.py::test_unicode_combining_characters PASSED          [ 97%]
tests/test_unicode.py::test_passwords_are_not_silently_normalized PASSED [100%]

============================= 42 passed in 0.11s ==============================
```

---

## 7. Realistic Security Limitations

1. **Local Offline Scope:** Static dictionary matching checks against 4,200+ signatures. It cannot determine if a credential was exposed in an unindexed private data leak.
2. **Contextual & Personal Data:** Offline tools cannot detect personal identifiers (e.g., family names, pet names, employee IDs) unless structured like standard dates.
3. **RAM Memory Realities:** CPython string objects are immutable heap allocations. While ENIGMA minimizes variable retention and purges UI state, guaranteed zeroization (`memset_s`) is not possible in pure Python.
4. **Defense in Depth:** Password validation is only one layer of security. It does not replace multi-factor authentication (MFA), secure channel encryption (TLS), or proper rate limiting.

---

## 8. Professional Resume Summary

**ENIGMA — Explainable Password Risk Analysis Workbench (Python, Streamlit, Pytest)**
- Engineered a local-first password risk analysis workbench implementing an explainable rules engine, decoupling checkbox compliance from empirical risk.
- Developed linear-time ($O(n)$) pattern detection algorithms for spatial keyboard sweeps, alphabetical/numerical sequences, repetitive chunks, and leetspeak mutations with redacted diagnostic evidence.
- Implemented Unicode-aware code point parsing supporting 149k+ characters, international alphabets, and combining diacritics without silent string mutation.
- Built constant-time verification tooling (`hmac.compare_digest`) and an Argon2id gatekeeper pre-filter to demonstrate mitigations for timing side-channel attacks and KDF exhaustion.
- Authored a 42-test automated verification suite covering boundary conditions, privacy guarantees, STRIDE threat model invariants, and computational complexity benchmarks.
