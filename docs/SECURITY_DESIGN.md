# ENIGMA — Security Design Document
**Explainable Password Risk Analysis Workbench**  
**DecodeLabs Industrial Training Kit 2026 | Project 1: Password Strength Checker**

---

## 1. System Overview & Core Philosophy

Conventional password checkers rely on simplistic scoring algorithms: they award points for uppercase letters, digits, and special symbols, and sum them up into a score. This design creates a severe security flaw: a password like `P@ssw0rd1!` earns full points for having 4 character classes and 10 characters, despite being trivial for dictionary attacks and rule-based mutation engines (like Hashcat's `best64.rule`).

**ENIGMA** is engineered as an **Explainable Password Risk Analysis Workbench**. Its core philosophy is:
> *"Decode the pattern. Reveal the risk. Protect the secret."*

ENIGMA decouples **Organizational Policy Compliance** from **True Risk Assessment** and introduces a deterministic **Precedence Arbitration Rules Engine** that cannot be tricked by superficial character swaps.

```
+-----------------------------------------------------------------------------------+
|                              INPUT: Raw String                                    |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|               STAGE 1: Input Validation & Unicode Ingestion                       |
|   - Bounded length check (<= 512 code points) to prevent ReDoS / DoS               |
|   - Unicode code point measurement (not raw bytes)                                |
|   - Normalization inspection (NFC vs NFD) without silent mutation                 |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|               STAGE 2: Character Composition & Policy Check                       |
|   - DecodeLabs Baseline: 8+ characters, >= 3 character classes                     |
|   - Unicode category classification (Lu, Ll, Nd, P*, S*, M*)                      |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|               STAGE 3: Predictable Pattern & Dictionary Scan                      |
|   - O(1) set lookup in local 4,200+ common weak credentials dataset               |
|   - Linear scan: repeated runs (aaaa), dominance (>50%), chunks (abcabc)          |
|   - Spatial keyboard walks: QWERTY rows, reverse rows, diagonals (1qaz)           |
|   - Leetspeak translation: de-leeting root word against weak dictionary           |
|   - Date & calendar year masks (1940-2035)                                        |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|               STAGE 4: Precedence Rules Arbitration Engine                        |
|   - Rule 1: Common Password Match -> FORCED WEAK                                  |
|   - Rule 2: Sub-8 Character Floor -> FORCED WEAK                                  |
|   - Rule 3: Severe Predictability Pattern -> FORCED WEAK                          |
|   - Rule 4: NIST SP 800-63B Passphrase Exception -> QUALIFIED STRONG (>= 18 chars)|
|   - Rule 5: Moderate Pattern / Policy Balance -> MEDIUM                           |
|   - Rule 6: High Entropy & Clean Scan -> STRONG                                   |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|           STAGE 5: Output Generation & "Decode the Verdict"                       |
|   - Risk Classification (Weak / Medium / Strong)                                  |
|   - Step-by-Step Verdict Audit Trace                                              |
|   - Redacted Evidence Findings (Zero Secret Exposure)                             |
|   - Context-Aware Prioritized Remediation Plan                                    |
+-----------------------------------------------------------------------------------+
```

---

## 2. DecodeLabs Curriculum Themes Implemented

### Theme A: Unicode Architecture (Slide 7)
Standard ASCII covers 95 printable characters (codes 32 to 126). Unicode expands this keyspace to over **149,000 code points** spanning 161 scripts.
- **Code Point Counting:** Python 3 strings are sequences of Unicode code points. ENIGMA measures `len(password)` in code points, not UTF-8 bytes. For example, the 4-byte emoji `🔐` is accurately counted as 1 code point, not 4 characters.
- **Character Classification:** Rather than relying on simple ASCII regexes (`[a-zA-Z]`), ENIGMA uses `unicodedata.category(c)` to support international alphabets (such as Cyrillic `Пароль`, Arabic, Kanji).
- **Normalization Integrity:** A character like `é` can exist in composed form (NFC: `U+00E9`) or decomposed form (NFD: `e` + `U+0301`). ENIGMA detects normalization differences and alerts the user without silently mutating the original input.

### Theme B: Linear-Time Efficiency & IPO Model (Slide 8 & 9)
- **Constraint:** Analysis time must grow linearly ($O(n)$) with password length, avoiding polynomial ($O(n^2)$) or exponential explosions that enable ReDoS (Regular Expression Denial of Service).
- **Pythonic Elegance:** Detectors employ C-optimized built-ins, single-pass generator expressions, and short-circuit evaluation (`any(c.isdigit() for c in s)`).
- **Benchmark Evidence:** Automated benchmarks confirm that analyzing 512 code points executes in under 2 milliseconds on standard hardware, scaling linearly from 16 to 512 characters.

### Theme C: RAM Security & Heap Lifetime (Slide 10 — HINNOP Trap)
- **Malware RAM Scraping:** Attackers scrape volatile system RAM (e.g., POS malware like BlackPOS) searching for plaintext credentials stored in process memory.
- **The Immutability Trap:** In CPython, `str` objects are immutable heap allocations (`PyASCIIObject` or `PyCompactUnicodeObject`). Clearing a variable in the UI or overwriting a reference does not zeroize the underlying memory buffer.
- **Truthful Documentation:** ENIGMA provides a UI purge action and avoids session-state caching, but explicitly documents the residual risk: guaranteed zeroization cannot be achieved in pure Python without native C bindings (`memset_s`).

### Theme D: Timing Attacks & Constant-Time Verification (Slide 11)
- **The Attack Vector:** Standard string equality (`==`) compares bytes sequentially and exits on the first mismatch. An attacker measuring microsecond delays can deduce passwords or API tokens character-by-character.
- **Defensive Primitive:** For comparing authentication tokens or cryptographic hashes, ENIGMA demonstrates `hmac.compare_digest(a, b)`, which executes in constant time via OpenSSL's `CRYPTO_memcmp`.
- **Architectural Boundary:** ENIGMA clarifies that password *strength analysis* (validating an untrusted input against public policies) does not require constant-time equality, but secret *hash verification* during authentication strictly does.

### Theme E: The Gatekeeper Rule (Slide 12)
- **Principle:** *"You cannot hash what is weak. Filter entropy before Argon2id."*
- Password hashing functions (Argon2id, PBKDF2, bcrypt) are computationally expensive by design.
- The Gatekeeper acts as a pre-filter at registration or password change: if a password is weak, common, or below policy thresholds, the system halts immediately, saving server GPU/CPU cycles and preventing weak hashes from entering authentication databases.

---

## 3. Decision Precedence Rules Engine

| Precedence Rank | Rule Identifier | Trigger Condition | Resulting Risk Level | Security Rationale |
| :--- | :--- | :--- | :--- | :--- |
| **Rank 1 (Highest)** | `PRECEDENCE_RULE_1` | Matches local offline common password database | **WEAK** (Forced) | Known weak passwords are breached and indexed in attacker dictionaries. |
| **Rank 2** | `PRECEDENCE_RULE_2` | Length < 8 code points | **WEAK** (Forced) | Search space ($R^L$) is too small; GPU brute-force can exhaust keyspace in minutes. |
| **Rank 3** | `PRECEDENCE_RULE_3` | Severe predictability pattern (leetspeak weak base, long keyboard walk >=5, repeat dominance >=50%) | **WEAK** (Forced) | Structural predictability invalidates cosmetic character variety. |
| **Rank 4** | `PRECEDENCE_RULE_4A` | Length >= 18 code points, zero detected patterns | **STRONG** (Qualified) | NIST SP 800-63B passphrase qualification: sheer length provides massive keyspace (>100 bits) without artificial symbols. |
| **Rank 5** | `PRECEDENCE_RULE_4B` | Length 8–11 chars, moderate pattern (sequence, year append), or fails diversity policy | **MEDIUM** | Baseline acceptable for low-risk systems, but vulnerable to targeted mask attacks. |
| **Rank 6** | `PRECEDENCE_RULE_5` | Length >= 12, satisfies all 3+ policy classes, zero pattern findings | **STRONG** | High entropy and unpredictability across all dimensions. |

---

## 4. Privacy by Design

1. **Local-First Execution:** ENIGMA operates entirely within the user's local Python process. It performs zero external network calls, transmits no telemetry, and uses no external AI APIs.
2. **Offline Dataset:** The 4,200+ weak password dataset is bundled locally in `data/common_passwords.txt`.
3. **Safe Redacted Evidence:** Diagnostic findings and error messages redact the candidate credential. Evidence strings show only token previews (e.g. `'qwe...'`) and offsets, never exposing the plaintext secret.
4. **DoS Protection:** Inputs are capped at 512 code points to ensure bounded memory usage and prevent ReDoS vulnerabilities.
