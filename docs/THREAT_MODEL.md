# ENIGMA — Threat Model Document
**STRIDE Analysis & Security Boundary Specification**  
**DecodeLabs Industrial Training Kit 2026**

---

## 1. System Scope & Assets

ENIGMA is a local-first, explainable password risk analysis workbench.

### Primary Assets:
1. **Plaintext Candidate Password:** The sensitive credential entered by the user into the analysis console.
2. **Analysis Diagnostics & Findings:** Structural evidence, entropy calculations, and risk metrics.
3. **Local Common Password Dataset:** The local signature list used for offline matching.
4. **Host System Resources:** CPU and memory allocated to the Python analysis process.

---

## 2. Threat Actors & Capabilities

| Threat Actor | Access Level | Objectives | Assumed Capabilities |
| :--- | :--- | :--- | :--- |
| **Local Shoulder Surfer** | Physical visual access | Observe passwords typed into the UI console | Direct viewing of display screen |
| **Host-Level Malware / RAM Scraper** | Local OS unprivileged process | Harvest credentials lingering in application memory | Reads process virtual memory / heap space (e.g. BlackPOS style) |
| **Network Eavesdropper** | Local network / Wi-Fi | Intercept credentials transmitted in transit | Packet sniffing, man-in-the-middle on network adapters |
| **Malicious Input Submitter** | Web input console | Crash host server via catastrophic regex backtracking (ReDoS) | Sends crafted inputs up to megabytes in size |

---

## 3. Trust Boundaries

```
[ UNTRUSTED USER INPUT ]
           |
       (Boundary 1: Input Validation Boundary - Length Cap 512, Type Enforced)
           v
[ ENIGMA IN-MEMORY ANALYZER CORE (engine.py, patterns.py) ]
           |
       (Boundary 2: Diagnostic Output Boundary - Redacted Evidence)
           v
[ STREAMLIT WEB UI INTERFACE (app.py) ]
           |
       (Boundary 3: System Network Boundary - AIR-GAPPED: 0 Network Requests)
           x  [ EXTERNAL INTERNET / CLOUD SERVICES ] (BLOCKED)
```

---

## 4. STRIDE Threat Analysis Matrix

### 1. Spoofing
- **Threat:** Malicious package masquerades as ENIGMA or redirects validation to an external malicious server to steal credentials.
- **Mitigation:** Zero external runtime dependencies beyond pinned Streamlit and Pytest. Analysis runs strictly in-process with no remote endpoints.

### 2. Tampering
- **Threat:** Attacker tampers with the local common password dataset to whitelist weak credentials.
- **Mitigation:** Bundled local dataset loaded into an immutable `frozenset` at process initialization.

### 3. Repudiation
- **Threat:** User or system auditor disputes how a specific password was classified.
- **Mitigation:** ENIGMA produces a deterministic, step-by-step **Verdict Trace** ("Decode the Verdict") detailing every rule evaluated, its impact, and its outcome.

### 4. Information Disclosure
- **Threat 4A (Display Leakage):** Plaintext password is visible to bystanders.
  - *Mitigation:* Password masking toggle is enabled by default in the UI.
- **Threat 4B (Diagnostic Leakage):** Error logs, exception tracebacks, or findings cards print the full secret.
  - *Mitigation:* The `_redact_token()` utility masks sensitive substrings with ellipses (e.g. `'qwe...'`). Tests verify that raw credentials are never echoed in findings or error messages.
- **Threat 4C (Network Leakage):** Password is sent over HTTP to an external API.
  - *Mitigation:* No HTTP requests exist in the application codebase. 100% offline analysis.

### 5. Denial of Service (DoS / ReDoS)
- **Threat:** Attacker submits a 10MB string or specially crafted repetitive sequence causing polynomial regular expression backtracking (ReDoS) or memory exhaustion.
- **Mitigation:** Hard cap at 512 Unicode code points enforced before any pattern scanning occurs. All sequence detectors use linear-time pointer scans ($O(n)$) without nested quantifiers.

### 6. Elevation of Privilege
- **Threat:** Arbitrary code execution achieved through string evaluation (`eval()`, `exec()`, template injection).
- **Mitigation:** Inputs are strictly typed as Python `str` objects and subjected to safe string comparisons. No dynamic code interpretation or shell execution.

---

## 5. Residual Risks & Accepted Realities

1. **CPython Memory Immutability:** Python `str` objects are immutable heap allocations. When an input is cleared in the UI, Python rebinds the variable, but the original memory buffer lingers on the heap until CPython garbage collection and OS memory compaction occur. True memory zeroization is acknowledged as technically impossible in standard pure Python.
2. **Offline Breach Data Gaps:** ENIGMA matches against a curated list of 4,200+ known weak passwords. It cannot know if a newly created password was compromised in an unreleased breach.
3. **Targeted Social Engineering:** ENIGMA cannot determine if an apparently random string corresponds to a user's spouse name, pet name, or childhood address unless structured like standard calendar years.
