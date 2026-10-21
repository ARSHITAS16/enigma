"""
ENIGMA — Explainable Password Risk Analysis Workbench
Xbox PC App-Inspired UI/UX Redesign
DecodeLabs Industrial Training Kit 2026 | Project 1: Password Strength Checker

Tagline: "Decode the pattern. Reveal the risk. Protect the secret."
Local-first, deterministic, explainable cybersecurity workbench.
"""

from __future__ import annotations

import streamlit as st
import unicodedata
from analyzer import (
    PasswordAnalyzer,
    RiskLevel,
    Severity,
    is_common_password,
    generate_random_password,
    generate_passphrase,
    get_dataset_size,
)

# Page configuration
st.set_page_config(
    page_title="ENIGMA | Password Security Workbench",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ------------------------------------------------------------------------------
# XBOX PC APP-INSPIRED DESIGN SYSTEM & CSS
# ------------------------------------------------------------------------------
XBOX_THEME_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Segoe+UI:wght@400;600;700&family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;600;700&display=swap');

:root {
    --bg-main: #101210;
    --bg-sidebar: #191C19;
    --bg-card: #202420;
    --bg-card-hover: #262B26;
    --bg-card-secondary: #161916;
    --border-color: #343A34;
    --border-subtle: #2A302A;
    --xbox-green: #80CC14;
    --xbox-green-hover: #9BE622;
    --xbox-green-dim: rgba(128, 204, 20, 0.12);
    --text-primary: #F4F6F2;
    --text-secondary: #A5ADA3;
    --text-muted: #6E766D;
    --weak-red: #EF4444;
    --weak-red-dim: rgba(239, 68, 68, 0.12);
    --medium-amber: #F59E0B;
    --medium-amber-dim: rgba(245, 158, 11, 0.12);
    --strong-green: #80CC14;
    --strong-green-dim: rgba(128, 204, 20, 0.12);
    --card-radius: 10px;
    --btn-radius: 6px;
}

/* Global Application Background */
body, .stApp {
    background-color: var(--bg-main) !important;
    color: var(--text-primary) !important;
    font-family: 'Segoe UI', 'Inter', -apple-system, sans-serif !important;
}

code, pre, .mono {
    font-family: 'JetBrains Mono', monospace !important;
}

/* Sidebar Styling */
section[data-testid="stSidebar"] {
    background-color: var(--bg-sidebar) !important;
    border-right: 1px solid var(--border-color) !important;
}

section[data-testid="stSidebar"] div[data-testid="stRadio"] > div {
    gap: 4px;
}

section[data-testid="stSidebar"] div[data-testid="stRadio"] label {
    background-color: transparent;
    padding: 10px 14px;
    border-radius: var(--btn-radius);
    color: var(--text-secondary);
    font-size: 0.92rem;
    font-weight: 500;
    transition: all 0.15s ease;
    border-left: 3px solid transparent;
    margin-bottom: 2px;
}

section[data-testid="stSidebar"] div[data-testid="stRadio"] label:hover {
    background-color: #202420;
    color: var(--text-primary);
}

section[data-testid="stSidebar"] div[data-testid="stRadio"] label[data-checked="true"],
section[data-testid="stSidebar"] div[data-testid="stRadio"] label:has(input:checked) {
    background-color: #242924 !important;
    color: #FFFFFF !important;
    border-left: 3px solid var(--xbox-green) !important;
    font-weight: 600 !important;
}

/* Rounded Cards */
.xbox-card {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--card-radius);
    padding: 22px;
    margin-bottom: 16px;
    transition: border-color 0.2s ease, transform 0.2s ease;
}

.xbox-card:hover {
    border-color: #444C44;
}

.xbox-card-interactive:hover {
    border-color: var(--xbox-green);
    background: var(--bg-card-hover);
}

.xbox-card-header {
    font-size: 1.05rem;
    font-weight: 700;
    color: var(--text-primary);
    margin-bottom: 14px;
    display: flex;
    align-items: center;
    gap: 8px;
    border-bottom: 1px solid var(--border-subtle);
    padding-bottom: 8px;
    letter-spacing: -0.01em;
}

/* Featured Hero Banner (Xbox Home Style) */
.xbox-hero-banner {
    background: linear-gradient(135deg, #1C221C 0%, #151815 100%);
    border: 1px solid var(--border-color);
    border-left: 4px solid var(--xbox-green);
    border-radius: var(--card-radius);
    padding: 28px;
    margin-bottom: 24px;
}

.xbox-hero-title {
    font-size: 1.8rem;
    font-weight: 800;
    color: var(--text-primary);
    margin: 0 0 8px 0;
    letter-spacing: -0.02em;
}

.xbox-hero-desc {
    font-size: 0.98rem;
    color: var(--text-secondary);
    margin-bottom: 18px;
    max-width: 650px;
    line-height: 1.5;
}

/* Feature Game-Library Tile Card */
.xbox-tile {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--card-radius);
    padding: 20px;
    height: 100%;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    transition: all 0.2s ease;
}

.xbox-tile:hover {
    border-color: var(--xbox-green);
    transform: translateY(-2px);
    box-shadow: 0 6px 18px rgba(0, 0, 0, 0.35);
}

.xbox-tile-icon {
    font-size: 1.8rem;
    margin-bottom: 12px;
}

.xbox-tile-title {
    font-size: 1.15rem;
    font-weight: 700;
    color: var(--text-primary);
    margin-bottom: 6px;
}

.xbox-tile-desc {
    font-size: 0.88rem;
    color: var(--text-secondary);
    line-height: 1.45;
    margin-bottom: 16px;
}

/* Buttons */
.stButton > button {
    border-radius: var(--btn-radius) !important;
    font-weight: 600 !important;
    font-size: 0.92rem !important;
    padding: 8px 18px !important;
    transition: all 0.15s ease !important;
    border: 1px solid var(--border-color) !important;
    background-color: var(--bg-card) !important;
    color: var(--text-primary) !important;
}

.stButton > button:hover {
    border-color: var(--xbox-green) !important;
    color: #FFFFFF !important;
}

/* Primary Xbox Green Button Class helper */
div[data-testid="stButton"]:has(button[kind="primary"]) > button,
button.xbox-primary-btn {
    background-color: var(--xbox-green) !important;
    color: #101210 !important;
    border: none !important;
    font-weight: 700 !important;
}

div[data-testid="stButton"]:has(button[kind="primary"]) > button:hover,
button.xbox-primary-btn:hover {
    background-color: var(--xbox-green-hover) !important;
    box-shadow: 0 0 14px rgba(128, 204, 20, 0.35) !important;
}

/* Text Inputs */
div[data-testid="stTextInput"] input {
    background-color: #161916 !important;
    border: 1px solid var(--border-color) !important;
    border-radius: var(--btn-radius) !important;
    color: var(--text-primary) !important;
    font-size: 1rem !important;
    padding: 10px 14px !important;
}

div[data-testid="stTextInput"] input:focus {
    border-color: var(--xbox-green) !important;
    box-shadow: 0 0 0 1px var(--xbox-green) !important;
}

/* Status Badges */
.xbox-badge {
    display: inline-block;
    padding: 4px 12px;
    border-radius: 9999px;
    font-size: 0.78rem;
    font-weight: 700;
    letter-spacing: 0.04em;
    text-transform: uppercase;
}

.xbox-badge-weak {
    background-color: var(--weak-red-dim);
    color: var(--weak-red);
    border: 1px solid var(--weak-red);
}

.xbox-badge-medium {
    background-color: var(--medium-amber-dim);
    color: var(--medium-amber);
    border: 1px solid var(--medium-amber);
}

.xbox-badge-strong {
    background-color: var(--strong-green-dim);
    color: var(--strong-green);
    border: 1px solid var(--strong-green);
}

.xbox-badge-neutral {
    background-color: rgba(165, 173, 163, 0.12);
    color: var(--text-secondary);
    border: 1px solid #343A34;
}

/* Horizontal Strength Meter (Segmented) */
.meter-container {
    background: #161916;
    border-radius: 6px;
    height: 10px;
    width: 100%;
    display: flex;
    gap: 4px;
    margin: 14px 0;
    overflow: hidden;
}

.meter-segment {
    flex: 1;
    height: 100%;
    background: #2A302A;
    border-radius: 2px;
    transition: background 0.3s ease;
}

.meter-weak { background: var(--weak-red) !important; }
.meter-medium { background: var(--medium-amber) !important; }
.meter-strong { background: var(--strong-green) !important; }

/* Verdict Display Card */
.verdict-box {
    background: #171B17;
    border-radius: var(--card-radius);
    padding: 22px;
    border: 1px solid var(--border-color);
    margin-bottom: 18px;
}

.verdict-weak-border { border-left: 4px solid var(--weak-red); }
.verdict-medium-border { border-left: 4px solid var(--medium-amber); }
.verdict-strong-border { border-left: 4px solid var(--strong-green); }

/* Metric Box */
.xbox-metric-box {
    background: #171B17;
    border: 1px solid var(--border-color);
    border-radius: var(--card-radius);
    padding: 14px;
    text-align: center;
}

.xbox-metric-val {
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.7rem;
    font-weight: 700;
    color: var(--text-primary);
}

.xbox-metric-val-accent {
    color: var(--xbox-green);
}

.xbox-metric-label {
    font-size: 0.76rem;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-top: 4px;
}

/* Step Pipeline Card (Decode the Verdict) */
.xbox-trace-step {
    background: #161916;
    border-left: 3px solid #343A34;
    border-radius: 0 6px 6px 0;
    padding: 12px 16px;
    margin-bottom: 8px;
}

.xbox-trace-title {
    font-weight: 600;
    color: var(--text-primary);
    font-size: 0.92rem;
    display: flex;
    justify-content: space-between;
}

.xbox-trace-reason {
    font-size: 0.85rem;
    color: var(--text-secondary);
    margin-top: 4px;
    line-height: 1.4;
}

/* Safe Redacted Evidence Tag */
.xbox-evidence-tag {
    background: #101210;
    border: 1px solid var(--border-color);
    padding: 3px 8px;
    border-radius: 4px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.82rem;
    color: var(--text-primary);
    display: inline-block;
    margin-top: 6px;
}
</style>
"""
st.markdown(XBOX_THEME_CSS, unsafe_allow_html=True)

# ------------------------------------------------------------------------------
# SESSION STATE INITIALIZATION
# ------------------------------------------------------------------------------
if "nav_choice" not in st.session_state:
    st.session_state.nav_choice = "🏠 Home"
if "analyzer_pwd_input" not in st.session_state:
    st.session_state.analyzer_pwd_input = ""
if "analyzed_result" not in st.session_state:
    st.session_state.analyzed_result = None
if "clear_message" not in st.session_state:
    st.session_state.clear_message = False
if "slider_min_length" not in st.session_state:
    st.session_state.slider_min_length = 8
if "slider_min_classes" not in st.session_state:
    st.session_state.slider_min_classes = 3
if "min_length_policy" not in st.session_state:
    st.session_state.min_length_policy = 8
if "min_classes_policy" not in st.session_state:
    st.session_state.min_classes_policy = 3
if "mask_password" not in st.session_state:
    st.session_state.mask_password = True
if "generated_credential" not in st.session_state:
    st.session_state.generated_credential = ""

# Helper callback for resetting input
def handle_clear_input():
    st.session_state.analyzer_pwd_input = ""
    st.session_state.analyzed_result = None
    st.session_state.clear_message = True

# Helper callbacks for page navigation and cross-page inspection
def set_nav_choice(choice: str):
    st.session_state.nav_choice = choice

def inspect_password_in_analyzer(pwd: str):
    st.session_state.analyzer_pwd_input = pwd
    active_analyzer = PasswordAnalyzer(
        min_length_policy=st.session_state.min_length_policy,
        min_classes_policy=st.session_state.min_classes_policy,
    )
    st.session_state.analyzed_result = active_analyzer.analyze(pwd)
    st.session_state.nav_choice = "🔍 Password Analyzer"

def analyze_generated_credential():
    cred = st.session_state.get("generated_credential", "")
    if cred:
        st.session_state.analyzer_pwd_input = cred
        active_analyzer = PasswordAnalyzer(
            min_length_policy=st.session_state.min_length_policy,
            min_classes_policy=st.session_state.min_classes_policy,
        )
        st.session_state.analyzed_result = active_analyzer.analyze(cred)
        st.session_state.nav_choice = "🔍 Password Analyzer"

def clear_generated_credential():
    st.session_state.generated_credential = ""

# Helper callbacks for settings
def on_policy_slider_change():
    st.session_state.min_length_policy = st.session_state.slider_min_length
    st.session_state.min_classes_policy = st.session_state.slider_min_classes
    if st.session_state.analyzer_pwd_input and st.session_state.analyzed_result is not None:
        updated_analyzer = PasswordAnalyzer(
            min_length_policy=st.session_state.min_length_policy,
            min_classes_policy=st.session_state.min_classes_policy
        )
        st.session_state.analyzed_result = updated_analyzer.analyze(st.session_state.analyzer_pwd_input)

def reset_policy_defaults():
    st.session_state.slider_min_length = 8
    st.session_state.slider_min_classes = 3
    st.session_state.min_length_policy = 8
    st.session_state.min_classes_policy = 3
    if st.session_state.analyzer_pwd_input and st.session_state.analyzed_result is not None:
        default_analyzer = PasswordAnalyzer(min_length_policy=8, min_classes_policy=3)
        st.session_state.analyzed_result = default_analyzer.analyze(st.session_state.analyzer_pwd_input)
    st.toast("Reset to DecodeLabs defaults (8 chars, 3 classes)!", icon="✅")

# Active Analyzer Engine configured with current policy settings
analyzer = PasswordAnalyzer(
    min_length_policy=st.session_state.min_length_policy,
    min_classes_policy=st.session_state.min_classes_policy
)

# ------------------------------------------------------------------------------
# SIDEBAR: COMPACT, QUIET XBOX-STYLE VERTICAL NAVIGATION (5 ITEMS)
# ------------------------------------------------------------------------------
with st.sidebar:
    # Brand & Wordmark
    st.markdown(
        """
        <div style="padding: 10px 4px 18px 4px;">
            <div style="display:flex; align-items:center; gap:10px;">
                <span style="font-size: 1.6rem;">🛡️</span>
                <div>
                    <div style="font-size: 1.3rem; font-weight: 800; letter-spacing: 0.04em; color: #F4F6F2; line-height: 1.1;">
                        ENIGMA
                    </div>
                    <div style="font-size: 0.72rem; color: #80CC14; font-weight: 600; letter-spacing: 0.05em; text-transform: uppercase;">
                        Password Security Workbench
                    </div>
                </div>
            </div>
            <div style="font-size: 0.78rem; color: #6E766D; margin-top: 6px; font-style: italic;">
                "Decode the pattern. Reveal the risk. Protect the secret."
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown("<div style='height: 1px; background: #343A34; margin-bottom: 16px;'></div>", unsafe_allow_html=True)

    # 5 Clean Navigation Menu Items (Security Insights removed per user request)
    nav_options = [
        "🏠 Home",
        "🔍 Password Analyzer",
        "🎮 Pattern Lab",
        "⚡ Secure Generator",
        "⚙️ Settings",
    ]

    # Ensure nav_choice is valid
    if st.session_state.nav_choice not in nav_options:
        st.session_state.nav_choice = "🏠 Home"

    # Radio is directly bound to st.session_state.nav_choice
    st.radio(
        "Navigation",
        options=nav_options,
        key="nav_choice",
        label_visibility="collapsed"
    )

    st.markdown("<div style='flex-grow: 1;'></div>", unsafe_allow_html=True)
    st.markdown("<div style='height: 80px;'></div>", unsafe_allow_html=True)

    # Quiet Sidebar Footer
    st.markdown("<div style='height: 1px; background: #2A302A; margin-bottom: 12px;'></div>", unsafe_allow_html=True)
    st.markdown(
        """
        <div style="padding: 4px; font-size: 0.75rem; color: #6E766D; line-height: 1.5;">
            <div style="color: #A5ADA3; font-weight: 600;">Cybersecurity Internship Project 01</div>
            <div>DecodeLabs Industrial Kit 2026</div>
            <div style="color: #80CC14; margin-top: 4px;">● 100% Local-First Engine</div>
        </div>
        """,
        unsafe_allow_html=True
    )


# ==============================================================================
# SCREEN 1: HOME DASHBOARD
# ==============================================================================
if st.session_state.nav_choice == "🏠 Home":
    # Header Greeting
    st.markdown(
        """
        <div style="margin-bottom: 22px;">
            <h1 style="font-size: 2.1rem; font-weight: 800; color: #F4F6F2; margin: 0 0 6px 0; letter-spacing: -0.02em;">
                Welcome to ENIGMA
            </h1>
            <div style="font-size: 1.05rem; color: #A5ADA3;">
                Understand your password. Discover its weaknesses. Strengthen your security.
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Featured Hero Panel: PASSWORD SECURITY CENTER
    with st.container():
        st.markdown(
            """
            <div class="xbox-hero-banner">
                <div style="display:flex; justify-content:space-between; align-items:flex-start;">
                    <div>
                        <div style="font-size: 0.8rem; font-weight: 700; color: #80CC14; letter-spacing: 0.08em; text-transform: uppercase; margin-bottom: 4px;">
                            FEATURED TOOL
                        </div>
                        <div class="xbox-hero-title">PASSWORD SECURITY CENTER</div>
                        <div class="xbox-hero-desc">
                            Analyze password patterns and understand your security risks. Evaluate character composition, 
                            detect predictable keyboard walks and leetspeak substitutions, and inspect explainable rule traces.
                        </div>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        col_hero_btn, col_hero_status = st.columns([1, 2])
        with col_hero_btn:
            st.button(
                "Analyze a Password",
                type="primary",
                use_container_width=True,
                key="home_btn_analyze_hero",
                on_click=set_nav_choice,
                args=("🔍 Password Analyzer",)
            )
        with col_hero_status:
            st.markdown(
                """
                <div style="display:flex; gap:12px; align-items:center; height:100%; font-size:0.84rem; color:#A5ADA3;">
                    <span>🛡️ <b>4,200+</b> Offline Signatures</span>
                    <span>•</span>
                    <span>🔒 <b>Zero</b> Network Egress</span>
                    <span>•</span>
                    <span>⚡ <b>O(n)</b> Linear Engine</span>
                </div>
                """,
                unsafe_allow_html=True
            )

    st.markdown("<div style='height: 18px;'></div>", unsafe_allow_html=True)
    st.markdown("### Featured Tools")

    # Grid of Three Feature Cards (Game-Tile Style)
    c1, c2, c3 = st.columns(3)

    with c1:
        st.markdown(
            """
            <div class="xbox-tile">
                <div>
                    <div class="xbox-tile-icon">🔍</div>
                    <div class="xbox-tile-title">Password Analyzer</div>
                    <div class="xbox-tile-desc">
                        Examine password strength, predictable patterns, character classes, and actionable security recommendations.
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
        st.button(
            "Open Analyzer →",
            key="home_btn_analyzer",
            use_container_width=True,
            on_click=set_nav_choice,
            args=("🔍 Password Analyzer",)
        )

    with c2:
        st.markdown(
            """
            <div class="xbox-tile">
                <div>
                    <div class="xbox-tile-icon">🎮</div>
                    <div class="xbox-tile-title">Pattern Lab</div>
                    <div class="xbox-tile-desc">
                        Explore synthetic examples and discover why predictable passwords (like leetspeak or keyboard sweeps) are risky.
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
        st.button(
            "Explore Patterns →",
            key="home_btn_patterns",
            use_container_width=True,
            on_click=set_nav_choice,
            args=("🎮 Pattern Lab",)
        )

    with c3:
        st.markdown(
            """
            <div class="xbox-tile">
                <div>
                    <div class="xbox-tile-icon">⚡</div>
                    <div class="xbox-tile-title">Secure Generator</div>
                    <div class="xbox-tile-desc">
                        Generate strong random passwords and memorable multi-word passphrases locally using Python's secrets module.
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
        st.button(
            "Open Generator →",
            key="home_btn_gen",
            use_container_width=True,
            on_click=set_nav_choice,
            args=("⚡ Secure Generator",)
        )

    st.markdown("<div style='height: 24px;'></div>", unsafe_allow_html=True)

    # Educational Footer Card
    st.markdown(
        """
        <div class="xbox-card" style="border-left: 3px solid #343A34;">
            <div style="font-weight: 600; color: #F4F6F2; margin-bottom: 4px;">
                Defensive Security Principle
            </div>
            <div style="font-size: 0.88rem; color: #A5ADA3; line-height: 1.5;">
                Cosmetic complexity (e.g. <code>P@ssw0rd1!</code>) does not equal unpredictability. 
                ENIGMA decouples legacy character-class compliance from true risk assessment, 
                guaranteeing that structural predictability is revealed rather than masked.
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )


# ==============================================================================
# SCREEN 2: PASSWORD ANALYZER (THE CENTERPIECE)
# ==============================================================================
elif st.session_state.nav_choice == "🔍 Password Analyzer":
    st.markdown(
        """
        <div style="margin-bottom: 18px;">
            <h1 style="font-size: 1.9rem; font-weight: 800; color: #F4F6F2; margin: 0 0 4px 0; letter-spacing: -0.02em;">
                PASSWORD ANALYZER
            </h1>
            <div style="font-size: 0.98rem; color: #A5ADA3;">
                Check a password's strength and understand the risks.
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Central Analysis Card
    with st.container():
        st.markdown(
            """
            <div class="xbox-card" style="padding-bottom: 16px;">
                <div class="xbox-card-header">
                    <span>🔐 Candidate Input Console</span>
                </div>
            """,
            unsafe_allow_html=True
        )

        col_input_box, col_toggle = st.columns([5, 1])
        with col_toggle:
            mask_active = st.checkbox("Mask input", value=st.session_state.mask_password, key="mask_check")
            st.session_state.mask_password = mask_active

        with col_input_box:
            input_type = "password" if mask_active else "default"
            # Single source of truth: widget key bound directly to st.session_state.analyzer_pwd_input
            st.text_input(
                "Enter Candidate Password:",
                type=input_type,
                placeholder="Type or paste a candidate credential to inspect...",
                label_visibility="collapsed",
                key="analyzer_pwd_input"
            )

        # Action Buttons Row
        col_btn_analyze, col_btn_clear, col_btn_spacer = st.columns([2, 1, 4])
        with col_btn_analyze:
            analyze_clicked = st.button("Analyze Password", type="primary", use_container_width=True, key="btn_run_analysis")
        with col_btn_clear:
            st.button("Clear", use_container_width=True, on_click=handle_clear_input, key="btn_clear_input")

        # Privacy Note
        st.markdown(
            """
            <div style="font-size: 0.8rem; color: #6E766D; margin-top: 12px; display:flex; align-items:center; gap:6px;">
                <span>🔒</span>
                <span><b>100% Local-First Privacy:</b> Evaluated in-process. Zero network egress. Passwords are never logged, stored, or cached.</span>
            </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    # Notice when user cleared input
    if st.session_state.clear_message:
        st.info(
            "ℹ️ **Memory Lifetime Note (Slide 10):** Input purged from UI state. "
            "Because Python strings are immutable heap allocations, memory buffers linger until CPython garbage collection occurs."
        )
        st.session_state.clear_message = False

    # Execute analysis if user clicked Analyze button
    if analyze_clicked and st.session_state.analyzer_pwd_input:
        try:
            st.session_state.analyzed_result = analyzer.analyze(st.session_state.analyzer_pwd_input)
        except ValueError as err:
            st.error(f"Validation Error: {str(err)}")
            st.session_state.analyzed_result = None

    result = st.session_state.analyzed_result

    # Result Rendering
    if result is None:
        # Empty State
        st.markdown(
            """
            <div class="xbox-card" style="text-align: center; padding: 42px 20px; color: #A5ADA3;">
                <div style="font-size: 2.4rem; margin-bottom: 8px;">🛡️</div>
                <div style="font-size: 1.2rem; font-weight: 700; color: #F4F6F2; margin-bottom: 4px;">Ready to analyze</div>
                <div style="font-size: 0.92rem; max-width: 480px; margin: 0 auto;">
                    Enter a synthetic test password or your chosen candidate to inspect its risk profile and explainable decision chain.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
    else:
        # 1. Executive Verdict Card
        verdict_val = result.risk_level.value
        border_cls = f"verdict-{verdict_val.lower()}-border"
        badge_cls = f"xbox-badge-{verdict_val.lower()}"
        pol_badge_cls = "xbox-badge-strong" if result.policy_result.compliant else "xbox-badge-weak"
        pol_text = "POLICY COMPLIANT" if result.policy_result.compliant else "POLICY NON-COMPLIANT"

        st.markdown(
            f"""
            <div class="verdict-box {border_cls}">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 8px;">
                    <div style="display:flex; gap:10px; align-items:center;">
                        <span class="xbox-badge {badge_cls}">VERDICT: {verdict_val}</span>
                        <span class="xbox-badge {pol_badge_cls}">{pol_text}</span>
                    </div>
                    <span style="font-size:0.8rem; color:#A5ADA3;">DecodeLabs Project 01</span>
                </div>
                <div style="font-size: 1.8rem; font-weight: 800; color: #F4F6F2; margin-bottom: 4px;">
                    {verdict_val} PASSWORD
                </div>
                <div style="font-size: 0.95rem; color: #A5ADA3;">
                    {result.policy_result.summary_message}
                </div>
            """,
            unsafe_allow_html=True
        )

        # Horizontal Strength Meter
        m_s1 = "meter-weak" if verdict_val in ("WEAK", "MEDIUM", "STRONG") else ""
        m_s2 = "meter-medium" if verdict_val in ("MEDIUM", "STRONG") else ""
        m_s3 = "meter-strong" if verdict_val == "STRONG" else ""

        st.markdown(
            f"""
                <div class="meter-container">
                    <div class="meter-segment {m_s1}"></div>
                    <div class="meter-segment {m_s2}"></div>
                    <div class="meter-segment {m_s3}"></div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        # 2. Key Metrics Row
        m1, m2, m3, m4 = st.columns(4)
        with m1:
            st.markdown(
                f"""
                <div class="xbox-metric-box">
                    <div class="xbox-metric-val">{result.metrics.length}</div>
                    <div class="xbox-metric-label">Code Point Length</div>
                </div>
                """,
                unsafe_allow_html=True
            )
        with m2:
            st.markdown(
                f"""
                <div class="xbox-metric-box">
                    <div class="xbox-metric-val">{result.policy_result.classes_satisfied}/4</div>
                    <div class="xbox-metric-label">Character Classes</div>
                </div>
                """,
                unsafe_allow_html=True
            )
        with m3:
            st.markdown(
                f"""
                <div class="xbox-metric-box">
                    <div class="xbox-metric-val">{result.metrics.estimated_charset_pool_size}</div>
                    <div class="xbox-metric-label">Charset Pool Size (R)</div>
                </div>
                """,
                unsafe_allow_html=True
            )
        with m4:
            st.markdown(
                f"""
                <div class="xbox-metric-box">
                    <div class="xbox-metric-val xbox-metric-val-accent">{result.entropy.bits:.1f} <span style="font-size:0.9rem;">b</span></div>
                    <div class="xbox-metric-label">Theoretical Entropy</div>
                </div>
                """,
                unsafe_allow_html=True
            )

        st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

        # 3. Side-by-Side: Detected Risks vs Remediation Plan
        col_risks, col_recs = st.columns(2)

        with col_risks:
            st.markdown(
                """
                <div class="xbox-card">
                    <div class="xbox-card-header">
                        <span>⚠️ Identified Risk Findings</span>
                    </div>
                """,
                unsafe_allow_html=True
            )
            if not result.findings:
                st.success("✅ Clean Scan: Zero predictable patterns, repetitions, or common dictionary matches detected.")
            else:
                for f in result.findings:
                    sev_class = "xbox-badge-weak" if f.severity.value in ("CRITICAL", "HIGH") else "xbox-badge-medium"
                    st.markdown(
                        f"""
                        <div style="background:#161916; border-left: 3px solid #EF4444; border-radius: 0 6px 6px 0; padding:12px; margin-bottom:8px;">
                            <div style="display:flex; justify-content:space-between; align-items:center;">
                                <b style="color:#F4F6F2; font-size:0.92rem;">{f.title}</b>
                                <span class="xbox-badge {sev_class}">{f.severity.value}</span>
                            </div>
                            <div style="font-size:0.86rem; color:#A5ADA3; margin-top:4px;">{f.description}</div>
                            <div class="xbox-evidence-tag">Evidence: {f.evidence_redacted}</div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )

            # Defensive Strengths
            st.markdown(
                """
                    <div class="xbox-card-header" style="margin-top: 18px;">
                        <span>🛡️ Defensive Strengths</span>
                    </div>
                """,
                unsafe_allow_html=True
            )
            for obs in result.positive_observations:
                st.markdown(f"• <span style='font-size:0.86rem; color:#A5ADA3;'>{obs}</span>", unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)

        with col_recs:
            st.markdown(
                """
                <div class="xbox-card">
                    <div class="xbox-card-header">
                        <span>📋 Prioritized Recommendations</span>
                    </div>
                """,
                unsafe_allow_html=True
            )
            for idx, rec in enumerate(result.recommendations, 1):
                st.markdown(
                    f"""
                    <div style="background:#161916; border-radius:6px; padding:10px 14px; margin-bottom:8px; border:1px solid #2A302A;">
                        <b style="color:#80CC14; font-size:0.88rem;">Step {idx}:</b>
                        <span style="font-size:0.87rem; color:#F4F6F2;">{rec}</span>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
            st.markdown("</div>", unsafe_allow_html=True)

        # 4. Expandable "Decode the Verdict" Panel
        with st.expander("🔍 Decode the Verdict — Step-by-Step Rule Engine Audit Trace", expanded=False):
            st.markdown(
                "<div style='font-size:0.88rem; color:#A5ADA3; margin-bottom:12px;'>"
                "Inspect the transparent evaluation pipeline to see how raw characteristics triggered precedence rules:"
                "</div>",
                unsafe_allow_html=True
            )
            for s in result.verdict_trace:
                step_border = "#80CC14" if s.impact == "POSITIVE" else "#EF4444" if s.impact in ("CRITICAL", "HIGH_RISK") else "#F59E0B" if s.impact == "MODERATE_RISK" else "#343A34"
                st.markdown(
                    f"""
                    <div class="xbox-trace-step" style="border-left-color: {step_border};">
                        <div class="xbox-trace-title">
                            <span><b>{s.stage}</b> — <span style="font-family:'JetBrains Mono'; font-size:0.84rem; color:#80CC14;">{s.rule_applied}</span></span>
                            <span style="color:{step_border}; font-weight:700; font-size:0.8rem;">{s.outcome}</span>
                        </div>
                        <div class="xbox-trace-reason">{s.security_reasoning}</div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

            st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
            st.markdown(
                f"""
                <div style="background:#101210; border:1px solid #2A302A; border-radius:6px; padding:12px; font-size:0.84rem; color:#A5ADA3;">
                    <b>Entropy Calculation:</b> <code>{result.entropy.formula_description}</code> = <b>{result.entropy.bits:.2f} bits</b><br>
                    <span style="color:#6E766D;">{result.entropy.educational_caveat}</span>
                </div>
                """,
                unsafe_allow_html=True
            )

            st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
            st.markdown("<b>Documented Limitations:</b>")
            for lim in result.limitations:
                st.markdown(f"• <span style='font-size:0.82rem; color:#6E766D;'>{lim}</span>", unsafe_allow_html=True)


# ==============================================================================
# SCREEN 3: PATTERN LAB (GAME-LIBRARY-STYLE CARDS)
# ==============================================================================
elif st.session_state.nav_choice == "🎮 Pattern Lab":
    st.markdown(
        """
        <div style="margin-bottom: 20px;">
            <h1 style="font-size: 1.9rem; font-weight: 800; color: #F4F6F2; margin: 0 0 4px 0; letter-spacing: -0.02em;">
                PATTERN LAB
            </h1>
            <div style="font-size: 0.98rem; color: #A5ADA3;">
                Explore synthetic examples and discover why predictable passwords are risky.
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown(
        """
        <div class="xbox-card" style="margin-bottom: 20px;">
            <div style="font-weight: 600; color: #F4F6F2; margin-bottom: 4px;">
                The "Cosmetic Complexity" Illusion
            </div>
            <div style="font-size: 0.88rem; color: #A5ADA3; line-height: 1.5;">
                In legacy password checkers, passwords with uppercase letters, numbers, and symbols receive full points. 
                Modern attackers, however, use mutation rulesets (e.g. Hashcat's <code>best64.rule</code>) that instantly 
                reverse predictable substitutions. Click <b>Inspect in Analyzer</b> on any card below to see ENIGMA's real engine in action.
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    pattern_cases = [
        {
            "category": "LEETSPEAK MUTATION",
            "name": "The Cosmetic Illusion",
            "pwd": "P@ssw0rd1!",
            "desc": "10 characters with all 4 classes (Upper, Lower, Digit, Symbol). Passes standard enterprise policies.",
            "legacy": "PASS (4/4 Classes)",
            "enigma": "WEAK (Severe Leetspeak Base)",
            "icon": "🎭"
        },
        {
            "category": "HIGH-ENTROPY PASSPHRASE",
            "name": "NIST SP 800-63B Passphrase",
            "pwd": "correct-horse-battery-staple",
            "desc": "28 characters, only lowercase and hyphens. Fails legacy 3-class rules, but delivers 160+ bits of search space.",
            "legacy": "FAIL (No upper/digits)",
            "enigma": "STRONG (NIST SP 800-63B Passphrase)",
            "icon": "📖"
        },
        {
            "category": "SPATIAL KEYBOARD WALK",
            "name": "QWERTY Key Sweep",
            "pwd": "qwertyuiop123",
            "desc": "13 characters with letters and numbers. Physical proximity walk across the entire top keyboard row.",
            "legacy": "PASS (Length > 12)",
            "enigma": "WEAK (Keyboard Walk Override)",
            "icon": "⌨️"
        },
        {
            "category": "DICTIONARY + YEAR MASK",
            "name": "Corporate Pattern",
            "pwd": "Admin@2026!",
            "desc": "High-frequency corporate root word combined with upcoming calendar year mask.",
            "legacy": "PASS (4/4 Classes)",
            "enigma": "WEAK (Dictionary + Year Mask)",
            "icon": "📅"
        },
        {
            "category": "REPEATED RUNS",
            "name": "Character Dominance",
            "pwd": "aaaaaaa1111",
            "desc": "11 characters inflating length through consecutive identical character runs.",
            "legacy": "FAIL (2 Classes)",
            "enigma": "WEAK (Repetition & Dominance)",
            "icon": "🔁"
        },
        {
            "category": "CSPRNG UNIFORM RANDOM",
            "name": "16-Character High Entropy",
            "pwd": "K7#m$P2!vL9&qX8*",
            "desc": "16 characters uniformly selected from all 4 classes via secrets module. Zero predictable structures.",
            "legacy": "PASS (4/4 Classes)",
            "enigma": "STRONG (Clean High-Entropy)",
            "icon": "🎲"
        },
        {
            "category": "UNICODE SCRIPT",
            "name": "Cyrillic Script Keyspace",
            "pwd": "Пароль2026!#",
            "desc": "12 code points in Cyrillic script. Expands search space into international Unicode (Slide 7).",
            "legacy": "PASS (4/4 Classes)",
            "enigma": "MEDIUM (Year pattern noted)",
            "icon": "🌐"
        },
        {
            "category": "SEQUENTIAL RUN",
            "name": "Ascending Numbers",
            "pwd": "Safe12345678!",
            "desc": "Word followed by an 8-digit consecutive counting sequence.",
            "legacy": "PASS (4/4 Classes)",
            "enigma": "WEAK (Sequential Progression)",
            "icon": "🔢"
        }
    ]

    # Render in 2 columns
    for i in range(0, len(pattern_cases), 2):
        col_left, col_right = st.columns(2)
        for col, case_data in zip([col_left, col_right], pattern_cases[i:i+2]):
            with col:
                st.markdown(
                    f"""
                    <div class="xbox-tile" style="margin-bottom: 16px;">
                        <div>
                            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                                <span class="xbox-badge xbox-badge-neutral">{case_data['category']}</span>
                                <span style="font-size:1.3rem;">{case_data['icon']}</span>
                            </div>
                            <div class="xbox-tile-title">{case_data['name']}</div>
                            <div style="background:#161916; border:1px solid #2A302A; border-radius:4px; padding:6px 10px; margin:8px 0; font-family:'JetBrains Mono'; font-size:0.9rem; color:#80CC14;">
                                {case_data['pwd']}
                            </div>
                            <div class="xbox-tile-desc">{case_data['desc']}</div>
                            <div style="font-size:0.8rem; margin-bottom:12px; line-height:1.6;">
                                <span style="color:#EF4444;">Legacy Checkbox: <b>{case_data['legacy']}</b></span><br>
                                <span style="color:#80CC14;">ENIGMA Verdict: <b>{case_data['enigma']}</b></span>
                            </div>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
                st.button(
                    f"Inspect '{case_data['pwd']}' in Analyzer",
                    key=f"btn_inspect_{case_data['pwd']}",
                    use_container_width=True,
                    on_click=inspect_password_in_analyzer,
                    args=(case_data['pwd'],)
                )


# ==============================================================================
# SCREEN 4: SECURE GENERATOR
# ==============================================================================
elif st.session_state.nav_choice == "⚡ Secure Generator":
    st.markdown(
        """
        <div style="margin-bottom: 20px;">
            <h1 style="font-size: 1.9rem; font-weight: 800; color: #F4F6F2; margin: 0 0 4px 0; letter-spacing: -0.02em;">
                SECURE CREDENTIAL GENERATOR
            </h1>
            <div style="font-size: 0.98rem; color: #A5ADA3;">
                Generate strong random credentials locally using Python's secrets module.
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    t_rnd, t_pass = st.tabs(["🎲 High-Entropy Random Password", "📖 Memorable Multi-Word Passphrase"])

    with t_rnd:
        with st.container():
            st.markdown(
                """
                <div class="xbox-card">
                    <div class="xbox-card-header">
                        <span>Configuration: Random Character Token</span>
                    </div>
                """,
                unsafe_allow_html=True
            )
            col_glen, col_gpools = st.columns([1, 2])
            with col_glen:
                gen_len = st.slider("Password Length", min_value=12, max_value=64, value=16, key="gen_rnd_len")
            with col_gpools:
                st.write("Character Classes Included:")
                g_u = st.checkbox("Uppercase Letters (A-Z)", value=True, key="gen_u")
                g_l = st.checkbox("Lowercase Letters (a-z)", value=True, key="gen_l")
                g_d = st.checkbox("Digits (0-9)", value=True, key="gen_d")
                g_s = st.checkbox("Symbols (!@#$%...)", value=True, key="gen_s")

            if st.button("Generate Random Password", type="primary", use_container_width=True, key="btn_gen_rnd"):
                new_pwd = generate_random_password(
                    length=gen_len,
                    use_upper=g_u,
                    use_lower=g_l,
                    use_digits=g_d,
                    use_symbols=g_s
                )
                st.session_state.generated_credential = new_pwd

            st.markdown("</div>", unsafe_allow_html=True)

    with t_pass:
        with st.container():
            st.markdown(
                """
                <div class="xbox-card">
                    <div class="xbox-card-header">
                        <span>Configuration: EFF-Style Diceware Passphrase</span>
                    </div>
                """,
                unsafe_allow_html=True
            )
            col_pw, col_psep = st.columns(2)
            with col_pw:
                w_count = st.slider("Word Count", min_value=4, max_value=8, value=5, key="gen_w_count")
            with col_psep:
                w_sep = st.selectbox("Word Separator", options=["-", "_", ".", " "], index=0, key="gen_w_sep")

            col_pcap, col_pnum = st.columns(2)
            with col_pcap:
                w_cap = st.checkbox("Capitalize Words", value=True, key="gen_w_cap")
            with col_pnum:
                w_num = st.checkbox("Append Random 2-digit Number", value=True, key="gen_w_num")

            if st.button("Generate Passphrase", type="primary", use_container_width=True, key="btn_gen_pass"):
                new_phrase = generate_passphrase(
                    word_count=w_count,
                    separator=w_sep,
                    capitalize_words=w_cap,
                    append_number=w_num
                )
                st.session_state.generated_credential = new_phrase

            st.markdown("</div>", unsafe_allow_html=True)

    # Generated Credential Display Panel
    if st.session_state.generated_credential:
        cred = st.session_state.generated_credential
        st.markdown(
            f"""
            <div class="xbox-card" style="border: 1px solid #80CC14; background: #161B16;">
                <div style="font-size: 0.82rem; font-weight:700; color: #80CC14; text-transform:uppercase; margin-bottom: 6px;">
                    GENERATED CREDENTIAL
                </div>
                <div style="font-family:'JetBrains Mono'; font-size:1.35rem; color:#F4F6F2; padding:12px; background:#101210; border-radius:6px; word-break:break-all; border:1px solid #2A302A;">
                    {cred}
                </div>
                <div style="font-size:0.8rem; color:#6E766D; margin-top:8px;">
                    🔒 Generated locally in RAM via os.urandom. Never transmitted or persisted.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        col_load, col_clear_gen = st.columns([2, 1])
        with col_load:
            st.button(
                "Analyze this in Password Analyzer →",
                use_container_width=True,
                key="btn_analyze_generated_cred",
                on_click=analyze_generated_credential
            )
        with col_clear_gen:
            st.button(
                "Clear Generated",
                use_container_width=True,
                key="btn_clear_generated_cred",
                on_click=clear_generated_credential
            )


# ==============================================================================
# SCREEN 5: SETTINGS
# ==============================================================================
elif st.session_state.nav_choice == "⚙️ Settings":
    st.markdown(
        """
        <div style="margin-bottom: 20px;">
            <h1 style="font-size: 1.9rem; font-weight: 800; color: #F4F6F2; margin: 0 0 4px 0; letter-spacing: -0.02em;">
                SETTINGS & POLICY CONFIGURATION
            </h1>
            <div style="font-size: 0.98rem; color: #A5ADA3;">
                Configure organizational baseline thresholds and inspection rules.
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    with st.container():
        st.markdown(
            """
            <div class="xbox-card">
                <div class="xbox-card-header">
                    <span>⚙️ Organizational Baseline Policy</span>
                </div>
            """,
            unsafe_allow_html=True
        )

        col_s_len, col_s_classes = st.columns(2)
        with col_s_len:
            # FIX: Slider uses explicit key="slider_min_length" and on_change callback
            st.slider(
                "Minimum Length Policy",
                min_value=6,
                max_value=24,
                key="slider_min_length",
                on_change=on_policy_slider_change,
                help="DecodeLabs minimum assignment requirement is 8 code points."
            )
            st.caption("Baseline minimum required for policy compliance. (Standard assignment value is 8 characters).")

        with col_s_classes:
            # FIX: Slider uses explicit key="slider_min_classes" and on_change callback
            st.slider(
                "Minimum Character Classes",
                min_value=1,
                max_value=4,
                key="slider_min_classes",
                on_change=on_policy_slider_change,
                help="Classes: Uppercase, Lowercase, Digits, Symbols."
            )
            st.caption("Number of independent character classes required to satisfy organizational policy.")

        st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)

        # FIX: Reset button invokes callback that resets both slider session keys before widgets render
        st.button(
            "Reset to DecodeLabs Defaults (8 chars, 3 classes)",
            on_click=reset_policy_defaults,
            use_container_width=True,
            key="btn_reset_policy_defaults"
        )

        st.markdown("</div>", unsafe_allow_html=True)

    # Active Policy Summary Card
    st.markdown(
        f"""
        <div class="xbox-card" style="border-left: 3px solid #80CC14;">
            <div style="font-weight: 600; color: #F4F6F2; margin-bottom: 4px;">Active Configuration Summary</div>
            <div style="font-size: 0.88rem; color: #A5ADA3; line-height: 1.5;">
                • Length Floor: <b>{st.session_state.min_length_policy}</b> characters.<br>
                • Minimum Character Classes: <b>{st.session_state.min_classes_policy}</b> of 4 required.<br>
                • Offline Signatures: <b>{get_dataset_size():,}</b> weak passwords loaded in memory.<br>
                • Maximum Input Cap: <b>512</b> Unicode code points (DoS/ReDoS protection).
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )
