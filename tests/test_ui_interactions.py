"""
UI Interaction Integration Tests using Streamlit AppTest framework.
Validates:
1. Absence of Security Insights tab in navigation (exactly 5 navigation screens).
2. Reset to DecodeLabs Defaults in Settings screen resets sliders and policy variables to 8 chars and 3 classes.
3. 'Analyze this in Password Analyzer ->' in Secure Generator populates candidate input and switches to Password Analyzer screen.
"""

from pathlib import Path
from streamlit.testing.v1 import AppTest

APP_PATH = str(Path(__file__).parent.parent / "app.py")


def test_sidebar_navigation_screens():
    """Verify that Security Insights is removed and only the 5 approved screens exist."""
    at = AppTest.from_file(APP_PATH).run()
    assert not at.exception, f"App encountered exception: {at.exception}"

    # Verify radio options
    radio = at.sidebar.radio(key="nav_choice")
    options = radio.options
    assert len(options) == 5, f"Expected 5 navigation options, found {len(options)}: {options}"
    assert "📊 Security Insights" not in options
    assert "Security Insights" not in " ".join(options)
    assert any("Home" in opt for opt in options)
    assert any("Password Analyzer" in opt for opt in options)
    assert any("Pattern Lab" in opt for opt in options)
    assert any("Secure Generator" in opt for opt in options)
    assert any("Settings" in opt for opt in options)


def test_settings_reset_to_defaults():
    """Verify that clicking 'Reset to DecodeLabs Defaults' resets sliders and session state."""
    at = AppTest.from_file(APP_PATH).run()
    assert not at.exception

    # Switch to Settings
    radio = at.sidebar.radio(key="nav_choice")
    for opt in radio.options:
        if "Settings" in opt:
            settings_opt = opt
            break
    radio.set_value(settings_opt).run()
    assert not at.exception

    # Modify sliders
    slider_len = at.slider(key="slider_min_length")
    slider_classes = at.slider(key="slider_min_classes")
    slider_len.set_value(16).run()
    slider_classes.set_value(4).run()

    assert at.session_state.slider_min_length == 16
    assert at.session_state.slider_min_classes == 4
    assert at.session_state.min_length_policy == 16
    assert at.session_state.min_classes_policy == 4

    # Click the Reset Button
    reset_btn = at.button(key="btn_reset_policy_defaults")
    reset_btn.click().run()
    assert not at.exception

    # Verify that sliders and session state are restored to DecodeLabs defaults (8 chars, 3 classes)
    assert at.session_state.slider_min_length == 8, f"Expected 8, got {at.session_state.slider_min_length}"
    assert at.session_state.slider_min_classes == 3, f"Expected 3, got {at.session_state.slider_min_classes}"
    assert at.session_state.min_length_policy == 8
    assert at.session_state.min_classes_policy == 3


def test_secure_generator_analyze_transition():
    """Verify that generating a credential and clicking 'Analyze this in Password Analyzer ->' correctly navigates and populates."""
    at = AppTest.from_file(APP_PATH).run()
    assert not at.exception

    # Switch to Secure Generator
    radio = at.sidebar.radio(key="nav_choice")
    for opt in radio.options:
        if "Secure Generator" in opt:
            gen_opt = opt
            break
    radio.set_value(gen_opt).run()
    assert not at.exception

    # Click 'Generate Random Password'
    gen_btn = at.button(key="btn_gen_rnd")
    gen_btn.click().run()
    assert not at.exception

    cred = at.session_state.generated_credential
    assert cred, "Generated credential should not be empty"
    assert len(cred) >= 12

    # Click 'Analyze this in Password Analyzer ->'
    analyze_trans_btn = at.button(key="btn_analyze_generated_cred")
    analyze_trans_btn.click().run()
    assert not at.exception

    # Verify navigation switched to Password Analyzer
    assert "Password Analyzer" in at.session_state.nav_choice

    # Verify candidate input was populated with the generated credential
    assert at.session_state.analyzer_pwd_input == cred

    # Verify analysis result exists and has a verdict
    assert at.session_state.analyzed_result is not None
    assert at.session_state.analyzed_result.risk_level is not None


def test_home_navigation_buttons():
    """Verify that feature tiles on Home dashboard navigate properly without errors."""
    at = AppTest.from_file(APP_PATH).run()
    assert not at.exception

    # Click hero button to open Analyzer
    hero_btn = at.button(key="home_btn_analyze_hero")
    hero_btn.click().run()
    assert not at.exception
    assert "Password Analyzer" in at.session_state.nav_choice

    # Return to Home
    radio = at.sidebar.radio(key="nav_choice")
    for opt in radio.options:
        if "Home" in opt:
            home_opt = opt
            break
    radio.set_value(home_opt).run()
    assert not at.exception

    # Click Generator card button
    gen_btn = at.button(key="home_btn_gen")
    gen_btn.click().run()
    assert not at.exception
    assert "Secure Generator" in at.session_state.nav_choice


def test_pattern_lab_inspect_transition():
    """Verify that clicking 'Inspect in Analyzer' in Pattern Lab switches to analyzer and populates input."""
    at = AppTest.from_file(APP_PATH).run()
    assert not at.exception

    # Switch to Pattern Lab
    radio = at.sidebar.radio(key="nav_choice")
    for opt in radio.options:
        if "Pattern Lab" in opt:
            lab_opt = opt
            break
    radio.set_value(lab_opt).run()
    assert not at.exception

    # Inspect a synthetic case (e.g. P@ssw0rd1!)
    inspect_btn = at.button(key="btn_inspect_P@ssw0rd1!")
    inspect_btn.click().run()
    assert not at.exception

    # Should have navigated to Password Analyzer and analyzed the case
    assert "Password Analyzer" in at.session_state.nav_choice
    assert at.session_state.analyzer_pwd_input == "P@ssw0rd1!"
    assert at.session_state.analyzed_result is not None
