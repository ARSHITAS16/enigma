"""
Pytest configuration and fixtures for ENIGMA test suite.
"""

import sys
from pathlib import Path
import pytest

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from analyzer import PasswordAnalyzer


@pytest.fixture
def analyzer():
    """Provides a fresh default PasswordAnalyzer instance."""
    return PasswordAnalyzer(min_length_policy=8, min_classes_policy=3, max_input_length=512)
