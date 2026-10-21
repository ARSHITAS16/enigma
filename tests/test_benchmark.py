"""
Performance benchmark and computational efficiency verification for ENIGMA.
Validates Slide 8 & 9 constraint: Linear-time O(n) scan without polynomial blowup.
"""

import time
import pytest
from analyzer import PasswordAnalyzer, generate_random_password, generate_passphrase


def test_linear_time_complexity_benchmark(analyzer):
    """
    Benchmarks execution time across lengths: 16, 64, 128, 256, 512 characters.
    Validates that runtime is bounded and approximately linear (O(n)).
    """
    lengths = [16, 64, 128, 256, 512]
    timings = {}

    for length in lengths:
        test_input = "aB9!xY2@" * (length // 8)
        
        # Warmup
        _ = analyzer.analyze(test_input)

        # Timed execution over 20 iterations
        start = time.perf_counter()
        for _ in range(20):
            _ = analyzer.analyze(test_input)
        elapsed_ms = ((time.perf_counter() - start) / 20) * 1000
        timings[length] = elapsed_ms

        # Assert each evaluation completes in well under 25 milliseconds
        assert elapsed_ms < 25.0, f"Analysis of length {length} took {elapsed_ms:.2f}ms (exceeded 25ms SLA)"

    # Check scaling: ratio of 512 chars (32x length of 16) should not blow up exponentially
    time_16 = max(timings[16], 0.001)
    time_512 = timings[512]
    scaling_ratio = time_512 / time_16
    
    # 32x length should scale well below 100x (safely avoiding O(n^2) or O(2^n))
    assert scaling_ratio < 100.0, f"Scaling ratio {scaling_ratio:.1f}x indicates non-linear complexity"


def test_generator_performance():
    # Verify generator creates requested lengths efficiently
    for length in (8, 16, 32, 64):
        pwd = generate_random_password(length=length)
        assert len(pwd) == length

    phrase = generate_passphrase(word_count=5, separator="-")
    assert len(phrase.split("-")) >= 5
