"""
tests/test_metrics.py — Tests for Prometheus metrics registry, collectors, and HTTP endpoint
"""

from vaulting.metrics import (
    REGISTRY,
    generate_metrics_page,
    timer,
)


def test_metrics_collection_and_formatting():
    """Verify counters and gauges update and render in Prometheus text format."""
    REGISTRY.rotations_total.inc(labels={"outcome": "test_success"})
    REGISTRY.secrets_total.set(42)

    page = generate_metrics_page()
    text = page.decode("utf-8")

    assert "# TYPE vaulting_rotations counter" in text
    assert 'vaulting_rotations_total{outcome="test_success"} 1.0' in text
    assert "# TYPE vaulting_secrets_total gauge" in text
    assert "vaulting_secrets_total 42" in text


def test_timer_context_manager():
    """Verify timer records duration into the histogram."""
    initial_count = REGISTRY.rotation_duration._total
    with timer(REGISTRY.rotation_duration):
        pass

    assert REGISTRY.rotation_duration._total == initial_count + 1
