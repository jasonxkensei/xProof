"""pytest wrapper — runs examples/compliance_observability.py in CI.

This test imports the example module and calls its three verification
functions so the full observability pattern (structured logging, webhook
success, webhook failure fallback) is exercised on every CI run.
"""

import sys
import os


def _ensure_examples_importable() -> None:
    """Add python-sdk/ to sys.path so 'examples' package is importable."""
    sdk_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if sdk_root not in sys.path:
        sys.path.insert(0, sdk_root)


_ensure_examples_importable()


def test_compliance_observability_core() -> None:
    """Core observability pattern — structured JSON log, audit trail, assertions."""
    import examples.compliance_observability as obs

    obs.run("ci-test-decision-core")


def test_compliance_observability_webhook_success() -> None:
    """Webhook success path — urlopen called with correct payload."""
    import examples.compliance_observability as obs

    obs.run_with_webhook_success("ci-test-decision-webhook-ok")


def test_compliance_observability_webhook_failure() -> None:
    """Webhook failure path — OSError logged as warning, not re-raised."""
    import examples.compliance_observability as obs

    obs.run_with_webhook_failure("ci-test-decision-webhook-fail")
