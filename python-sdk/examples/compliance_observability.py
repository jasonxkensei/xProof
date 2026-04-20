"""Compliance violation alerts — runnable observability example.

Demonstrates the pattern from the README "Observability — surfacing violations
in dashboards" section against a fully mocked XProofClient so no real API key
or network access is required.

Run from the python-sdk directory (where the xproof package is installed):

    # Install the package once (if not already installed):
    pip install -e .

    # Then run the example:
    python examples/compliance_observability.py

Expected outcome: structured JSON log lines are printed to stdout and the
script exits 0, confirming the _emit_violation helper and get_confidence_trail
call both behave as documented.
"""

import json
import logging
import sys
import urllib.request
from typing import Any, Dict, List
from unittest.mock import MagicMock

from xproof.models import ConfidenceTrail, PolicyCheckResult, PolicyViolation


logger = logging.getLogger("xproof.compliance")
logging.basicConfig(
    level=logging.INFO,
    stream=sys.stdout,
    format="%(message)s",
)

VIOLATION_WEBHOOK_URL = None


def _emit_violation(decision_id: str, violation: PolicyViolation) -> None:
    """Emit one structured log line and, optionally, a webhook call."""
    payload = {
        "event":       "policy_violation",
        "decision_id": decision_id,
        "rule":        violation.rule,
        "severity":    violation.severity,
        "message":     violation.message,
    }
    logger.error(json.dumps(payload))

    if VIOLATION_WEBHOOK_URL:
        try:
            body = json.dumps(payload).encode()
            req  = urllib.request.Request(
                VIOLATION_WEBHOOK_URL,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5):
                pass
        except Exception as exc:
            logger.warning(json.dumps({"event": "webhook_error", "detail": str(exc)}))


def build_mock_client(decision_id: str) -> MagicMock:
    """Return a mock XProofClient pre-loaded with a non-compliant policy check
    and a matching confidence trail so the example works without any network
    calls."""

    violation_data = {
        "rule":     "data-retention-90d",
        "severity": "error",
        "message":  "Document retention period exceeds the 90-day policy limit.",
    }

    policy_check = PolicyCheckResult.from_dict({
        "decision_id":      decision_id,
        "total_anchors":    2,
        "policy_compliant": False,
        "policy_violations": [violation_data],
        "checked_at":       "2026-04-20T12:00:00Z",
    })

    trail_raw = {
        "decision_id":       decision_id,
        "total_anchors":     2,
        "current_confidence": 0.72,
        "current_stage":     "review",
        "is_finalized":      False,
        "policy_compliant":  False,
        "policy_violations": [violation_data],
        "stages": [
            {
                "proof_id":         "proof-stage-1",
                "confidence_level": 0.50,
                "threshold_stage":  "draft",
                "reversibility_class": "reversible",
                "anchored_at":      "2026-04-20T11:00:00Z",
                "transaction_hash": "0xabc123",
                "transaction_url":  "https://explorer.multiversx.com/transactions/0xabc123",
                "policy_violations": [],
            },
            {
                "proof_id":         "proof-stage-2",
                "confidence_level": 0.72,
                "threshold_stage":  "review",
                "reversibility_class": "costly",
                "anchored_at":      "2026-04-20T12:00:00Z",
                "transaction_hash": "0xdef456",
                "transaction_url":  "https://explorer.multiversx.com/transactions/0xdef456",
                "policy_violations": [violation_data],
            },
        ],
    }
    trail = ConfidenceTrail.from_dict(trail_raw)

    client = MagicMock()
    client.get_policy_check.return_value = policy_check
    client.get_confidence_trail.return_value = trail
    return client


def run(decision_id: str) -> None:
    """Exercise the observability pattern and verify structured outputs."""

    client = build_mock_client(decision_id)

    check = client.get_policy_check(decision_id)
    assert check.decision_id == decision_id, "get_policy_check must echo back the decision_id"

    emitted: List[Dict[str, Any]] = []
    trail_stages = 0

    if not check.policy_compliant:
        for v in check.policy_violations:
            _emit_violation(decision_id, v)
            emitted.append({
                "rule":     v.rule,
                "severity": v.severity,
                "message":  v.message,
            })

        trail = client.get_confidence_trail(decision_id)
        trail_stages = len(trail.stages)
        logger.error(json.dumps({
            "event":       "audit_trail",
            "decision_id": decision_id,
            "trail":       trail.raw,
        }))

        assert trail.decision_id == decision_id, "Trail decision_id must match"
        assert trail_stages == 2, "Trail must contain two stage anchors"
        assert trail.stages[1].transaction_hash == "0xdef456", \
            "Second stage transaction hash must be 0xdef456"

    assert len(emitted) == 1, "Exactly one violation must have been emitted"
    assert emitted[0]["rule"] == "data-retention-90d", \
        "Emitted violation rule must match the stubbed rule"

    client.get_policy_check.assert_called_once_with(decision_id)
    client.get_confidence_trail.assert_called_once_with(decision_id)

    print(json.dumps({
        "result":       "ok",
        "decision_id":  decision_id,
        "violations":   len(emitted),
        "trail_stages": trail_stages,
    }))


def main() -> None:
    decision_id = "demo-decision-42"

    print(f"Running compliance observability example for decision '{decision_id}' ...\n")
    run(decision_id)
    print("\nAll assertions passed — example exited cleanly.")


if __name__ == "__main__":
    main()
