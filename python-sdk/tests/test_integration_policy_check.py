"""Live-API integration test — policy check endpoint (Task #86).

Run with:
    pytest python-sdk/tests/test_integration_policy_check.py -m integration -v

Requires:
    XPROOF_INTEGRATION=1  (opt-in flag so CI never hits the live API by default)
    XPROOF_API_KEY=<key>  (optional — falls back to registering a trial key)

Tests covered:
  1. certify_with_confidence() round-trip + get_policy_check() on compliant proof
  2. PolicyCheckResult fields are properly typed
  3. certify_with_confidence() raises PolicyViolationError when
     an irreversible action is submitted with confidence < 0.95
"""

import hashlib
import os
import time
import uuid

import pytest

from xproof import (
    PolicyViolationError,
    RateLimitError,
    XProofClient,
)
from xproof.models import PolicyCheckResult


@pytest.mark.integration
@pytest.mark.skipif(
    not os.environ.get("XPROOF_INTEGRATION"),
    reason="Set XPROOF_INTEGRATION=1 to run live policy-check integration tests",
)
def test_policy_check_compliant_decision() -> None:
    """certify_with_confidence + get_policy_check — happy path (compliant)."""
    api_key = os.environ.get("XPROOF_API_KEY")
    if api_key:
        client = XProofClient(api_key=api_key)
    else:
        try:
            client = XProofClient.register(f"sdk-polchk-{uuid.uuid4().hex[:8]}")
        except RateLimitError:
            pytest.skip("Rate-limited — trial registration limit reached")

    unique = f"policy-check-test-{time.time()}-{uuid.uuid4().hex}"
    file_hash = hashlib.sha256(unique.encode()).hexdigest()

    cert = client.certify_with_confidence(
        file_hash=file_hash,
        file_name="policy-check-test.json",
        author="sdk-test",
        confidence_level=0.80,
        threshold_stage="review",
        reversibility_class="reversible",
    )
    assert cert.id, "certify_with_confidence should return a Certification with an id"

    result = client.get_policy_check(cert.id)
    assert isinstance(result, PolicyCheckResult)
    assert result.decision_id == cert.id
    assert isinstance(result.policy_compliant, bool)
    assert isinstance(result.policy_violations, list)
    assert result.policy_compliant is True, (
        "A reversible action at 0.80 confidence should be compliant"
    )
    assert result.total_anchors >= 1


@pytest.mark.integration
@pytest.mark.skipif(
    not os.environ.get("XPROOF_INTEGRATION"),
    reason="Set XPROOF_INTEGRATION=1 to run live policy-check integration tests",
)
def test_policy_check_irreversible_below_threshold_raises() -> None:
    """certify_with_confidence raises PolicyViolationError for irreversible < 0.95."""
    api_key = os.environ.get("XPROOF_API_KEY")
    if api_key:
        client = XProofClient(api_key=api_key)
    else:
        try:
            client = XProofClient.register(f"sdk-polchk-{uuid.uuid4().hex[:8]}")
        except RateLimitError:
            pytest.skip("Rate-limited — trial registration limit reached")

    unique = f"policy-violate-test-{time.time()}-{uuid.uuid4().hex}"
    file_hash = hashlib.sha256(unique.encode()).hexdigest()

    with pytest.raises(PolicyViolationError) as exc_info:
        client.certify_with_confidence(
            file_hash=file_hash,
            file_name="irreversible-low-confidence.json",
            author="sdk-test",
            confidence_level=0.70,
            threshold_stage="execution",
            reversibility_class="irreversible",
        )

    err = exc_info.value
    assert err.violations, "PolicyViolationError must carry at least one violation"
    first = err.violations[0]
    assert first.reversibility_class == "irreversible"
    assert first.threshold <= 0.95
