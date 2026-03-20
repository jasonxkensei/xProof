"""Integration test against the live xProof API.

Run with: pytest python-sdk/tests/test_integration.py -m integration -v
This test hits the real API and uses the trial flow.
Skips automatically when rate-limited or when XPROOF_INTEGRATION env is not set.
"""

import hashlib
import os
import time
import uuid

import pytest

from xproof import XProofClient, ConflictError, RateLimitError


@pytest.mark.integration
@pytest.mark.skipif(
    not os.environ.get("XPROOF_INTEGRATION"),
    reason="Set XPROOF_INTEGRATION=1 to run live integration tests",
)
def test_full_trial_flow():
    """Register trial -> certify_hash -> verify -> verify_hash."""
    unique_name = f"sdk-test-{uuid.uuid4().hex[:8]}"
    try:
        client = XProofClient.register(unique_name)
    except RateLimitError:
        pytest.skip("Rate-limited — trial registration limit reached")

    assert client.api_key.startswith("pm_")
    assert client.registration is not None
    assert client.registration.trial.remaining > 0

    unique_data = f"xproof-sdk-integration-test-{time.time()}-{uuid.uuid4().hex}"
    file_hash = hashlib.sha256(unique_data.encode()).hexdigest()

    cert = client.certify_hash(
        file_hash=file_hash,
        file_name="sdk-integration-test.txt",
        author=unique_name,
    )
    assert cert.id
    assert cert.file_hash == file_hash

    verified = client.verify(cert.id)
    assert verified.id == cert.id
    assert verified.file_hash == file_hash

    verified_by_hash = client.verify_hash(file_hash)
    assert verified_by_hash.id == cert.id

    with pytest.raises(ConflictError):
        client.certify_hash(
            file_hash=file_hash,
            file_name="sdk-integration-test.txt",
            author=unique_name,
        )


@pytest.mark.integration
@pytest.mark.skipif(
    not os.environ.get("XPROOF_INTEGRATION"),
    reason="Set XPROOF_INTEGRATION=1 to run live integration tests",
)
def test_pricing_endpoint():
    """Pricing is a public endpoint, no auth needed."""
    client = XProofClient()
    pricing = client.get_pricing()
    assert pricing.price_usd > 0
