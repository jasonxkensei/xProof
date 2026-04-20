"""Unit tests for XProofClient with mocked HTTP responses."""

import hashlib
import json
import os
import tempfile

import pytest
import responses
from xproof import (
    AuthenticationError,
    ConflictError,
    NotFoundError,
    RateLimitError,
    ServerError,
    ValidationError,
    XProofClient,
    XProofError,
    hash_file,
)
from xproof.utils import hash_bytes

BASE = "https://xproof.app"


@responses.activate
def test_register():
    responses.add(
        responses.POST,
        f"{BASE}/api/agent/register",
        json={
            "api_key": "pm_test123",
            "agent_name": "test-agent",
            "trial": {"quota": 10, "used": 0, "remaining": 10},
            "endpoints": {
                "certify": f"{BASE}/api/proof",
                "batch": f"{BASE}/api/batch",
            },
        },
        status=200,
    )
    client = XProofClient.register("test-agent")
    assert client.api_key == "pm_test123"
    assert client.registration is not None
    assert client.registration.agent_name == "test-agent"
    assert client.registration.trial.quota == 10
    assert client.registration.trial.remaining == 10
    assert "certify" in client.registration.endpoints


@responses.activate
def test_certify_hash():
    responses.add(
        responses.POST,
        f"{BASE}/api/proof",
        json={
            "id": "proof-001",
            "fileName": "report.pdf",
            "fileHash": "abc123",
            "transactionHash": "tx-001",
            "transactionUrl": "https://explorer.multiversx.com/tx/001",
            "createdAt": "2026-01-01T00:00:00Z",
            "authorName": "Alice",
            "blockchainStatus": "confirmed",
        },
        status=201,
    )
    client = XProofClient(api_key="pm_test")
    cert = client.certify_hash(
        file_hash="abc123",
        file_name="report.pdf",
        author="Alice",
    )
    assert cert.id == "proof-001"
    assert cert.file_name == "report.pdf"
    assert cert.file_hash == "abc123"
    assert cert.transaction_hash == "tx-001"
    assert cert.author_name == "Alice"
    assert cert.blockchain_status == "confirmed"


@responses.activate
def test_certify_file():
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
        f.write(b"hello world")
        tmppath = f.name

    try:
        expected_hash = hashlib.sha256(b"hello world").hexdigest()
        responses.add(
            responses.POST,
            f"{BASE}/api/proof",
            json={
                "id": "proof-file",
                "fileName": os.path.basename(tmppath),
                "fileHash": expected_hash,
                "transactionHash": "tx-file",
                "transactionUrl": "https://explorer.multiversx.com/tx/file",
                "createdAt": "2026-01-01T00:00:00Z",
                "authorName": "Bob",
            },
            status=201,
        )
        client = XProofClient(api_key="pm_test")
        cert = client.certify(tmppath, author="Bob")
        assert cert.id == "proof-file"
        assert cert.file_hash == expected_hash
        req_body = json.loads(responses.calls[0].request.body)
        assert req_body["file_hash"] == expected_hash
    finally:
        os.unlink(tmppath)


@responses.activate
def test_batch_certify():
    responses.add(
        responses.POST,
        f"{BASE}/api/batch",
        json={
            "batch_id": "batch-001",
            "total": 2,
            "created": 2,
            "existing": 0,
            "results": [
                {
                    "file_hash": "h1",
                    "filename": "a.pdf",
                    "proof_id": "proof-b1",
                    "verify_url": "https://example.com/proof/proof-b1",
                    "badge_url": "https://example.com/badge/proof-b1",
                    "status": "created",
                },
                {
                    "file_hash": "h2",
                    "filename": "b.pdf",
                    "proof_id": "proof-b2",
                    "verify_url": "https://example.com/proof/proof-b2",
                    "badge_url": "https://example.com/badge/proof-b2",
                    "status": "created",
                },
            ],
        },
        status=201,
    )
    client = XProofClient(api_key="pm_test")
    result = client.batch_certify([
        {"file_hash": "h1", "file_name": "a.pdf", "author": "A"},
        {"file_hash": "h2", "file_name": "b.pdf", "author": "B"},
    ])
    assert result.batch_id == "batch-001"
    assert result.summary.total == 2
    assert result.summary.created == 2
    assert result.summary.existing == 0
    assert result.summary.certified == 2
    assert len(result.results) == 2
    assert result.results[0].id == "proof-b1"


def test_batch_certify_max_50():
    client = XProofClient(api_key="pm_test")
    with pytest.raises(ValueError, match="maximum of 50"):
        client.batch_certify([{"file_hash": f"h{i}", "file_name": f"f{i}", "author": ""} for i in range(51)])


@responses.activate
def test_verify():
    responses.add(
        responses.GET,
        f"{BASE}/api/proof/proof-001",
        json={
            "id": "proof-001",
            "fileName": "doc.pdf",
            "fileHash": "xyz",
            "transactionHash": "tx-v",
            "transactionUrl": "",
            "createdAt": "",
        },
        status=200,
    )
    client = XProofClient(api_key="pm_test")
    cert = client.verify("proof-001")
    assert cert.id == "proof-001"
    assert cert.file_name == "doc.pdf"


@responses.activate
def test_verify_hash():
    responses.add(
        responses.GET,
        f"{BASE}/api/proof/hash/abc123",
        json={
            "id": "proof-vh",
            "fileName": "doc.pdf",
            "fileHash": "abc123",
            "transactionHash": "tx-vh",
            "transactionUrl": "",
            "createdAt": "",
        },
        status=200,
    )
    client = XProofClient(api_key="pm_test")
    cert = client.verify_hash("abc123")
    assert cert.id == "proof-vh"
    assert cert.file_hash == "abc123"


@responses.activate
def test_get_pricing():
    responses.add(
        responses.GET,
        f"{BASE}/api/pricing",
        json={
            "protocol": "xproof",
            "version": "1.0",
            "price_usd": 0.05,
            "tiers": [{"min": 1, "max": 100, "price": 0.05}],
            "payment_methods": [{"method": "USDC", "network": "Base"}],
        },
        status=200,
    )
    client = XProofClient()
    pricing = client.get_pricing()
    assert pricing.protocol == "xproof"
    assert pricing.price_usd == 0.05
    assert len(pricing.tiers) == 1
    assert pricing.tiers[0].price_usd == 0.05


@responses.activate
def test_error_401():
    responses.add(responses.POST, f"{BASE}/api/proof", json={"error": "Unauthorized"}, status=401)
    client = XProofClient(api_key="pm_bad")
    with pytest.raises(AuthenticationError):
        client.certify_hash("h", "f", "a")


@responses.activate
def test_error_400():
    responses.add(responses.POST, f"{BASE}/api/proof", json={"error": "Bad request"}, status=400)
    client = XProofClient(api_key="pm_test")
    with pytest.raises(ValidationError):
        client.certify_hash("h", "f", "a")


@responses.activate
def test_error_404():
    responses.add(responses.GET, f"{BASE}/api/proof/nope", json={"error": "Not found"}, status=404)
    client = XProofClient()
    with pytest.raises(NotFoundError):
        client.verify("nope")


@responses.activate
def test_error_409():
    responses.add(
        responses.POST,
        f"{BASE}/api/proof",
        json={"error": "Already certified", "certificationId": "dup-1"},
        status=409,
    )
    client = XProofClient(api_key="pm_test")
    with pytest.raises(ConflictError) as exc_info:
        client.certify_hash("h", "f", "a")
    assert exc_info.value.certification_id == "dup-1"


@responses.activate
def test_error_429():
    responses.add(responses.POST, f"{BASE}/api/proof", json={"error": "Rate limited"}, status=429)
    client = XProofClient(api_key="pm_test")
    with pytest.raises(RateLimitError):
        client.certify_hash("h", "f", "a")


@responses.activate
def test_error_500():
    responses.add(responses.POST, f"{BASE}/api/proof", json={"error": "Server error"}, status=500)
    client = XProofClient(api_key="pm_test")
    with pytest.raises(ServerError):
        client.certify_hash("h", "f", "a")


def test_no_api_key_certify():
    client = XProofClient()
    with pytest.raises(ValueError, match="api_key is required"):
        client.certify_hash("h", "f", "a")


def test_hash_file():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"test data")
        tmppath = f.name
    try:
        result = hash_file(tmppath)
        expected = hashlib.sha256(b"test data").hexdigest()
        assert result == expected
        assert len(result) == 64
    finally:
        os.unlink(tmppath)


def test_hash_bytes():
    result = hash_bytes(b"hello")
    expected = hashlib.sha256(b"hello").hexdigest()
    assert result == expected
    assert len(result) == 64


@responses.activate
def test_auth_header_uses_bearer():
    responses.add(
        responses.POST,
        f"{BASE}/api/proof",
        json={"id": "p1", "fileName": "f", "fileHash": "h", "transactionHash": "t", "transactionUrl": "", "createdAt": ""},
        status=201,
    )
    client = XProofClient(api_key="pm_mykey123")
    client.certify_hash("a" * 64, "f.txt", "author")
    req = responses.calls[0].request
    assert "Authorization" in req.headers
    assert req.headers["Authorization"] == "Bearer pm_mykey123"
    assert "X-API-Key" not in req.headers


@responses.activate
def test_certify_hash_sends_snake_case_fields():
    responses.add(
        responses.POST,
        f"{BASE}/api/proof",
        json={"id": "p1", "fileName": "f", "fileHash": "h", "transactionHash": "t", "transactionUrl": "", "createdAt": ""},
        status=201,
    )
    client = XProofClient(api_key="pm_test")
    test_hash = "b" * 64
    client.certify_hash(test_hash, "report.pdf", "Alice")
    req_body = json.loads(responses.calls[0].request.body)
    assert "file_hash" in req_body
    assert "filename" in req_body
    assert "author_name" in req_body
    assert req_body["file_hash"] == test_hash
    assert req_body["filename"] == "report.pdf"
    assert req_body["author_name"] == "Alice"
    assert "fileHash" not in req_body
    assert "fileName" not in req_body


@responses.activate
def test_batch_sends_snake_case_fields():
    responses.add(
        responses.POST,
        f"{BASE}/api/batch",
        json={"results": [], "summary": {"total": 0, "certified": 0, "failed": 0}},
        status=200,
    )
    client = XProofClient(api_key="pm_test")
    client.batch_certify([
        {"file_hash": "a" * 64, "file_name": "a.pdf", "author": "Alice"},
    ])
    req_body = json.loads(responses.calls[0].request.body)
    assert "files" in req_body
    assert req_body["files"][0]["file_hash"] == "a" * 64
    assert req_body["files"][0]["filename"] == "a.pdf"
    assert req_body.get("author_name") == "Alice"
    assert "fileHash" not in req_body["files"][0]
    assert "fileName" not in req_body["files"][0]


@responses.activate
def test_certify_hash_with_4w_metadata():
    responses.add(
        responses.POST,
        f"{BASE}/api/proof",
        json={"id": "p-4w", "fileName": "f", "fileHash": "h", "transactionHash": "t", "transactionUrl": "", "createdAt": ""},
        status=201,
    )
    client = XProofClient(api_key="pm_test")
    client.certify_hash(
        "c" * 64,
        "action.json",
        "agent-x",
        who="erd1abc...",
        what="sha256-of-action",
        when="2026-03-20T12:00:00Z",
        why="sha256-of-instruction",
        metadata={"custom_key": "custom_value"},
    )
    req_body = json.loads(responses.calls[0].request.body)
    assert "metadata" in req_body
    meta = req_body["metadata"]
    assert meta["who"] == "erd1abc..."
    assert meta["what"] == "sha256-of-action"
    assert meta["when"] == "2026-03-20T12:00:00Z"
    assert meta["why"] == "sha256-of-instruction"
    assert meta["custom_key"] == "custom_value"


@responses.activate
def test_certify_hash_without_4w():
    responses.add(
        responses.POST,
        f"{BASE}/api/proof",
        json={"id": "p-no4w", "fileName": "f", "fileHash": "h", "transactionHash": "t", "transactionUrl": "", "createdAt": ""},
        status=201,
    )
    client = XProofClient(api_key="pm_test")
    client.certify_hash("d" * 64, "doc.pdf", "author")
    req_body = json.loads(responses.calls[0].request.body)
    assert "metadata" not in req_body


@responses.activate
def test_no_auth_for_public_endpoints():
    responses.add(
        responses.GET,
        f"{BASE}/api/pricing",
        json={"protocol": "xproof", "version": "1.0", "price_usd": 0.05},
        status=200,
    )
    client = XProofClient()
    client.get_pricing()
    req = responses.calls[0].request
    assert req.headers.get("Authorization", "") == ""


@responses.activate
def test_json_decode_error_raises_xproof_error():
    responses.add(
        responses.POST,
        f"{BASE}/api/proof",
        body="<html>Not Found</html>",
        status=200,
        content_type="text/html",
    )
    client = XProofClient(api_key="pm_test")
    with pytest.raises(XProofError, match="Unexpected non-JSON response"):
        client.certify_hash("e" * 64, "test.pdf", "author")


@responses.activate
def test_verify_hash_uses_correct_endpoint():
    responses.add(
        responses.GET,
        f"{BASE}/api/proof/hash/abc123def",
        json={
            "id": "proof-ep",
            "fileName": "check.pdf",
            "fileHash": "abc123def",
            "transactionHash": "tx-ep",
            "transactionUrl": "",
            "createdAt": "",
        },
        status=200,
    )
    client = XProofClient(api_key="pm_test")
    cert = client.verify_hash("abc123def")
    assert cert.id == "proof-ep"
    assert responses.calls[0].request.url == f"{BASE}/api/proof/hash/abc123def"


# ---------------------------------------------------------------------------
# certify_with_confidence() tests
# ---------------------------------------------------------------------------

CERT_RESPONSE = {
    "id": "proof-cwc",
    "fileName": "analysis.json",
    "fileHash": "a" * 64,
    "transactionHash": "tx-cwc",
    "transactionUrl": "https://explorer.multiversx.com/tx/cwc",
    "createdAt": "2026-04-20T10:00:00Z",
    "authorName": "AgentX",
    "blockchainStatus": "confirmed",
}


@responses.activate
def test_certify_with_confidence_happy_path():
    responses.add(responses.POST, f"{BASE}/api/proof", json=CERT_RESPONSE, status=201)
    client = XProofClient(api_key="pm_test")
    cert = client.certify_with_confidence(
        file_hash="a" * 64,
        file_name="analysis.json",
        author="AgentX",
        confidence_level=0.8,
        threshold_stage="partial",
        decision_id="decision-42",
    )
    assert cert.id == "proof-cwc"
    assert cert.author_name == "AgentX"

    req_body = json.loads(responses.calls[0].request.body)
    assert req_body["filename"] == "analysis.json"
    assert req_body["file_hash"] == "a" * 64
    assert req_body["author_name"] == "AgentX"
    meta = req_body["metadata"]
    assert meta["confidence_level"] == 0.8
    assert meta["threshold_stage"] == "partial"
    assert meta["decision_id"] == "decision-42"


@responses.activate
def test_certify_with_confidence_includes_4w_fields():
    responses.add(responses.POST, f"{BASE}/api/proof", json=CERT_RESPONSE, status=201)
    client = XProofClient(api_key="pm_test")
    client.certify_with_confidence(
        file_hash="b" * 64,
        file_name="plan.json",
        author="AgentY",
        confidence_level=0.6,
        threshold_stage="initial",
        decision_id="decision-99",
        who="erd1agent...",
        what="sha256-of-plan",
        when="2026-04-20T09:00:00Z",
        why="sha256-of-goal",
        metadata={"extra_key": "extra_value"},
    )
    req_body = json.loads(responses.calls[0].request.body)
    meta = req_body["metadata"]
    assert meta["confidence_level"] == 0.6
    assert meta["threshold_stage"] == "initial"
    assert meta["decision_id"] == "decision-99"
    assert meta["who"] == "erd1agent..."
    assert meta["what"] == "sha256-of-plan"
    assert meta["when"] == "2026-04-20T09:00:00Z"
    assert meta["why"] == "sha256-of-goal"
    assert meta["extra_key"] == "extra_value"


@responses.activate
def test_certify_with_confidence_boundary_values():
    responses.add(responses.POST, f"{BASE}/api/proof", json=CERT_RESPONSE, status=201)
    responses.add(responses.POST, f"{BASE}/api/proof", json=CERT_RESPONSE, status=201)
    client = XProofClient(api_key="pm_test")

    cert_min = client.certify_with_confidence(
        file_hash="c" * 64,
        file_name="min.json",
        author="Agent",
        confidence_level=0.0,
        threshold_stage="initial",
        decision_id="dec-min",
    )
    assert cert_min.id == "proof-cwc"
    meta_min = json.loads(responses.calls[0].request.body)["metadata"]
    assert meta_min["confidence_level"] == 0.0

    cert_max = client.certify_with_confidence(
        file_hash="d" * 64,
        file_name="max.json",
        author="Agent",
        confidence_level=1.0,
        threshold_stage="final",
        decision_id="dec-max",
    )
    assert cert_max.id == "proof-cwc"
    meta_max = json.loads(responses.calls[1].request.body)["metadata"]
    assert meta_max["confidence_level"] == 1.0
    assert meta_max["threshold_stage"] == "final"


def test_certify_with_confidence_invalid_confidence_too_low():
    client = XProofClient(api_key="pm_test")
    with pytest.raises(ValueError, match="confidence_level must be between 0.0 and 1.0"):
        client.certify_with_confidence(
            file_hash="e" * 64,
            file_name="f.json",
            author="Agent",
            confidence_level=-0.1,
            threshold_stage="initial",
            decision_id="dec-low",
        )


def test_certify_with_confidence_invalid_confidence_too_high():
    client = XProofClient(api_key="pm_test")
    with pytest.raises(ValueError, match="confidence_level must be between 0.0 and 1.0"):
        client.certify_with_confidence(
            file_hash="f" * 64,
            file_name="f.json",
            author="Agent",
            confidence_level=1.01,
            threshold_stage="final",
            decision_id="dec-high",
        )


def test_certify_with_confidence_invalid_threshold_stage():
    client = XProofClient(api_key="pm_test")
    with pytest.raises(ValueError, match="threshold_stage must be one of"):
        client.certify_with_confidence(
            file_hash="a" * 64,
            file_name="f.json",
            author="Agent",
            confidence_level=0.5,
            threshold_stage="invalid-stage",
            decision_id="dec-stage",
        )


def test_certify_with_confidence_blank_decision_id():
    client = XProofClient(api_key="pm_test")
    with pytest.raises(ValueError, match="decision_id is required"):
        client.certify_with_confidence(
            file_hash="a" * 64,
            file_name="f.json",
            author="Agent",
            confidence_level=0.5,
            threshold_stage="partial",
            decision_id="",
        )


def test_certify_with_confidence_whitespace_decision_id():
    client = XProofClient(api_key="pm_test")
    with pytest.raises(ValueError, match="decision_id is required"):
        client.certify_with_confidence(
            file_hash="a" * 64,
            file_name="f.json",
            author="Agent",
            confidence_level=0.5,
            threshold_stage="partial",
            decision_id="   ",
        )


def test_certify_with_confidence_no_api_key():
    client = XProofClient()
    with pytest.raises(ValueError, match="api_key is required"):
        client.certify_with_confidence(
            file_hash="a" * 64,
            file_name="f.json",
            author="Agent",
            confidence_level=0.5,
            threshold_stage="partial",
            decision_id="dec-nokey",
        )
