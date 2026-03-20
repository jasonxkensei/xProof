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
            "results": [
                {
                    "id": "proof-b1",
                    "fileName": "a.pdf",
                    "fileHash": "h1",
                    "transactionHash": "tx1",
                    "transactionUrl": "",
                    "createdAt": "",
                },
                {
                    "id": "proof-b2",
                    "fileName": "b.pdf",
                    "fileHash": "h2",
                    "transactionHash": "tx2",
                    "transactionUrl": "",
                    "createdAt": "",
                },
            ],
            "summary": {"total": 2, "certified": 2, "failed": 0},
        },
        status=200,
    )
    client = XProofClient(api_key="pm_test")
    result = client.batch_certify([
        {"file_hash": "h1", "file_name": "a.pdf", "author": "A"},
        {"file_hash": "h2", "file_name": "b.pdf", "author": "B"},
    ])
    assert result.summary.total == 2
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
        f"{BASE}/api/verify/abc123",
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
