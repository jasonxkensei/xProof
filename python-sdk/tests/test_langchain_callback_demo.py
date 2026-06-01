"""pytest wrapper — tests examples/langchain-chain/main.py in CI.

Exercises the XProofCallbackHandler callback-handler flow:
- Two LLM calls are simulated with on_llm_start / on_llm_end hooks.
- flush() is called and asserts it returns the expected number of certified
  items.
- The main() entry-point is exercised end-to-end with XProofClient.register
  patched so no real API key or network call is required.

The demo is loaded via importlib because the directory name "langchain-chain"
contains a hyphen that prevents normal package import.
"""

from __future__ import annotations

import importlib.util
import os
import types
import uuid
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip(
    "langchain_core",
    reason="langchain-core not installed; skipping LangChain callback demo tests",
)

from xproof.integrations.langchain import XProofCallbackHandler  # noqa: E402
from xproof.models import BatchResult, BatchResultSummary, Certification  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_certification(proof_id: str, file_hash: str) -> Certification:
    return Certification(
        id=proof_id,
        file_name=f"{proof_id}.json",
        file_hash=file_hash,
        transaction_hash=f"tx-{proof_id}",
        transaction_url="",
        created_at="2026-04-22T09:00:00Z",
    )


def _make_batch_result(certifications: list[Certification]) -> BatchResult:
    return BatchResult(
        batch_id="batch-ci-test",
        results=certifications,
        summary=BatchResultSummary(
            total=len(certifications),
            created=len(certifications),
            existing=0,
        ),
    )


def _make_mock_client(certifications: list[Certification]) -> MagicMock:
    """Return a mock XProofClient pre-wired for the callback handler demo."""
    mock = MagicMock()
    mock.api_key = "pm_test_ci"
    mock.batch_certify.return_value = _make_batch_result(certifications)
    mock.verify.side_effect = lambda proof_id: next(
        (c for c in certifications if c.id == proof_id), certifications[0]
    )
    mock.registration.api_key = "pm_test_ci_key"
    mock.registration.trial.remaining = 10
    return mock


def _load_main() -> types.ModuleType:
    """Load main.py from the langchain-chain examples directory via importlib."""
    sdk_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    demo_path = os.path.join(sdk_root, "examples", "langchain-chain", "main.py")
    spec = importlib.util.spec_from_file_location("langchain_chain_main", demo_path)
    assert spec is not None and spec.loader is not None, (
        f"Could not load module spec from {demo_path}"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


_main_module = _load_main()


# ---------------------------------------------------------------------------
# Direct handler tests (no importlib required)
# ---------------------------------------------------------------------------

def _make_llm_response(text: str) -> object:
    """Build the minimal LangChain-style LLM response object the handler reads."""
    Gen = type("Gen", (), {"text": text})
    return type(
        "Response",
        (),
        {
            "generations": [[Gen()]],
            "llm_output": {"model_name": "gpt-4"},
        },
    )()


def test_flush_returns_all_certified_items() -> None:
    """flush() returns one Certification per LLM call after two on_llm_end events."""
    cert_1 = _make_certification("proof-001", "a" * 64)
    cert_2 = _make_certification("proof-002", "b" * 64)
    mock_client = _make_mock_client([cert_1, cert_2])

    handler = XProofCallbackHandler(
        client=mock_client,
        agent_name="ci-test-agent",
        batch_mode=True,
    )

    run_id_1 = uuid.uuid4()
    handler.on_llm_start(
        serialized={"name": "ChatOpenAI"},
        prompts=["What is the capital of France?"],
        run_id=run_id_1,
        parent_run_id=None,
    )
    handler.on_llm_end(
        response=_make_llm_response("Paris is the capital of France."),
        run_id=run_id_1,
    )

    run_id_2 = uuid.uuid4()
    handler.on_llm_start(
        serialized={"name": "ChatOpenAI"},
        prompts=["Translate 'hello' to Spanish"],
        run_id=run_id_2,
        parent_run_id=None,
    )
    handler.on_llm_end(
        response=_make_llm_response("Hola"),
        run_id=run_id_2,
    )

    results = handler.flush()

    assert len(results) == 2
    mock_client.batch_certify.assert_called_once()


def test_flush_returns_empty_list_when_no_pending() -> None:
    """flush() returns [] when called with no queued LLM calls."""
    mock_client = _make_mock_client([])

    handler = XProofCallbackHandler(
        client=mock_client,
        agent_name="ci-test-agent",
        batch_mode=True,
    )

    results = handler.flush()

    assert results == []
    mock_client.batch_certify.assert_not_called()


def test_flush_result_items_have_id_and_file_hash() -> None:
    """Each item returned by flush() exposes .id and .file_hash attributes."""
    cert = _make_certification("proof-xyz", "c" * 64)
    mock_client = _make_mock_client([cert])

    handler = XProofCallbackHandler(
        client=mock_client,
        agent_name="ci-test-agent",
        batch_mode=True,
    )

    run_id = uuid.uuid4()
    handler.on_llm_start(
        serialized={"name": "ChatOpenAI"},
        prompts=["Test prompt"],
        run_id=run_id,
        parent_run_id=None,
    )
    handler.on_llm_end(
        response=_make_llm_response("Test response"),
        run_id=run_id,
    )

    results = handler.flush()

    assert len(results) == 1
    assert results[0].id == "proof-xyz"
    assert results[0].file_hash == "c" * 64


# ---------------------------------------------------------------------------
# Integration test via main() with patched XProofClient.register
# ---------------------------------------------------------------------------

def test_main_runs_end_to_end() -> None:
    """main() completes without error when XProofClient.register is patched."""
    cert_1 = _make_certification("proof-main-1", "d" * 64)
    cert_2 = _make_certification("proof-main-2", "e" * 64)
    mock_client = _make_mock_client([cert_1, cert_2])

    with patch("xproof.XProofClient.register", return_value=mock_client):
        _main_module.main()

    mock_client.batch_certify.assert_called_once()
    assert mock_client.verify.call_count == 2
