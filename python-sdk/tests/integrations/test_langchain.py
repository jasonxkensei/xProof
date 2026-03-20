"""Tests for the LangChain xProof callback handler."""

import json
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest


pytest.importorskip("langchain_core", reason="langchain-core not installed")

from xproof.integrations.langchain import XProofCallbackHandler


@pytest.fixture
def mock_client():
    client = MagicMock()
    client.certify_hash.return_value = MagicMock(
        id="proof-lc",
        file_hash="h",
        transaction_hash="tx",
    )
    client.batch_certify.return_value = MagicMock()
    return client


@pytest.fixture
def handler(mock_client):
    return XProofCallbackHandler(client=mock_client, agent_name="test-agent")


def test_llm_end_certifies(handler, mock_client):
    run_id = uuid4()
    handler.on_llm_start(
        {"name": "gpt-4"},
        ["Hello"],
        run_id=run_id,
    )

    response = MagicMock()
    gen = MagicMock()
    gen.text = "Hi there"
    response.generations = [[gen]]

    handler.on_llm_end(response, run_id=run_id)
    mock_client.certify_hash.assert_called_once()

    call_kwargs = mock_client.certify_hash.call_args
    assert call_kwargs.kwargs["author"] == "test-agent"
    assert call_kwargs.kwargs["metadata"]["action_type"] == "llm_call"
    assert call_kwargs.kwargs["metadata"]["who"] == "test-agent"
    assert "when" in call_kwargs.kwargs["metadata"]


def test_tool_end_certifies(handler, mock_client):
    run_id = uuid4()
    handler.on_tool_start(
        {"name": "search"},
        "query text",
        run_id=run_id,
    )
    handler.on_tool_end("search results", run_id=run_id)
    mock_client.certify_hash.assert_called_once()

    call_kwargs = mock_client.certify_hash.call_args
    assert call_kwargs.kwargs["metadata"]["action_type"] == "tool_call"
    assert "tool-search" in call_kwargs.kwargs["file_name"]


def test_chain_events_disabled_by_default(handler, mock_client):
    run_id = uuid4()
    handler.on_chain_start({"name": "agent"}, {"input": "hi"}, run_id=run_id)
    handler.on_chain_end({"output": "bye"}, run_id=run_id)
    mock_client.certify_hash.assert_not_called()


def test_chain_events_when_enabled(mock_client):
    handler = XProofCallbackHandler(
        client=mock_client, agent_name="test-agent", certify_chains=True
    )
    run_id = uuid4()
    handler.on_chain_start({"name": "agent"}, {"input": "hi"}, run_id=run_id)
    handler.on_chain_end({"output": "bye"}, run_id=run_id)
    mock_client.certify_hash.assert_called_once()
    call_kwargs = mock_client.certify_hash.call_args
    assert call_kwargs.kwargs["metadata"]["action_type"] == "chain_completion"


def test_llm_disabled(mock_client):
    handler = XProofCallbackHandler(
        client=mock_client, agent_name="test-agent", certify_llm=False
    )
    run_id = uuid4()
    handler.on_llm_start({"name": "gpt-4"}, ["Hello"], run_id=run_id)

    response = MagicMock()
    response.generations = [[MagicMock(text="Hi")]]
    handler.on_llm_end(response, run_id=run_id)
    mock_client.certify_hash.assert_not_called()


def test_tools_disabled(mock_client):
    handler = XProofCallbackHandler(
        client=mock_client, agent_name="test-agent", certify_tools=False
    )
    run_id = uuid4()
    handler.on_tool_start({"name": "calc"}, "1+1", run_id=run_id)
    handler.on_tool_end("2", run_id=run_id)
    mock_client.certify_hash.assert_not_called()


def test_batch_mode(mock_client):
    handler = XProofCallbackHandler(
        client=mock_client, agent_name="test-agent", batch_mode=True
    )

    run_id1 = uuid4()
    handler.on_tool_start({"name": "search"}, "q", run_id=run_id1)
    handler.on_tool_end("result", run_id=run_id1)

    run_id2 = uuid4()
    handler.on_tool_start({"name": "calc"}, "1+1", run_id=run_id2)
    handler.on_tool_end("2", run_id=run_id2)

    mock_client.certify_hash.assert_not_called()
    assert len(handler._pending) == 2

    handler.flush()
    mock_client.batch_certify.assert_called_once()
    assert len(handler._pending) == 0


def test_4w_metadata_present(handler, mock_client):
    run_id = uuid4()
    handler.on_tool_start({"name": "web_search"}, "test query", run_id=run_id)
    handler.on_tool_end("results", run_id=run_id)

    call_kwargs = mock_client.certify_hash.call_args.kwargs
    meta = call_kwargs["metadata"]
    assert "who" in meta
    assert "what" in meta
    assert "when" in meta
    assert "why" in meta
    assert meta["framework"] == "langchain"
