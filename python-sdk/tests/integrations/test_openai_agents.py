"""Tests for the OpenAI Agents SDK xProof integration."""

import asyncio
import hashlib
import json
from unittest.mock import MagicMock

import pytest

from xproof.integrations.openai_agents import (
    XProofRunHooks,
    XProofTracingProcessor,
    _hash_data,
)


def _run(coro):
    """Helper to run an async coroutine synchronously."""
    return asyncio.get_event_loop().run_until_complete(coro)


@pytest.fixture
def mock_client():
    client = MagicMock()
    client.certify_hash.return_value = MagicMock(
        id="proof-oai",
        file_hash="h",
        transaction_hash="tx",
    )
    client.batch_certify.return_value = MagicMock()
    return client


@pytest.fixture
def hooks(mock_client):
    return XProofRunHooks(client=mock_client, agent_name="test-agent")


class FakeAgent:
    def __init__(self, name="test-agent"):
        self.name = name


class FakeTool:
    def __init__(self, name="calculator"):
        self.name = name


class FakeContext:
    pass


def test_tool_end_certifies(hooks, mock_client):
    ctx = FakeContext()
    agent = FakeAgent()
    tool = FakeTool("web_search")

    _run(hooks.on_tool_end(ctx, agent, tool, "search results"))
    mock_client.certify_hash.assert_called_once()

    call_kwargs = mock_client.certify_hash.call_args.kwargs
    assert call_kwargs["metadata"]["action_type"] == "tool_end"
    assert call_kwargs["metadata"]["framework"] == "openai-agents"
    assert "tool-web_search" in call_kwargs["file_name"]


def test_tool_end_hash_includes_output(hooks, mock_client):
    ctx = FakeContext()
    agent = FakeAgent("analyst")
    tool = FakeTool("calculator")

    _run(hooks.on_tool_end(ctx, agent, tool, "42"))
    call_kwargs = mock_client.certify_hash.call_args.kwargs

    expected_hash = _hash_data({
        "tool": "calculator",
        "agent": "analyst",
        "output": "42",
    })
    assert call_kwargs["file_hash"] == expected_hash


def test_agent_end_certifies(hooks, mock_client):
    ctx = FakeContext()
    agent = FakeAgent("researcher")

    _run(hooks.on_agent_end(ctx, agent, "Final analysis report"))
    mock_client.certify_hash.assert_called_once()

    call_kwargs = mock_client.certify_hash.call_args.kwargs
    assert call_kwargs["metadata"]["action_type"] == "agent_end"
    assert call_kwargs["metadata"]["framework"] == "openai-agents"
    assert "agent-researcher" in call_kwargs["file_name"]


def test_agent_end_hash_includes_output(hooks, mock_client):
    ctx = FakeContext()
    agent = FakeAgent("writer")

    _run(hooks.on_agent_end(ctx, agent, "Draft complete"))
    call_kwargs = mock_client.certify_hash.call_args.kwargs

    expected_hash = _hash_data({
        "agent": "writer",
        "output": "Draft complete",
    })
    assert call_kwargs["file_hash"] == expected_hash


def test_tool_disabled(mock_client):
    hooks = XProofRunHooks(
        client=mock_client, agent_name="test-agent", certify_tools=False
    )
    _run(hooks.on_tool_end(FakeContext(), FakeAgent(), FakeTool(), "result"))
    mock_client.certify_hash.assert_not_called()


def test_agent_disabled(mock_client):
    hooks = XProofRunHooks(
        client=mock_client, agent_name="test-agent", certify_agent=False
    )
    _run(hooks.on_agent_end(FakeContext(), FakeAgent(), "output"))
    mock_client.certify_hash.assert_not_called()


def test_4w_metadata_present(hooks, mock_client):
    _run(hooks.on_tool_end(FakeContext(), FakeAgent(), FakeTool(), "result"))

    call_kwargs = mock_client.certify_hash.call_args.kwargs
    meta = call_kwargs["metadata"]
    assert meta["who"] == "test-agent"
    assert "what" in meta
    assert "when" in meta
    assert "why" in meta
    assert meta["framework"] == "openai-agents"


def test_batch_mode_manual_flush(mock_client):
    hooks = XProofRunHooks(
        client=mock_client, agent_name="test-agent", batch_mode=True
    )

    _run(hooks.on_tool_end(FakeContext(), FakeAgent(), FakeTool("t1"), "r1"))
    _run(hooks.on_tool_end(FakeContext(), FakeAgent(), FakeTool("t2"), "r2"))

    mock_client.certify_hash.assert_not_called()
    assert len(hooks._pending) == 2

    hooks.flush()
    mock_client.batch_certify.assert_called_once()
    assert len(hooks._pending) == 0


def test_batch_mode_auto_flush_on_agent_end(mock_client):
    hooks = XProofRunHooks(
        client=mock_client, agent_name="test-agent", batch_mode=True
    )

    _run(hooks.on_tool_end(FakeContext(), FakeAgent(), FakeTool(), "r1"))
    mock_client.certify_hash.assert_not_called()
    assert len(hooks._pending) == 1

    _run(hooks.on_agent_end(FakeContext(), FakeAgent(), "final"))
    mock_client.batch_certify.assert_called_once()
    assert len(hooks._pending) == 0


def test_batch_flush_empty(mock_client):
    hooks = XProofRunHooks(
        client=mock_client, agent_name="test-agent", batch_mode=True
    )
    hooks.flush()
    mock_client.batch_certify.assert_not_called()


def test_agent_name_from_agent_object(mock_client):
    hooks = XProofRunHooks(client=mock_client, agent_name="default")
    agent = FakeAgent("custom-agent")
    _run(hooks.on_agent_end(FakeContext(), agent, "output"))

    call_kwargs = mock_client.certify_hash.call_args.kwargs
    assert "agent-custom-agent" in call_kwargs["file_name"]


def test_on_agent_start_noop(hooks, mock_client):
    _run(hooks.on_agent_start(FakeContext(), FakeAgent()))
    mock_client.certify_hash.assert_not_called()


def test_on_tool_start_noop(hooks, mock_client):
    _run(hooks.on_tool_start(FakeContext(), FakeAgent(), FakeTool()))
    mock_client.certify_hash.assert_not_called()


def test_on_handoff_noop(hooks, mock_client):
    _run(hooks.on_handoff(FakeContext(), FakeAgent("a"), FakeAgent("b")))
    mock_client.certify_hash.assert_not_called()


class TestTracingProcessor:
    @pytest.fixture
    def processor(self, mock_client):
        return XProofTracingProcessor(client=mock_client, agent_name="trace-agent")

    def _make_span(self, kind, name="test", output="result"):
        span_data = MagicMock()
        span_data.type = kind
        span_data.name = name
        span_data.output = output
        span = MagicMock()
        span.span_data = span_data
        span.span_id = "span-123"
        return span

    def test_tool_span_certifies(self, processor, mock_client):
        span = self._make_span("tool", name="calculator", output="42")
        processor.on_span_end(span)
        mock_client.certify_hash.assert_called_once()

        call_kwargs = mock_client.certify_hash.call_args.kwargs
        assert call_kwargs["metadata"]["action_type"] == "tool_span_end"
        assert "span-tool-calculator" in call_kwargs["file_name"]

    def test_agent_span_certifies(self, processor, mock_client):
        span = self._make_span("agent", name="researcher", output="report")
        processor.on_span_end(span)
        mock_client.certify_hash.assert_called_once()

        call_kwargs = mock_client.certify_hash.call_args.kwargs
        assert call_kwargs["metadata"]["action_type"] == "agent_span_end"
        assert "span-agent-researcher" in call_kwargs["file_name"]

    def test_unknown_span_ignored(self, processor, mock_client):
        span = self._make_span("llm", name="gpt-4", output="hello")
        processor.on_span_end(span)
        mock_client.certify_hash.assert_not_called()

    def test_tool_span_disabled(self, mock_client):
        processor = XProofTracingProcessor(
            client=mock_client, certify_tool_spans=False
        )
        span = self._make_span("tool", name="calc")
        processor.on_span_end(span)
        mock_client.certify_hash.assert_not_called()

    def test_agent_span_disabled(self, mock_client):
        processor = XProofTracingProcessor(
            client=mock_client, certify_agent_spans=False
        )
        span = self._make_span("agent", name="writer")
        processor.on_span_end(span)
        mock_client.certify_hash.assert_not_called()

    def test_4w_metadata_present(self, processor, mock_client):
        span = self._make_span("tool", name="search")
        processor.on_span_end(span)

        call_kwargs = mock_client.certify_hash.call_args.kwargs
        meta = call_kwargs["metadata"]
        assert meta["who"] == "trace-agent"
        assert "what" in meta
        assert "when" in meta
        assert "why" in meta
        assert meta["framework"] == "openai-agents"

    def test_span_without_data_ignored(self, processor, mock_client):
        span = MagicMock()
        span.span_data = None
        processor.on_span_end(span)
        mock_client.certify_hash.assert_not_called()

    def test_on_span_start_noop(self, processor, mock_client):
        span = self._make_span("tool")
        processor.on_span_start(span)
        mock_client.certify_hash.assert_not_called()

    def test_force_flush_noop(self, processor, mock_client):
        processor.force_flush()
        mock_client.certify_hash.assert_not_called()

    def test_shutdown_noop(self, processor, mock_client):
        processor.shutdown()
        mock_client.certify_hash.assert_not_called()
