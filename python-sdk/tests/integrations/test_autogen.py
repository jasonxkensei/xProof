"""Tests for the AutoGen xProof integration."""

import json
import hashlib
from unittest.mock import MagicMock, call
from typing import Any

import pytest

from xproof.integrations.autogen import (
    XProofAutoGenHooks,
    register_xproof_hooks,
    _extract_text,
    _hash_data,
)


@pytest.fixture
def mock_client():
    client = MagicMock()
    client.certify_hash.return_value = MagicMock(
        id="proof-ag",
        file_hash="h",
        transaction_hash="tx",
    )
    client.batch_certify.return_value = MagicMock()
    return client


@pytest.fixture
def hooks(mock_client):
    return XProofAutoGenHooks(client=mock_client, agent_name="test-agent")


class FakeAgent:
    """Minimal mock of autogen.ConversableAgent for testing."""

    def __init__(self, name: str = "fake-agent"):
        self.name = name
        self._hooks: dict = {}

    def register_hook(self, hookable_method: str, hook: Any) -> None:
        self._hooks.setdefault(hookable_method, []).append(hook)


def test_on_received_certifies(hooks, mock_client):
    result = hooks.on_received("Hello from user")

    assert result == "Hello from user"
    mock_client.certify_hash.assert_called_once()

    call_kwargs = mock_client.certify_hash.call_args.kwargs
    assert call_kwargs["author"] == "test-agent"
    assert call_kwargs["metadata"]["action_type"] == "message_received"
    assert call_kwargs["metadata"]["framework"] == "autogen"


def test_on_sent_certifies(hooks, mock_client):
    result = hooks.on_send("Reply from agent")

    assert result == "Reply from agent"
    mock_client.certify_hash.assert_called_once()

    call_kwargs = mock_client.certify_hash.call_args.kwargs
    assert call_kwargs["metadata"]["action_type"] == "message_sent"
    assert call_kwargs["metadata"]["framework"] == "autogen"


def test_on_received_dict_message(hooks, mock_client):
    msg = {"content": "structured message", "role": "user"}
    result = hooks.on_received(msg)

    assert result == msg
    mock_client.certify_hash.assert_called_once()

    call_kwargs = mock_client.certify_hash.call_args.kwargs
    expected_hash = _hash_data({"direction": "received", "content": "structured message"})
    assert call_kwargs["file_hash"] == expected_hash


def test_on_received_returns_message_unchanged(hooks, mock_client):
    msg = {"content": "important data", "metadata": {"key": "value"}}
    result = hooks.on_received(msg)
    assert result is msg


def test_on_sent_returns_message_unchanged(hooks, mock_client):
    msg = "outgoing message"
    result = hooks.on_send(msg)
    assert result is msg


def test_received_disabled(mock_client):
    hooks = XProofAutoGenHooks(
        client=mock_client, agent_name="test-agent", certify_received=False
    )
    hooks.on_received("Hello")
    mock_client.certify_hash.assert_not_called()


def test_sent_disabled(mock_client):
    hooks = XProofAutoGenHooks(
        client=mock_client, agent_name="test-agent", certify_sent=False
    )
    hooks.on_send("Reply")
    mock_client.certify_hash.assert_not_called()


def test_4w_metadata_present(hooks, mock_client):
    hooks.on_received("test message")

    call_kwargs = mock_client.certify_hash.call_args.kwargs
    meta = call_kwargs["metadata"]
    assert meta["who"] == "test-agent"
    assert "what" in meta
    assert "when" in meta
    assert "why" in meta
    assert meta["framework"] == "autogen"


def test_hash_includes_direction(hooks, mock_client):
    hooks.on_received("same text")
    recv_hash = mock_client.certify_hash.call_args.kwargs["file_hash"]
    mock_client.reset_mock()

    hooks.on_send("same text")
    send_hash = mock_client.certify_hash.call_args.kwargs["file_hash"]

    assert recv_hash != send_hash


def test_batch_mode_manual_flush(mock_client):
    hooks = XProofAutoGenHooks(
        client=mock_client, agent_name="test-agent", batch_mode=True
    )

    hooks.on_received("msg 1")
    hooks.on_send("msg 2")

    mock_client.certify_hash.assert_not_called()
    assert len(hooks._pending) == 2

    hooks.flush()
    mock_client.batch_certify.assert_called_once()
    assert len(hooks._pending) == 0


def test_batch_mode_flush_empty(mock_client):
    hooks = XProofAutoGenHooks(
        client=mock_client, agent_name="test-agent", batch_mode=True
    )
    hooks.flush()
    mock_client.batch_certify.assert_not_called()


def test_register_xproof_hooks_positional_client(mock_client):
    agent = FakeAgent(name="positional")
    hooks = register_xproof_hooks(agent, mock_client)

    assert hooks.agent_name == "positional"
    recv_hook = agent._hooks["process_last_received_message"][0]
    recv_hook("hello")
    mock_client.certify_hash.assert_called_once()


def test_register_xproof_hooks(mock_client):
    agent = FakeAgent(name="analyst")
    hooks = register_xproof_hooks(agent, client=mock_client)

    assert hooks.agent_name == "analyst"
    assert "process_last_received_message" in agent._hooks
    assert len(agent._hooks["process_last_received_message"]) == 1

    recv_hook = agent._hooks["process_last_received_message"][0]
    result = recv_hook("test input")
    assert result == "test input"
    mock_client.certify_hash.assert_called_once()


def test_register_xproof_hooks_custom_name(mock_client):
    agent = FakeAgent(name="default-name")
    hooks = register_xproof_hooks(
        agent, client=mock_client, agent_name="custom-name"
    )
    assert hooks.agent_name == "custom-name"


def test_register_xproof_hooks_sends_hook(mock_client):
    agent = FakeAgent(name="sender")
    hooks = register_xproof_hooks(agent, client=mock_client)

    assert "process_message_before_send" in agent._hooks
    send_hook = agent._hooks["process_message_before_send"][0]
    result = send_hook("outgoing")
    assert result == "outgoing"

    call_kwargs = mock_client.certify_hash.call_args.kwargs
    assert call_kwargs["metadata"]["action_type"] == "message_sent"


def test_extract_text_str():
    assert _extract_text("hello") == "hello"


def test_extract_text_dict():
    assert _extract_text({"content": "hello", "role": "user"}) == "hello"


def test_extract_text_dict_no_content():
    result = _extract_text({"role": "user"})
    assert "role" in result


def test_extract_text_other():
    assert _extract_text(42) == "42"


def test_on_send_with_extra_positional_args(hooks, mock_client):
    result = hooks.on_send("Reply", "recipient_agent", False)

    assert result == "Reply"
    mock_client.certify_hash.assert_called_once()
    call_kwargs = mock_client.certify_hash.call_args.kwargs
    assert call_kwargs["metadata"]["action_type"] == "message_sent"


def test_file_name_format(hooks, mock_client):
    hooks.on_received("test")
    call_kwargs = mock_client.certify_hash.call_args.kwargs
    assert call_kwargs["file_name"].startswith("msg-recv-test-agent-")
    assert call_kwargs["file_name"].endswith(".json")

    mock_client.reset_mock()
    hooks.on_send("test")
    call_kwargs = mock_client.certify_hash.call_args.kwargs
    assert call_kwargs["file_name"].startswith("msg-sent-test-agent-")
