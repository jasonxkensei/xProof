"""AutoGen integration for automatic xProof certification.

Provides hook helpers and an optional ConversableAgent subclass that
auto-certify messages exchanged between AutoGen agents on-chain using
the xProof 4W framework (Who, What, When, Why).

Targets AutoGen 0.2.x (pyautogen). AutoGen 0.4.x event-driven
architecture is out of scope.
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

from ..client import XProofClient


def _hash_data(data: Any) -> str:
    serialized = json.dumps(data, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode()).hexdigest()


def _extract_text(message: Any) -> str:
    """Extract text content from an AutoGen message.

    AutoGen messages can be strings, dicts with a ``content`` key, or
    other structures.  This helper normalises them to a plain string.
    """
    if isinstance(message, str):
        return message
    if isinstance(message, dict):
        return str(message.get("content", message))
    return str(message)


class XProofAutoGenHooks:
    """Manages xProof certification hooks for an AutoGen agent.

    Use :func:`register_xproof_hooks` for a one-liner setup, or
    instantiate this class directly for more control.

    Example::

        from xproof.integrations.autogen import XProofAutoGenHooks

        hooks = XProofAutoGenHooks(api_key="pm_...")
        agent.register_hook("process_last_received_message", hooks.on_received)

    """

    def __init__(
        self,
        api_key: str = "",
        client: Optional[XProofClient] = None,
        agent_name: str = "autogen-agent",
        certify_received: bool = True,
        certify_sent: bool = True,
        batch_mode: bool = False,
    ) -> None:
        self.client = client or XProofClient(api_key=api_key)
        self.agent_name = agent_name
        self.certify_received = certify_received
        self.certify_sent = certify_sent
        self.batch_mode = batch_mode
        self._pending: List[Dict[str, Any]] = []

    def _certify(
        self,
        action_type: str,
        data_hash: str,
        file_name: str,
        context: str = "",
    ) -> None:
        entry = {
            "file_hash": data_hash,
            "file_name": file_name,
            "author": self.agent_name,
            "metadata": {
                "who": self.agent_name,
                "what": data_hash,
                "when": datetime.now(timezone.utc).isoformat(),
                "why": context or action_type,
                "action_type": action_type,
                "framework": "autogen",
            },
        }

        if self.batch_mode:
            self._pending.append(entry)
        else:
            self.client.certify_hash(
                file_hash=entry["file_hash"],
                file_name=entry["file_name"],
                author=entry["author"],
                metadata=entry["metadata"],
            )

    def flush(self) -> None:
        """Send all pending certifications in a batch."""
        if not self._pending:
            return
        self.client.batch_certify(self._pending)
        self._pending.clear()

    def on_received(self, message: Any) -> Any:
        """Hook for ``process_last_received_message``.

        Certifies the incoming message content and returns it unchanged
        so the agent can continue processing.
        """
        if self.certify_received:
            text = _extract_text(message)
            data_hash = _hash_data({"direction": "received", "content": text})
            self._certify(
                action_type="message_received",
                data_hash=data_hash,
                file_name=f"msg-recv-{self.agent_name}-{data_hash[:8]}.json",
                context=f"Message received by {self.agent_name}",
            )
        return message

    def on_send(self, message: Any, *args: Any, **kwargs: Any) -> Any:
        """Hook for ``process_message_before_send``.

        Certifies the outgoing message content and returns it unchanged.
        Accepts extra positional args (``recipient``, ``silent``) that
        newer pyautogen releases pass to the hook callback.
        """
        if self.certify_sent:
            text = _extract_text(message)
            data_hash = _hash_data({"direction": "sent", "content": text})
            self._certify(
                action_type="message_sent",
                data_hash=data_hash,
                file_name=f"msg-sent-{self.agent_name}-{data_hash[:8]}.json",
                context=f"Message sent by {self.agent_name}",
            )
        return message


def register_xproof_hooks(
    agent: Any,
    api_key: str = "",
    client: Optional[XProofClient] = None,
    agent_name: Optional[str] = None,
    certify_received: bool = True,
    certify_sent: bool = True,
    batch_mode: bool = False,
) -> "XProofAutoGenHooks":
    """Register xProof certification hooks on an AutoGen agent.

    This is the recommended one-liner for adding xProof certification to
    any ``ConversableAgent`` (or subclass such as ``AssistantAgent`` or
    ``UserProxyAgent``).

    Args:
        agent: An AutoGen ``ConversableAgent`` instance.
        api_key: xProof API key (ignored if *client* is provided).
        client: Pre-configured :class:`~xproof.client.XProofClient`.
        agent_name: Name used in 4W metadata. Defaults to ``agent.name``.
        certify_received: Certify incoming messages (default ``True``).
        certify_sent: Certify outgoing messages (default ``True``).
        batch_mode: Buffer certifications for batch sending (default ``False``).

    Returns:
        The :class:`XProofAutoGenHooks` instance (useful for calling
        :meth:`~XProofAutoGenHooks.flush` in batch mode).

    Example::

        from autogen import AssistantAgent
        from xproof.integrations.autogen import register_xproof_hooks

        assistant = AssistantAgent("analyst", llm_config={...})
        hooks = register_xproof_hooks(assistant, api_key="pm_...")
    """
    name = agent_name or getattr(agent, "name", "autogen-agent")
    hooks = XProofAutoGenHooks(
        api_key=api_key,
        client=client,
        agent_name=name,
        certify_received=certify_received,
        certify_sent=certify_sent,
        batch_mode=batch_mode,
    )

    agent.register_hook(
        hookable_method="process_last_received_message",
        hook=hooks.on_received,
    )

    agent.register_hook(
        hookable_method="process_message_before_send",
        hook=hooks.on_send,
    )

    return hooks


try:
    from autogen import ConversableAgent as _ConversableAgent
except ImportError:
    _ConversableAgent = None

if _ConversableAgent is not None:

    class XProofConversableAgent(_ConversableAgent):
        """AutoGen ``ConversableAgent`` with built-in xProof certification.

        Requires the ``pyautogen`` package. On init, automatically registers
        hooks that certify all incoming and outgoing messages on-chain.

        Example::

            from xproof.integrations.autogen import XProofConversableAgent

            agent = XProofConversableAgent(
                "analyst",
                llm_config={...},
                xproof_api_key="pm_...",
            )
        """

        def __init__(
            self,
            name: str,
            xproof_api_key: str = "",
            xproof_client: Optional[XProofClient] = None,
            certify_received: bool = True,
            certify_sent: bool = True,
            xproof_batch_mode: bool = False,
            **kwargs: Any,
        ) -> None:
            super().__init__(name, **kwargs)
            self.xproof_hooks = register_xproof_hooks(
                agent=self,
                api_key=xproof_api_key,
                client=xproof_client,
                agent_name=name,
                certify_received=certify_received,
                certify_sent=certify_sent,
                batch_mode=xproof_batch_mode,
            )
