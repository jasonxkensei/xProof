"""AutoGen + xProof: automatic message certification between agents.

Demonstrates how to attach xProof hooks to AutoGen agents so that every
message exchanged is certified on-chain with 4W metadata (WHO, WHAT,
WHEN, WHY) on MultiversX.

Run: python main.py

Requirements:
    pip install pyautogen xproof

For real usage, attach hooks to agents with a real LLM config and
xProof API key.  This demo uses the standalone XProofAutoGenHooks class
to simulate the flow without requiring a running LLM backend.
"""

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock

from xproof.integrations.autogen import (
    XProofAutoGenHooks,
    register_xproof_hooks,
)


def demo_standalone_hooks():
    """Demo: use XProofAutoGenHooks directly (no pyautogen needed)."""
    print("=== Standalone Hooks Demo ===\n")

    mock_client = MagicMock()
    mock_client.certify_hash.return_value = MagicMock(
        id="proof-123",
        file_hash="abc123",
        transaction_hash="tx-456",
    )

    hooks = XProofAutoGenHooks(
        client=mock_client,
        agent_name="analyst",
        batch_mode=True,
    )

    hooks.on_received("What are the Q3 revenue figures?")
    hooks.on_send("Based on my analysis, Q3 revenue was $4.2M, up 15% YoY.")
    hooks.on_received("Can you break that down by region?")
    hooks.on_send("North America: $2.1M, Europe: $1.3M, Asia: $0.8M.")

    print(f"Buffered {len(hooks._pending)} certifications in batch mode")
    for i, entry in enumerate(hooks._pending, 1):
        meta = entry["metadata"]
        print(f"  {i}. {meta['action_type']}: {meta['who']} ({meta['why']})")

    hooks.flush()
    print(f"\nFlushed. batch_certify called: {mock_client.batch_certify.called}")
    print(f"Certifications sent: {len(mock_client.batch_certify.call_args[0][0])}")


def demo_register_hooks():
    """Demo: use register_xproof_hooks with a fake agent."""
    print("\n=== Register Hooks Demo ===\n")

    class FakeAgent:
        def __init__(self, name):
            self.name = name
            self._hooks = {}

        def register_hook(self, hookable_method, hook):
            self._hooks.setdefault(hookable_method, []).append(hook)
            print(f"  Registered hook: {hookable_method}")

    mock_client = MagicMock()
    mock_client.certify_hash.return_value = MagicMock(
        id="proof-789",
        file_hash="def789",
        transaction_hash="tx-012",
    )

    assistant = FakeAgent("research-assistant")
    print(f"Creating agent: {assistant.name}")
    hooks = register_xproof_hooks(assistant, client=mock_client)
    print()

    recv_hook = assistant._hooks["process_last_received_message"][0]
    msg = recv_hook("Summarise the latest AI safety research.")
    print(f"Received message processed (returned unchanged): {msg[:40]}...")

    send_hook = assistant._hooks["process_message_before_send"][0]
    reply = send_hook("Here is a summary of recent AI safety papers...")
    print(f"Sent message processed (returned unchanged): {reply[:40]}...")

    print(f"\nTotal certify_hash calls: {mock_client.certify_hash.call_count}")


if __name__ == "__main__":
    demo_standalone_hooks()
    demo_register_hooks()
