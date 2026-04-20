"""Fetch.ai uAgents + xProof: certify every message exchanged between agents.

Incoming and outgoing messages are certified with 4W metadata:
  WHO  = agent name
  WHAT = SHA-256 hash of the message payload
  WHEN = UTC timestamp
  WHY  = "message_received" or "message_sent"

Install:
    pip install xproof uagents

Run:
    python main.py

Production usage:
    from uagents import Agent, Context
    from xproof import XProofClient
    from xproof.integrations.fetchai import XProofuAgentMiddleware, xproof_handler

    client = XProofClient(api_key="pm_...")
    middleware = XProofuAgentMiddleware(
        client=client,
        agent_name="research-agent",
        certify_incoming=True,
        certify_outgoing=True,
    )

    agent = Agent(name="research-agent", seed="my-seed")

    @agent.on_message(model=QueryMessage)
    @xproof_handler(middleware)
    async def handle_query(ctx: Context, sender: str, msg: QueryMessage):
        response = await do_research(msg.query)
        await ctx.send(sender, ResponseMessage(result=response))

    if __name__ == "__main__":
        agent.run()
"""

import json
from unittest.mock import MagicMock

from xproof.integrations.fetchai import XProofuAgentMiddleware, wrap_agent


def make_mock_client():
    client = MagicMock()
    client.certify_hash.return_value = MagicMock(
        id="proof-fa-001",
        file_hash="abc123def456",
        transaction_hash="tx-mvx-001",
    )
    client.batch_certify.return_value = MagicMock(
        batch_id="batch-fa-001",
        summary=MagicMock(total=2, created=2, existing=0),
    )
    return client


def demo_single_certify():
    print("=== Single-message certification ===\n")

    mock_client = make_mock_client()
    middleware = XProofuAgentMiddleware(
        client=mock_client,
        agent_name="research-agent",
        certify_incoming=True,
        certify_outgoing=True,
    )

    print("Incoming message: 'Summarise the Q3 earnings report'")
    middleware.certify_incoming(
        "Summarise the Q3 earnings report",
        sender="agent1",
        context="query_received",
        decision_id="req-001",
    )
    in_kwargs = mock_client.certify_hash.call_args.kwargs
    meta = in_kwargs["metadata"]
    print(f"  proof: {mock_client.certify_hash.return_value.id}")
    print(f"  who:   {meta['who']}")
    print(f"  why:   {meta['why']}")

    print("\nOutgoing response: 'Q3 revenue $4.2M, +15% YoY'")
    middleware.certify_outgoing(
        "Q3 revenue $4.2M, +15% YoY",
        recipient="agent1",
        context="response_sent",
        decision_id="req-001",
    )
    out_kwargs = mock_client.certify_hash.call_args.kwargs
    meta_out = out_kwargs["metadata"]
    print(f"  proof: {mock_client.certify_hash.return_value.id}")
    print(f"  who:   {meta_out['who']}")
    print(f"  why:   {meta_out['why']}")

    print(f"\nTotal certify calls: {mock_client.certify_hash.call_count}")


def demo_batch_mode():
    print("\n=== Batch mode (flush at end of handler) ===\n")

    mock_client = make_mock_client()
    middleware = XProofuAgentMiddleware(
        client=mock_client,
        agent_name="trading-agent",
        certify_incoming=True,
        certify_outgoing=True,
        batch_mode=True,
    )

    print("Queuing 2 certifications...")
    middleware.certify_incoming(
        json.dumps({"ticker": "AAPL", "signal": "buy"}),
        decision_id="trade-001",
        context="signal_received",
    )
    middleware.certify_outgoing(
        json.dumps({"order": "buy", "qty": 100}),
        decision_id="trade-001",
        context="order_sent",
    )

    assert mock_client.certify_hash.call_count == 0, "batch mode should not call certify_hash yet"
    print("  No individual calls made yet (batched)")

    print("Flushing batch...")
    result = middleware.flush()
    print(f"  Batch ID: {result.batch_id if result else 'n/a'}")
    print(f"  Total: {result.summary.total if result else 0} certifications sent")


def demo_runtime_toggle():
    print("\n=== Runtime toggle (disable outgoing mid-session) ===\n")

    mock_client = make_mock_client()
    middleware = XProofuAgentMiddleware(
        client=mock_client,
        agent_name="compliance-agent",
        certify_incoming=True,
        certify_outgoing=True,
    )

    print("Both incoming and outgoing active")
    middleware.certify_incoming("audit request", decision_id="audit-001", context="received")
    middleware.certify_outgoing("audit report", decision_id="audit-001", context="sent")
    print(f"  certify calls: {mock_client.certify_hash.call_count}")

    print("\nDisabling outgoing at runtime...")
    middleware.set_certify_outgoing(False)

    middleware.certify_outgoing("should be skipped", decision_id="audit-002", context="sent")
    print(f"  certify calls after disable: {mock_client.certify_hash.call_count} (same as before)")

    print("\nRe-enabling outgoing...")
    middleware.set_certify_outgoing(True)

    middleware.certify_outgoing("now certified again", decision_id="audit-003", context="sent")
    print(f"  certify calls after re-enable: {mock_client.certify_hash.call_count}")


def demo_wrap_agent():
    print("\n=== wrap_agent() helper ===\n")

    class FakeAgent:
        def __init__(self, name):
            self.name = name

    mock_client = make_mock_client()
    agent = FakeAgent("research-agent")

    middleware = wrap_agent(
        agent,
        client=mock_client,
        certify_incoming=True,
        certify_outgoing=True,
    )

    print(f"Wrapped agent: {agent.name}")
    print(f"Middleware type: {type(middleware).__name__}")

    middleware.certify_incoming(
        "What is the market cap of EGLD?",
        decision_id="query-001",
        context="query_received",
    )
    print(f"  certify call made: {mock_client.certify_hash.called}")


def main():
    demo_single_certify()
    demo_batch_mode()
    demo_runtime_toggle()
    demo_wrap_agent()

    print()
    print("In production, replace make_mock_client() with:")
    print("  from xproof import XProofClient")
    print("  client = XProofClient(api_key='pm_...')")
    print("and attach middleware to your real uAgent handlers.")


if __name__ == "__main__":
    main()
