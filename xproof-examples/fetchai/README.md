# Fetch.ai uAgents + xProof

Certify every message your uAgent sends or receives — tamper-proof, on-chain, in ~6 seconds.

## What gets certified

| Event | WHO | WHAT | WHY |
|-------|-----|------|-----|
| Incoming message | Agent name | SHA-256 of payload | `"message_received"` |
| Outgoing response | Agent name | SHA-256 of payload | `"message_sent"` |

## Install

```bash
pip install xproof uagents
```

Get an xProof API key at **[xproof.app](https://xproof.app)**.

## Quickstart — decorator pattern

```python
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
```

## Quickstart — manual certification

```python
from xproof import XProofClient
from xproof.integrations.fetchai import XProofuAgentMiddleware

client = XProofClient(api_key="pm_...")
middleware = XProofuAgentMiddleware(
    client=client,
    agent_name="my-agent",
)

# Inside your handler:
middleware.certify_incoming(
    message=msg.payload,
    decision_id=ctx.session,
    context="message_received",
)
```

## Batch mode

Collect certifications and flush them at the end of a handler cycle to reduce latency:

```python
middleware = XProofuAgentMiddleware(
    client=client,
    agent_name="my-agent",
    batch_mode=True,
)

# After handling the request:
middleware.flush()
```

## Runtime toggles

Enable or disable incoming/outgoing certification at runtime without recreating the middleware:

```python
# Pause outgoing certification (e.g. during maintenance)
middleware.set_certify_outgoing(False)

# Resume
middleware.set_certify_outgoing(True)
```

## Run the demo

```bash
python main.py
```

The demo simulates an agent session using a mock client — no real API key or uAgents installation required to run.

## Links

- [xproof.app](https://xproof.app)
- [PyPI: xproof](https://pypi.org/project/xproof/)
- [Fetch.ai uAgents docs](https://docs.fetch.ai/uagents/)
