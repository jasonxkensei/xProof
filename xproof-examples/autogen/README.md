# AutoGen + xProof

Certify every message exchanged between AutoGen agents on the MultiversX blockchain.

## What gets certified

- **Sent messages** (`process_message_before_send`) — WHO = sender agent name
- **Received messages** (`process_last_received_message`) — WHO = receiver agent name

## Install

```bash
pip install xproof pyautogen
```

## Usage

```python
from autogen import ConversableAgent
from xproof import XProofClient
from xproof.integrations.autogen import register_xproof_hooks

client = XProofClient(api_key="pm_...")   # get key at xproof.app

alice = ConversableAgent(name="alice", ...)
bob   = ConversableAgent(name="bob", ...)

register_xproof_hooks(alice, client=client, agent_name="alice")
register_xproof_hooks(bob,   client=client, agent_name="bob")

# All messages between alice and bob are now certified automatically
alice.initiate_chat(bob, message="Summarise the Q3 earnings report.")
```

## Run the demo

```bash
python main.py
```

No API key or LLM required — the demo uses simulated agents and a mock xProof client.

## Links

- [xproof.app](https://xproof.app)
- Docs (LLM-readable): [xproof.app/llms.txt](https://xproof.app/llms.txt)
- [PyPI: xproof](https://pypi.org/project/xproof)
- [AutoGen](https://github.com/microsoft/autogen)
