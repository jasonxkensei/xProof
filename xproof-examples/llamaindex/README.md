# LlamaIndex + xProof

Certify every LLM call and query completion in your LlamaIndex pipeline.

## What gets certified

- `CBEventType.LLM` end events — LLM responses
- `CBEventType.QUERY` end events — query completions

Each certification records WHO (your agent name), WHAT (SHA-256 of the response), WHEN, and WHY.

## Install

```bash
pip install xproof llama-index-core
```

## Usage

```python
from llama_index.core.callbacks import CallbackManager
from xproof import XProofClient
from xproof.integrations.llamaindex import XProofCallbackHandler

client = XProofClient(api_key="pm_...")
handler = XProofCallbackHandler(client=client, agent_name="my-agent")
callback_manager = CallbackManager([handler])

# Attach to your query engine
query_engine = index.as_query_engine(callback_manager=callback_manager)
response = query_engine.query("What is the market outlook for 2025?")
```

Certifications are sent at the end of each trace (on `end_trace`).

## Run the demo

```bash
python main.py
```

No API key required — registers a free trial account automatically.

## Links

- [xproof.app](https://xproof.app)
- Docs (LLM-readable): [xproof.app/llms.txt](https://xproof.app/llms.txt)
- [PyPI: xproof](https://pypi.org/project/xproof)
