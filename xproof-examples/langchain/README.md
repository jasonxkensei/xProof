# LangChain + xProof

Certify every LLM call in your LangChain application with a tamper-proof blockchain record.

## What gets certified

Each `on_llm_end` event produces one certification with:
- **WHO** — your agent name
- **WHAT** — SHA-256 hash of the LLM response
- **WHEN** — UTC timestamp
- **WHY** — `"llm_response"` (configurable)

## Install

```bash
pip install xproof langchain-core
```

## Usage

```python
from xproof import XProofClient
from xproof.integrations.langchain import XProofCallbackHandler

client = XProofClient(api_key="pm_...")   # get key at xproof.app
handler = XProofCallbackHandler(client=client, agent_name="my-agent")

# Attach to any LangChain chain or LLM
chain = your_chain.with_config(callbacks=[handler])
result = chain.invoke({"input": "Summarise Q3 earnings"})
```

For batch certification (send multiple proofs in one API call):

```python
handler = XProofCallbackHandler(client=client, agent_name="my-agent", batch_mode=True)
# ... run your chain ...
handler.flush()   # send all buffered certifications
```

## Run the demo

```bash
python main.py
```

No API key required for the demo — it registers a free trial account automatically.

## Verify a proof

Every certification is publicly verifiable:

```
https://xproof.app/verify/<proof_id>
```

## Links

- [xproof.app](https://xproof.app)
- Docs (LLM-readable): [xproof.app/llms.txt](https://xproof.app/llms.txt)
- [PyPI: xproof](https://pypi.org/project/xproof)
