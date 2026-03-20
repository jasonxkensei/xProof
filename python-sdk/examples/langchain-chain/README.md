# LangChain + xProof Example

Demonstrates automatic certification of LangChain LLM and tool calls
using the xProof callback handler.

## Setup

```bash
cd python-sdk/examples/langchain-chain
pip install -r requirements.txt
```

## Run

```bash
python main.py
```

The script will:
1. Register a trial xProof agent
2. Simulate LangChain LLM calls with the XProofCallbackHandler
3. Each LLM call is automatically hashed and certified on-chain
4. Show the resulting proof trail with 4W metadata

Each proof is anchored on MultiversX and verifiable at
`https://xproof.app/verify/<proofId>`.
