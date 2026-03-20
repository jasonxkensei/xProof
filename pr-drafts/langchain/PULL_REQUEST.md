# PR: Add xProof callback handler integration

**Target repo:** `langchain-ai/langchain`
**Target branch:** `master`
**File to add:** `docs/docs/integrations/callbacks/xproof.mdx`

---

## PR Title
`docs: add xProof blockchain certification callback handler`

## PR Body

### Description

This PR adds documentation for the [xProof](https://xproof.app) callback handler — a proof and accountability layer for LangChain agents.

`XProofCallbackHandler` automatically certifies LLM inputs, outputs, and tool calls on the MultiversX blockchain, giving every agent action a tamper-proof, verifiable audit trail.

### What it does

- Intercepts `on_llm_start` / `on_llm_end` / `on_tool_start` / `on_tool_end` / `on_chain_start` / `on_chain_end`
- Hashes prompt + output locally (SHA-256), sends only the hash to xProof API
- Anchors a proof on-chain with optional 4W metadata (WHO/WHAT/WHEN/WHY)
- Zero PII sent — content never leaves the developer's environment

### Install

```bash
pip install xproof
```

### Checklist
- [x] Documentation added
- [x] Code example tested
- [x] No PII in examples
- [x] Free tier available (10 certs/day, no credit card)
