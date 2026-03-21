# xProof Skill for DeerFlow

**xProof as the trust layer for DeerFlow agent outputs.**

[DeerFlow](https://github.com/bytedance/deer-flow) is an extensible super-agent harness. This skill adds blockchain-anchored proof-of-existence to any DeerFlow agent, allowing it to certify its outputs on [MultiversX](https://multiversx.com) with the xProof 4W framework (Who, What, When, Why).

## Why xProof + DeerFlow?

AI agents produce outputs that downstream systems and humans rely on. Without a tamper-proof record, there is no way to verify *what* an agent produced, *when* it produced it, or *who* was responsible.

xProof solves this by anchoring a SHA-256 hash of the agent's output on the MultiversX blockchain. Each certification includes structured 4W metadata:

| Field | Meaning |
|-------|---------|
| **Who** | The agent or role that produced the output |
| **What** | SHA-256 hash of the certified content |
| **When** | ISO 8601 timestamp of certification |
| **Why** | Context or reason for the certification |

## Installation

```bash
pip install xproof
```

## Usage in DeerFlow

### 1. As a Python skill

```python
from xproof.integrations.deerflow import XProofDeerFlowSkill

skill = XProofDeerFlowSkill(api_key="pm_...")

# Certify plain text
result = skill._run("My research findings")

# Certify with metadata
result = skill._run('{"content": "Q3 analysis", "file_name": "q3.json", "why": "Quarterly review"}')
```

### 2. Via the skill definition

Copy `xproof.yaml` into your DeerFlow skills directory. The skill accepts a JSON input with `content` (required), and optional `file_name`, `author`, and `why` fields.

### 3. With the existing LangChain integration

DeerFlow uses LangGraph internally. You can also attach the xProof LangChain callback handler for automatic certification of all LLM calls and tool invocations:

```python
from xproof.integrations.langchain import XProofCallbackHandler

handler = XProofCallbackHandler(api_key="pm_...")
# Pass to your LangGraph/LangChain config
```

## Files

| File | Purpose |
|------|---------|
| `xproof.yaml` | DeerFlow skill definition (copy to skills directory) |
| `main.py` | Demo script showing the skill in action |
| `requirements.txt` | Python dependencies |

## PR Description for bytedance/deer-flow

Below is a ready-to-paste PR description for submitting this skill to the DeerFlow repository:

---

### Add xProof blockchain certification skill

**What:** Adds `xproof_certify` as a native DeerFlow skill that certifies agent outputs on the MultiversX blockchain.

**Why:** AI agents need accountability. xProof provides tamper-proof, blockchain-anchored proof-of-existence for any agent output. Each certification includes structured 4W metadata (Who, What, When, Why) creating an immutable audit trail.

**How it works:**
1. Agent invokes the `xproof_certify` skill with its output content
2. The skill hashes the content (SHA-256), attaches 4W metadata, and submits to the xProof API
3. xProof anchors the hash on MultiversX and returns a `proof_id` and `transaction_hash`
4. The proof can be independently verified at any time via the xProof verification endpoint

**Integration surface:**
- Skill definition: `skills/xproof.yaml`
- Python implementation: `pip install xproof` (the `XProofDeerFlowSkill` class)
- Zero DeerFlow core changes required — uses the standard skill interface

**Links:**
- [xProof website](https://xproof.app)
- [xProof Python SDK](https://github.com/jasonxkensei/xproof)
- [MultiversX blockchain](https://multiversx.com)

---
