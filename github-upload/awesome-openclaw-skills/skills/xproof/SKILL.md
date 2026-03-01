---
name: xproof
---

# xProof

Pre-execution cryptographic enforcement for autonomous agents. Anchor file proofs and agent decisions on MultiversX before execution. No proof = no action.

## Quick Start

```bash
# Certify a file
FILE_HASH=$(sha256sum output.pdf | awk '{print $1}')
curl -s -X POST https://xproof.app/api/proof \
  -H "Content-Type: application/json" \
  -d "{\"file_hash\": \"$FILE_HASH\", \"filename\": \"output.pdf\"}"

# Audit before executing a critical action
curl -s -X POST https://xproof.app/api/audit \
  -H "Authorization: Bearer $XPROOF_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"my-agent","session_id":"uuid","action_type":"trade","action_description":"Buy 10 EGLD","inputs_hash":"'$INPUTS_HASH'","risk_level":"high","decision":"approved"}'
```

## What It Does

- Anchors SHA-256 file hashes on MultiversX as immutable proof of existence and ownership
- Certifies agent decisions on-chain BEFORE executing critical actions (trade, deploy, transfer)
- Batch certification up to 50 files per call
- x402 payment protocol — no account needed, pay per request in USDC on Base
- If audit call fails or returns no proof_id, agent MUST stop. No fallback.

## When to Use

- Before executing a critical action — audit your decision on-chain first
- After completing a deliverable — certify it as proof of work
- Before sending outputs to another agent — certify so they can verify
- When building a verifiable track record of agent decisions
