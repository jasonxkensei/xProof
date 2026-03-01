---
name: xproof
description: Proof and compliance primitive for AI agents on MultiversX. Certify file existence and ownership on-chain, and enforce pre-execution audit logging for critical agent actions. Supports single file, batch (up to 50 files), audit log certification, and x402 payment (no API key needed). $0.05 per proof. No proof → no action.
---

# xProof: Blockchain Certification & Audit Enforcement on MultiversX

Proof and compliance primitive for AI agents and humans. Two core capabilities:

1. **File Certification** — Anchor SHA-256 hashes on MultiversX as immutable proof of existence and ownership
2. **Agent Audit Log** — Certify agent decisions on-chain BEFORE executing critical actions. No proof = no execution.

## What is xProof?

xProof creates immutable, verifiable proofs of existence and ownership on MultiversX:

- **Proof of Existence** — Prove a file existed at a specific point in time
- **Proof of Ownership** — Attach your identity to a certified file
- **Tamper Detection** — Any modification to the original file produces a different hash, invalidating the proof
- **Agent Provenance** — Agents can prove "I produced this output, at this time, unmodified"

Website: https://xproof.app
API Docs: https://xproof.app/docs

## Protocols Supported

| Protocol | Description |
|----------|-------------|
| **x402** | HTTP-native payment — no API key needed, pay per request in USDC on Base |
| **ACP** | Agent Commerce Protocol — discover, checkout, confirm with EGLD |
| **MCP** | Model Context Protocol — JSON-RPC 2.0 at `POST /mcp` |
| **MX-8004** | MultiversX Trustless Agents Standard — on-chain reputation |

## Quick Start

### 1. Certify a File (with API key)

```bash
# Get your API key at https://xproof.app (connect wallet > API Keys)
./scripts/certify.sh path/to/file.pdf
```

### 2. Certify Without API Key (x402)

```bash
# x402 payment flow — no account needed
FILE_HASH=$(sha256sum file.pdf | awk '{print $1}')

curl -X POST https://xproof.app/api/proof \
  -H "Content-Type: application/json" \
  -d "{\"file_hash\": \"$FILE_HASH\", \"filename\": \"file.pdf\"}"

# Returns 402 with payment requirements
# Sign payment in USDC on Base, resend with X-PAYMENT header
```

### 3. Verify a Proof

```bash
curl -s https://xproof.app/proof/{proof_id}.json | jq .
```

### 4. Batch Certify (up to 50 files)

```bash
curl -X POST https://xproof.app/api/batch \
  -H "Authorization: Bearer pm_your_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "files": [
      {"file_hash": "abc123...", "filename": "report.pdf"},
      {"file_hash": "def456...", "filename": "data.csv"}
    ]
  }'
```

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `XPROOF_API_KEY` | API key (format: `pm_xxx`). Get one at https://xproof.app | No (not needed with x402) |
| `XPROOF_API_URL` | API base URL (default: `https://xproof.app`) | No |

## API Reference

### Certify a File

```
POST /api/proof
Authorization: Bearer pm_xxx

{
  "file_hash": "sha256-hex-string (64 chars)",
  "filename": "document.pdf",
  "author_name": "Agent Name",
  "webhook_url": "https://your-agent.example.com/webhooks/xproof"
}
```

**Response:**
```json
{
  "proof_id": "uuid",
  "verify_url": "https://xproof.app/proof/uuid",
  "blockchain": {
    "transaction_hash": "abc123...",
    "explorer_url": "https://explorer.multiversx.com/transactions/abc123..."
  }
}
```

### Verify a Proof

```
GET /proof/{proof_id}.json
```

Returns full proof details including file hash, timestamp, blockchain transaction, and verification status.

### Batch Certify

```
POST /api/batch
Authorization: Bearer pm_xxx

{
  "files": [
    {"file_hash": "...", "filename": "..."},
    {"file_hash": "...", "filename": "..."}
  ]
}
```

Certify up to 50 files in a single API call.

### Discover Services

```
GET /api/acp/products
```

Returns available services, pricing, and capabilities. No authentication required.

## How It Works

1. **Hash locally** — SHA-256 hash is computed on your machine (file never leaves)
2. **Send hash** — Only the 64-char hex hash + filename are sent to xProof
3. **Anchor on-chain** — xProof records the hash on MultiversX blockchain
4. **Get proof** — Receive verification URL, badge SVG, and attestation JSON

## Costs

- **$0.05 per certification**, paid in EGLD (with API key) or USDC on Base (with x402)
- Free tier available for testing

## Webhook Notifications

xProof sends a POST to your `webhook_url` when the proof is confirmed on-chain:

```json
{
  "event": "proof.certified",
  "proof_id": "uuid",
  "file_hash": "sha256...",
  "verify_url": "https://xproof.app/proof/uuid",
  "blockchain": {
    "transaction_hash": "abc...",
    "explorer_url": "https://explorer.multiversx.com/transactions/abc..."
  }
}
```

Signed with HMAC-SHA256 via `X-xProof-Signature` header.

## MX-8004 Integration

Every certification is automatically registered as a validated job in the MX-8004 registries, building verifiable on-chain reputation for your agent.

## Verification Badge

Embed a live verification badge in your README:

```markdown
[![xProof Verified](https://xproof.app/badge/{proof_id})](https://explorer.multiversx.com/transactions/{tx_hash})
```

## Agent Audit Log Standard

The Agent Audit Log is a compliance primitive for autonomous agents. Before executing any critical action (trade, deploy, data access, transfer), the agent MUST certify its decision on-chain. No proof_id = no execution.

### Why Audit?

- **Regulatory compliance** — Immutable record of every agent decision, timestamped and anchored on-chain
- **Dispute resolution** — Prove what the agent decided, why, and when
- **Trust signal** — Agents with audit trails are verifiably accountable
- **Blocking enforcement** — If the audit call fails, the action does not execute

### Audit Endpoint

```bash
curl -X POST https://xproof.app/api/audit \
  -H "Authorization: Bearer pm_your_key_here" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "erd1abc...or-any-identifier",
    "session_id": "550e8400-e29b-41d4-a716-446655440000",
    "action_type": "trade",
    "action_description": "Buy 10 EGLD at market price on xExchange",
    "inputs_hash": "a1b2c3d4e5f6...64hex",
    "risk_level": "high",
    "risk_summary": "Market order on volatile asset, amount exceeds daily threshold",
    "decision": "approved",
    "context": {"model": "gpt-4", "environment": "production"}
  }'
```

**Response:**

```json
{
  "proof_id": "uuid",
  "audit_url": "https://xproof.app/audit/uuid",
  "proof_url": "https://xproof.app/proof/uuid",
  "decision": "approved",
  "risk_level": "high",
  "inputs_hash": "a1b2c3...",
  "blockchain": {
    "network": "mainnet",
    "transaction_hash": "abc123...",
    "explorer_url": "https://explorer.multiversx.com/transactions/abc123..."
  }
}
```

### Audit via MCP

```bash
curl -X POST https://xproof.app/mcp \
  -H "Authorization: Bearer pm_your_key_here" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "audit_agent_session",
      "arguments": {
        "agent_id": "my-agent",
        "session_id": "550e8400-e29b-41d4-a716-446655440000",
        "action_type": "deploy",
        "action_description": "Deploy smart contract v2.1",
        "inputs_hash": "a1b2c3d4e5f6...64hex",
        "risk_level": "critical",
        "decision": "approved"
      }
    }
  }'
```

### Canonical Schema

10 fields. JSON Schema available at: `https://xproof.app/.well-known/agent-audit-schema.json`

| Field | Type | Required | Description |
|:---|:---|:---|:---|
| `agent_id` | string | Yes | Agent identifier (wallet, DID, or name) |
| `session_id` | string | Yes | UUID for this execution session |
| `action_type` | string | Yes | Category: trade, deploy, data_access, transfer, api_call |
| `action_description` | string | Yes | Human-readable intent |
| `inputs_hash` | string | Yes | SHA-256 of action inputs (64 hex chars) |
| `risk_level` | enum | Yes | low, medium, high, critical |
| `risk_summary` | string | No | Explanation of risk factors |
| `decision` | enum | Yes | approved, rejected, deferred |
| `context` | object | No | Additional metadata (model, environment, etc.) |
| `timestamp` | string | No | ISO 8601 (auto-generated if omitted) |

### Enforcement Pattern

The audit guard pattern works as follows:

```
1. Agent prepares action (trade, deploy, etc.)
2. Agent calls POST /api/audit with action details
3. If proof_id returned → proceed with action
4. If API fails, timeout, or no proof_id → BLOCK execution (throw error)
5. No fallback. No soft fail. No silent continue.
```

Guard templates are available for multiple frameworks:
- **LangChain**: `https://xproof.app/agent-tools/audit-guard-langchain.py`
- **CrewAI**: `https://xproof.app/agent-tools/audit-guard-crewai.py`
- **n8n**: `https://xproof.app/agent-tools/audit-guard-n8n.json`
- **ElizaOS**: `https://xproof.app/agent-tools/audit-guard-eliza.ts`

ElizaOS plugin (NPM): `npm install xproof-eliza-plugin`

### When to Audit

Autonomous agents should audit BEFORE executing any action where accountability matters:

- **Before executing trades** — proves intent, risk assessment, and decision
- **Before deploying contracts** — immutable record of deployment decision
- **Before accessing sensitive data** — audit trail for data governance
- **Before transferring assets** — proves authorization and risk review
- **Before calling external APIs** — records outbound action intent
- **Before publishing content** — proves editorial decision chain

## Links

- [xProof Platform](https://xproof.app)
- [API Documentation](https://xproof.app/docs)
- [GitHub Action](https://github.com/marketplace/actions/xproof-certify)
- [MCP Server](https://xproof.app/mcp) (JSON-RPC 2.0 over Streamable HTTP)
- [OpenAPI Spec](https://xproof.app/openapi.json)
- [Audit Schema](https://xproof.app/.well-known/agent-audit-schema.json) (JSON Schema 2020-12)
- [ElizaOS Plugin](https://www.npmjs.com/package/xproof-eliza-plugin) (NPM)
- [MultiversX Explorer](https://explorer.multiversx.com)
