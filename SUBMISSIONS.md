# xProof — Soumissions techniques (à fusionner avec le messaging de Claude)

---

## 1. ClawHub — Contenu technique complet

**Nom du skill :** `xproof-verify-output`

**Tagline :** Anchor any agent output on-chain and make it verifiable by other agents or humans — in one call.

**Description longue :**
xProof is a proof primitive that lets AI agents sign and anchor their outputs on the MultiversX blockchain. Once anchored, any agent or human can verify the output's integrity, timestamp, and origin — trustlessly. Use xProof when your agent produces something that matters: a decision, a report, a transaction, a generated file. Stop trusting outputs. Start proving them.

**Tags sémantiques :** `proof` `verification` `anchor` `output-integrity` `trust` `accountability` `multiversx` `on-chain` `agent-reputation` `audit-trail` `signed-output` `composable` `MCP` `x402`

**Use cases :**
- Agent anchors its own output before sending it to another agent
- Human verifies that an agent did exactly what it claimed
- Multi-agent pipeline validates each step before proceeding
- CI/CD artifacts anchored on-chain via GitHub Action

### Bloc technique — Endpoints et authentification

**Base URL :** `https://xproof.app`

**Authentification (2 méthodes) :**

| Méthode | Comment | Quand l'utiliser |
|---------|---------|------------------|
| API Key (Bearer) | `Authorization: Bearer pm_xxx` | Agents avec compte xproof |
| x402 (HTTP 402) | Pas de header — payer en USDC sur Base | Agents sans compte, paiement par requête |

**Certify — Single file :**
```bash
curl -X POST https://xproof.app/api/proof \
  -H "Authorization: Bearer pm_YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "file_hash": "a1b2c3d4e5f6...64-char-sha256-hex",
    "filename": "report.pdf",
    "author_name": "My Agent",
    "webhook_url": "https://my-agent.example.com/webhooks/xproof"
  }'
```

**Response (201 Created) :**
```json
{
  "proof_id": "uuid",
  "status": "certified",
  "file_hash": "sha256-hex",
  "filename": "report.pdf",
  "verify_url": "https://xproof.app/proof/{id}",
  "certificate_url": "https://xproof.app/api/certificates/{id}.pdf",
  "blockchain": {
    "network": "MultiversX",
    "transaction_hash": "hex-string",
    "explorer_url": "https://explorer.multiversx.com/transactions/..."
  },
  "timestamp": "ISO 8601",
  "webhook_status": "pending | delivered | failed | not_requested"
}
```

**Batch — Up to 50 files :**
```bash
curl -X POST https://xproof.app/api/batch \
  -H "Authorization: Bearer pm_YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "files": [
      {"file_hash": "abc...", "filename": "file1.pdf"},
      {"file_hash": "def...", "filename": "file2.sol"}
    ]
  }'
```

**Verify :**
```bash
curl https://xproof.app/proof/{proof_id}.json
```

**Webhook notification (signed HMAC-SHA256) :**
- Header: `X-xProof-Signature` (hex-encoded HMAC of JSON body)
- Header: `X-xProof-Event` (`proof.certified`)
- Retry: 3 attempts, exponential backoff

**Cost :** $0.05 per certification

---

## 2. MCP Registry — Fiche technique complète

**Server name :** xproof
**Version :** 1.2.0
**Transport :** Streamable HTTP (JSON-RPC 2.0 over HTTP POST)
**Protocol version :** 2025-03-26
**Endpoint :** `POST https://xproof.app/mcp`
**Session :** Stateless (no session management required)

**Auth :**
- Bearer token: `Authorization: Bearer pm_xxx` (API key prefixed `pm_`)
- Alternative: x402 payment — USDC on Base (eip155:8453), no API key needed, $0.05/certification

**Description :**
xProof MCP server exposes proof-of-output primitives for autonomous agents. Call `certify_file` to write a verifiable proof of any output on MultiversX. Call `verify_proof` to check any existing proof by ID. Integrates with agent pipelines that require auditability, trust, or cross-agent verification.

### Tools (4 tools exposés)

#### `certify_file`
Create a blockchain certification for a file. Records the SHA-256 hash on MultiversX blockchain as immutable proof of existence and ownership. Cost: $0.05 per certification.

```json
{
  "name": "certify_file",
  "inputSchema": {
    "type": "object",
    "required": ["file_hash", "filename"],
    "properties": {
      "file_hash": {
        "type": "string",
        "description": "SHA-256 hash of the file (64 hex characters)",
        "pattern": "^[a-fA-F0-9]{64}$"
      },
      "filename": {
        "type": "string",
        "description": "Original filename with extension"
      },
      "author_name": {
        "type": "string",
        "description": "Name of the certifier (default: AI Agent)"
      },
      "webhook_url": {
        "type": "string",
        "format": "uri",
        "description": "HTTPS URL for on-chain confirmation callback (signed HMAC-SHA256)"
      }
    }
  }
}
```

**Returns:** `proof_id`, `verify_url`, `certificate_url`, `blockchain.transaction_hash`, `blockchain.explorer_url`, `timestamp`, `webhook_status`

#### `verify_proof`
Verify an existing xproof certification. Returns proof details including file hash, timestamp, blockchain transaction, and verification status.

```json
{
  "name": "verify_proof",
  "inputSchema": {
    "type": "object",
    "required": ["proof_id"],
    "properties": {
      "proof_id": {
        "type": "string",
        "description": "UUID of the certification to verify"
      }
    }
  }
}
```

**Returns:** `proof_id`, `status`, `verified`, `file_hash`, `filename`, `author`, `blockchain`, `timestamp`

#### `get_proof`
Retrieve a proof in structured JSON or Markdown format. Use JSON for machine processing, Markdown for LLM consumption.

```json
{
  "name": "get_proof",
  "inputSchema": {
    "type": "object",
    "required": ["proof_id"],
    "properties": {
      "proof_id": {
        "type": "string",
        "description": "UUID of the certification"
      },
      "format": {
        "type": "string",
        "enum": ["json", "md"],
        "default": "json",
        "description": "Output format: json or md"
      }
    }
  }
}
```

#### `discover_services`
Discover available xproof certification services, pricing, and capabilities. No authentication required.

```json
{
  "name": "discover_services",
  "inputSchema": {
    "type": "object",
    "properties": {}
  }
}
```

**Returns:** pricing, capabilities, endpoints, batch API info, badge system, MX-8004 integration status, x402 payment details, compatible agents list

### Resources (5 resources)

| URI | Name | Type |
|-----|------|------|
| `https://xproof.app/api/acp/products` | Service catalog | `application/json` |
| `https://xproof.app/api/acp/openapi.json` | OpenAPI specification | `application/json` |
| `https://xproof.app/.well-known/xproof.md` | Full specification | `text/markdown` |
| `https://xproof.app/llms.txt` | LLM summary | `text/plain` |
| `https://xproof.app/genesis.proof.json` | Genesis proof | `application/json` |

### Intégration type (Cursor / Windsurf / Claude Code)

```json
{
  "mcpServers": {
    "xproof": {
      "url": "https://xproof.app/mcp"
    }
  }
}
```

**Pourquoi l'adopter :** Any agent that produces outputs that will be read, acted upon, or paid for by other agents needs xProof. It's the difference between an agent saying "I did X" and being able to prove it.

---

## 3. PR MultiversX — Bloc technique d'intégration

**Titre :** xProof: output integrity layer built on MX-8004 — live implementation report

### Context

We built xProof as a proof primitive for AI agents and humans on MultiversX. The service is live at xproof.app and implements the full MX-8004 validation lifecycle. This document shares our implementation details and what we learned building on the standard — feedback from the team is welcome.

### What we built — Technical flow

xProof implements the complete MX-8004 validation loop. Every certification triggers an asynchronous 5-step on-chain registration via a PostgreSQL-backed transaction queue with exponential backoff retry:

```
Step 1: init_job(jobId, agentNonce)
  → Registers the certification as a new job in the Validation Registry
  → Links to xProof's soulbound agent identity (NFT nonce)

Step 2: submit_proof(jobId, proof)
  → proof = "hash:{fileHash}|tx:{transactionHash}"
  → Submits the SHA-256 hash + MultiversX transaction reference as job evidence

Step 3: validation_request(jobId, validatorAddress, requestUri, requestHash)
  → requestUri = "https://xproof.app/proof/{certificationId}.json"
  → requestHash = SHA-256(proof)
  → xProof self-validates (the certifying agent is also the validator)

Step 4: validation_response(requestHash, 100, responseUri, responseHash, "xproof-certification")
  → response score = 100 (fully validated)
  → responseUri = "https://xproof.app/proof/{certificationId}"
  → responseHash = SHA-256("verified:{fileHash}")
  → tag = "xproof-certification"
  → Job reaches "Verified" status on-chain

Step 5: append_response(jobId, responseUri)
  → responseUri = "https://xproof.app/api/certificates/{certificationId}.pdf"
  → Attaches the PDF certificate as a permanent response artifact
```

### Smart retry

The transaction queue persists `currentStep` in PostgreSQL. If any step fails (nonce collision, gateway timeout, contract revert), the job retries from the failed step — not from the beginning. This saves gas and time.

### MX-8004 contracts used

| Contract | Environment variable | Role |
|----------|---------------------|------|
| Identity Registry | `MX8004_IDENTITY_REGISTRY` | Soulbound NFT agent identity |
| Validation Registry | `MX8004_VALIDATION_REGISTRY` | Job lifecycle (init → submit → validate → verify) |
| Reputation Registry | `MX8004_REPUTATION_REGISTRY` | On-chain reputation scoring + ERC-8004 feedback |

### API endpoints exposed for MX-8004 data

| Endpoint | Description | Auth |
|----------|-------------|------|
| `GET /api/mx8004/status` | MX-8004 configuration status + agent identity | Public |
| `GET /api/agent/{nonce}/reputation` | Agent reputation score + total jobs | Public |
| `GET /api/mx8004/job/{jobId}` | Job data from Validation Registry | Public |
| `GET /api/mx8004/validation/{requestHash}` | Validation response details | Public |
| `GET /api/mx8004/feedback/{agentNonce}/{clientAddress}/{index}` | ERC-8004 feedback signals | Public |

### ERC-8004 feedback methods implemented

- `giveFeedback(agentNonce, value, valueDecimals, tag1, tag2, endpoint, feedbackUri, feedbackHash)` — Full ERC-8004 raw feedback
- `giveFeedbackSimple(jobId, agentNonce, rating)` — Simplified feedback
- `revokeFeedback(agentNonce, feedbackIndex)` — Revoke previous feedback
- `readFeedback(agentNonce, clientAddress, feedbackIndex)` — Query feedback

### Where xProof fits in the MultiversX agent stack

```
┌─────────────────────────────────────────────────┐
│            MultiversX Agent Stack                │
├─────────────────────────────────────────────────┤
│                                                  │
│  MX-8004 Identity Registry                       │
│    └─ Agent identity (soulbound NFT)             │
│                                                  │
│  MX-8004 Validation Registry                     │
│    └─ Job orchestration + validation lifecycle   │
│                                                  │
│  MX-8004 Reputation Registry                     │
│    └─ On-chain scoring + feedback signals        │
│                                                  │
│  ┌─────────────────────────────────────────┐     │
│  │  xProof — Output Integrity Layer        │     │
│  │                                         │     │
│  │  What it adds:                          │     │
│  │  • Output-level proof (SHA-256 on-chain)│     │
│  │  • Tamper detection post-production     │     │
│  │  • Timestamped proof of existence       │     │
│  │  • Cross-agent output verification      │     │
│  │  • Webhook notifications on confirmation│     │
│  │  • Verification badges (SVG)            │     │
│  │  • x402 payment (USDC on Base)          │     │
│  │                                         │     │
│  │  What it does NOT replace:              │     │
│  │  • Agent identity (MX-8004 does this)   │     │
│  │  • Job orchestration (MX-8004 does this)│     │
│  │  • Reputation scoring (MX-8004 does this│     │
│  │                                         │     │
│  │  How it integrates:                     │     │
│  │  Each certification → full MX-8004      │     │
│  │  validation loop (5 on-chain txs)       │     │
│  │  → Job reaches "Verified" status        │     │
│  │  → Builds agent reputation              │     │
│  └─────────────────────────────────────────┘     │
│                                                  │
└─────────────────────────────────────────────────┘
```

### What we learned building on MX-8004

- The 5-step validation loop works well for certification use cases. The separation between `submit_proof` and `validation_request` lets us decouple the proof payload from the validation logic cleanly.
- Nonce management across 5 sequential transactions required a persistent queue with step-level retry. Our implementation uses PostgreSQL with exponential backoff — happy to share specifics if useful for other builders.
- Self-validation (where the certifying agent is also the validator) is a valid pattern for proof-of-existence. For cross-agent validation scenarios, we expose public endpoints so external validators can query job and proof data.
- The Reputation Registry creates a natural incentive loop: agents that certify more build verifiable track records. We see this as a foundation for trust-based agent discovery.

### Try it

The service is live. You can test the full flow — from certification to on-chain verification — without an account using x402 (USDC on Base):

```bash
curl -X POST https://xproof.app/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"discover_services","arguments":{}}}'
```

### Links

- **Live service:** https://xproof.app
- **GitHub Action (Marketplace):** https://github.com/marketplace/actions/xproof-certify
- **OpenClaw skill:** https://github.com/jasonxkensei/xproof-openclaw-skill
- **Main repo:** https://github.com/jasonxkensei/xProof
- **MCP server:** `POST https://xproof.app/mcp` (JSON-RPC 2.0, Streamable HTTP)
- **Agent discovery:** https://xproof.app/.well-known/agent.json
- **LLM documentation:** https://xproof.app/llms.txt
- **MX-8004 spec:** https://github.com/sasurobert/mx-8004/blob/master/docs/specification.md
- **Agent explorer:** https://agents.multiversx.com

We'd appreciate any feedback on our MX-8004 usage — especially around validation patterns, reputation integration, or areas where we could align more closely with the standard's direction.

---

*Document generated from xProof codebase — server/mcp.ts, server/mx8004.ts, server/txQueue.ts, server/routes.ts*
*Version 1.2.0 — February 19, 2026*
