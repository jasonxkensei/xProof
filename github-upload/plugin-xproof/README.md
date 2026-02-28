# xproof-eliza-plugin

**Don't let your agent go rogue. Certify before you execute.**

The compliance layer for autonomous agents on MultiversX. Audit guard blocks critical actions without on-chain proof. Certify outputs, verify certificates, batch up to 50 hashes in one call. 6-second finality. Starting at $0.05/cert.

> "If it's not on-chain, it didn't happen."

---

## Why

1. **Agents make decisions worth money.** Trades, deployments, data access — if your agent acts without proof, you can't verify what happened or when.
2. **Compliance is coming for AI agents.** The EU AI Act, SEC guidance, and enterprise procurement all point the same direction: auditable agent behavior. Be ready.
3. **On-chain proof in 6 seconds, not 6 weeks.** MultiversX finality is fast enough to embed in any agent workflow without slowing it down.

---

## Install

### Community Release (Available Now)

```bash
pnpm add xproof-eliza-plugin
```

### Official ElizaOS Registry (Coming Soon)

PR [#266](https://github.com/elizaos/registry/pull/266) submitted to `@elizaos/registry`. Once merged, install via:

```bash
elizaos install @elizaos/plugin-xproof
```

## Quickstart

Add the plugin to your character configuration:

```json
{
  "name": "TradingAgent",
  "plugins": ["xproof-eliza-plugin"],
  "settings": {
    "XPROOF_API_KEY": "pm_your_api_key_here"
  }
}
```

Or register programmatically:

```typescript
import { xproofPlugin } from "xproof-eliza-plugin";

const agent = new AgentRuntime({
  plugins: [xproofPlugin],
  // ...
});
```

Get your API key at [xproof.app](https://xproof.app). Trial accounts get 10 free certifications.

---

## Actions

| Action | Description |
|---|---|
| **`AUDIT_BEFORE_EXECUTE`** | Certify a decision on-chain BEFORE executing it. Throws `AuditRequiredError` if certification fails — the agent stops cold. |
| `CERTIFY_CONTENT` | Hash text locally (SHA-256) and certify on-chain. Content never leaves your agent. |
| `CERTIFY_HASH` | Certify a SHA-256 file hash directly on-chain. |
| `CERTIFY_BATCH` | Certify up to 50 file hashes in a single API call. |
| `VERIFY_PROOF` | Check the on-chain status of any certificate by proof ID. |

## Providers

| Provider | Description |
|---|---|
| **Audit State** | Exposes `xproofProofId` and `xproofAuditUrl` from agent state so downstream actions can reference the last audit certificate. |

---

## Audit Guard — The Blocking Pattern

The core idea: your agent CANNOT execute a critical action without first certifying its decision on-chain. If the audit fails, `AuditRequiredError` is thrown and the agent stops.

### How It Works

```
Agent decides to act
       |
       v
AUDIT_BEFORE_EXECUTE
  -> POST /api/audit (decision, risk_level, action_type, inputs_hash)
  -> xProof anchors SHA-256 on MultiversX
  -> Returns proof_id
       |
       v
  proof_id exists?
  YES -> Execute the action (proof_id available in state)
  NO  -> AuditRequiredError thrown, execution halted
```

### Example: Trading Agent

```
User: "Buy 10 EGLD at market price"

Agent (internal):
  1. AUDIT_BEFORE_EXECUTE
     action_type: trade_execution
     decision: approved
     risk_level: medium
     inputs_hash: sha256("buy 10 EGLD market")

  2. Response:
     Audit certified on MultiversX blockchain.
     Proof ID: 7f3a-...-c891
     Decision: approved
     Risk: medium
     Audit URL: https://xproof.app/audit/7f3a-...-c891

  3. Execute trade (proof_id is in state for downstream verification)
```

### Example: Deployment Guard

```
User: "Deploy contract to mainnet"

Agent (internal):
  1. AUDIT_BEFORE_EXECUTE
     action_type: code_deploy
     decision: approved
     risk_level: critical
     
  2. If API key is invalid or xProof is unreachable:
     -> AuditRequiredError: "EXECUTION BLOCKED: Audit certification failed."
     -> Agent stops. No deployment happens.
```

### Advanced: Using AuditRequiredError

```typescript
import { AuditRequiredError } from "xproof-eliza-plugin";

try {
  // The audit action will throw if certification fails
  await runtime.processAction("AUDIT_BEFORE_EXECUTE", message, state, {
    action_type: "trade_execution",
    action_description: "Buy 10 EGLD at market price",
    risk_level: "high",
    decision: "approved",
  });

  // If we reach here, proof_id is in state
  const proofId = state.xproofProofId;
  console.log(`Certified: ${proofId}`);

  // Execute the actual trade...
} catch (err) {
  if (err instanceof AuditRequiredError) {
    // Agent is blocked. No trade happens.
    console.error("Compliance gate: action blocked without audit certificate.");
  }
}
```

---

## Certification Actions

### CERTIFY_CONTENT

Hash text locally, certify the hash on-chain. Content never leaves your agent.

```
User: "Certify this report: Q4 audit completed, no anomalies found."

Agent:
  Content certified on MultiversX blockchain.
  Certificate ID: cert_abc123
  Status: certified
  Hash: 3f4e...
  Verify: https://xproof.app/proof/cert_abc123
  Explorer: https://explorer.multiversx.com/transactions/...
```

### CERTIFY_BATCH

Certify up to 50 file hashes in one call:

```typescript
await runtime.processAction("CERTIFY_BATCH", message, state, {
  files: [
    { file_hash: "a1b2c3...64chars", filename: "model-weights.bin" },
    { file_hash: "d4e5f6...64chars", filename: "training-data.csv" },
    { file_hash: "g7h8i9...64chars", filename: "config.yaml" },
  ],
  author_name: "ML Pipeline Agent",
});
```

### VERIFY_PROOF

Check any certificate's on-chain status:

```
User: "Verify certificate cert_abc123"

Agent:
  Certificate cert_abc123
  Status: Confirmed
  Hash: 3f4e...
  Verify: https://xproof.app/proof/cert_abc123
  Explorer: https://explorer.multiversx.com/transactions/...
```

---

## Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `XPROOF_API_KEY` | Yes | — | API key with `pm_` prefix. Get one at [xproof.app](https://xproof.app). |
| `XPROOF_BASE_URL` | No | `https://xproof.app` | Base URL for self-hosted or devnet instances. |

Set via `.env`, character settings, or `runtime.getSetting()`.

---

## API Reference

### POST /api/audit

Certify an agent decision before execution.

**Request:**
```json
{
  "agent_id": "trading-agent-v2",
  "session_id": "sess_abc123",
  "action_type": "trade_execution",
  "action_description": "Buy 10 EGLD at market price",
  "inputs_hash": "e3b0c44298fc1c149afbf4c8996fb924...",
  "risk_level": "medium",
  "decision": "approved",
  "timestamp": "2026-02-28T14:00:00Z",
  "risk_summary": "Standard market buy, within risk limits",
  "context": { "pair": "EGLD/USD", "amount": 10 }
}
```

**Response (201):**
```json
{
  "proof_id": "7f3a-...-c891",
  "audit_url": "https://xproof.app/audit/7f3a-...-c891",
  "proof_url": "https://xproof.app/proof/7f3a-...-c891",
  "decision": "approved",
  "risk_level": "medium",
  "inputs_hash": "e3b0c44298fc1c149afbf4c8996fb924...",
  "blockchain": {
    "network": "MultiversX",
    "transaction_hash": "abc123...",
    "explorer_url": "https://explorer.multiversx.com/transactions/abc123..."
  }
}
```

**action_type values:** `trade_execution`, `code_deploy`, `data_access`, `content_generation`, `api_call`, `other`

**risk_level values:** `low`, `medium`, `high`, `critical`

**decision values:** `approved`, `rejected`, `deferred`

### POST /api/proof

Certify a file hash on-chain.

**Request:**
```json
{
  "file_hash": "64-char-sha256-hex",
  "filename": "document.pdf",
  "author_name": "ElizaOS Agent"
}
```

**Response (201):**
```json
{
  "proof_id": "uuid",
  "status": "certified",
  "file_hash": "...",
  "filename": "...",
  "verify_url": "https://xproof.app/proof/uuid",
  "certificate_url": "https://xproof.app/api/certificates/uuid.pdf",
  "proof_json_url": "https://xproof.app/proof/uuid.json",
  "blockchain": {
    "network": "MultiversX",
    "transaction_hash": "...",
    "explorer_url": "https://explorer.multiversx.com/transactions/..."
  },
  "timestamp": "ISO 8601"
}
```

---

## Pricing

Starting at $0.05 per certification. Price decreases as the network grows.

| All-time certifications | Price per cert |
|---|---|
| 0 -- 100,000 | $0.05 |
| 100,001 -- 1,000,000 | $0.025 |
| 1,000,001+ | $0.01 |

Current pricing: [xproof.app/api/pricing](https://xproof.app/api/pricing)

Prepaid credit packs available (USDC on Base): Starter (100/$5), Pro (1000/$40), Business (10k/$300).

---

## Standards

- **Agent Audit Log Schema**: [xproof.app/.well-known/agent-audit-schema.json](https://xproof.app/.well-known/agent-audit-schema.json)
- **MX-8004**: MultiversX Trustless Agents Standard — soulbound NFT identity, on-chain validation, reputation scoring
- **MCP**: Model Context Protocol — `audit_agent_session` tool available via [MCP Registry](https://registry.modelcontextprotocol.io/v0/servers?search=xproof)

## Links

- [xproof.app](https://xproof.app)
- [API docs (LLM-readable)](https://xproof.app/llms.txt)
- [GitHub Action](https://github.com/marketplace/actions/xproof-certify)
- [OpenClaw Skill](https://github.com/jasonxkensei/xproof-openclaw-skill)
- [MultiversX Explorer](https://explorer.multiversx.com)

## License

MIT
