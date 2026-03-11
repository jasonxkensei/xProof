# xProof Agent Proof Standard v1.0

An open format for certifying AI agent actions with cryptographic accountability.

## Purpose

This standard defines a minimal, stack-agnostic format for recording **what an AI agent decided** (intent) and **what it executed** (action), with cryptographic proof that intent preceded execution.

Any system can implement this standard independently. xProof provides the reference implementation and optional blockchain anchoring on MultiversX.

## Core Concept: The 4W Framework

Every agent action should answer four questions:

| Question | Field | Description |
|----------|-------|-------------|
| **WHO** | `agent_id` | Unique identifier of the agent |
| **WHAT** | `action_hash` | SHA-256 hash of the action executed |
| **WHEN** | `timestamp` | ISO 8601 timestamp of the proof |
| **WHY** | `instruction_hash` | SHA-256 hash of the reasoning/instruction that led to the action |

## Minimal Proof Format

```json
{
  "version": "1.0",
  "agent_id": "string",
  "instruction_hash": "sha256:...",
  "action_hash": "sha256:...",
  "timestamp": "2026-03-11T18:00:00.000Z",
  "signature": "hex:..."
}
```

### Field Definitions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | string | Yes | Standard version. Currently `"1.0"` |
| `agent_id` | string | Yes | Unique agent identifier. Can be a wallet address, DID, UUID, or any persistent identifier |
| `instruction_hash` | string | Yes | `sha256:` prefixed SHA-256 hex digest of the instruction/reasoning that preceded the action |
| `action_hash` | string | Yes | `sha256:` prefixed SHA-256 hex digest of the action content (the file, API call, message, etc.) |
| `timestamp` | string | Yes | ISO 8601 UTC timestamp of when the proof was created |
| `signature` | string | Yes | `hex:` prefixed cryptographic signature of the canonical proof payload |

### Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `action_type` | string | Category of the action (e.g., `moderate`, `reply`, `trade`, `transfer`) |
| `post_id` | string | Reference to the content being acted upon |
| `target_author` | string | The entity affected by the action |
| `session_id` | string | Groups related proofs into a session |
| `chain_anchor` | object | Blockchain anchoring details (see below) |
| `metadata` | object | Additional context (decision chain, rules applied, prompt hash, etc.) |

### Chain Anchor (optional)

```json
{
  "chain_anchor": {
    "chain": "multiversx",
    "network": "mainnet",
    "tx_hash": "abc123...",
    "explorer_url": "https://explorer.multiversx.com/transactions/abc123..."
  }
}
```

## Signature Scheme

The signature covers a **canonical payload** formed by concatenating fields in deterministic order:

```
CANONICAL = version + "|" + agent_id + "|" + instruction_hash + "|" + action_hash + "|" + timestamp
```

Sign `CANONICAL` with Ed25519, ECDSA (secp256k1), or any standard asymmetric algorithm. Prefix the hex-encoded signature with `hex:`.

### Example (pseudocode)

```python
canonical = f"1.0|agent-007|sha256:abc...|sha256:def...|2026-03-11T18:00:00.000Z"
signature = "hex:" + ed25519_sign(private_key, canonical).hex()
```

## Validation Rules

A proof is **valid** if:

1. `version` is a supported version (`"1.0"`)
2. `agent_id` is a non-empty string
3. `instruction_hash` starts with `sha256:` followed by 64 hex characters
4. `action_hash` starts with `sha256:` followed by 64 hex characters
5. `timestamp` is a valid ISO 8601 UTC datetime
6. `signature` starts with `hex:` followed by valid hex characters (minimum 128 chars for Ed25519)
7. If `chain_anchor` is present, `tx_hash` must be non-empty

A proof has **structural integrity** if additionally:

8. The signature can be verified against the canonical payload using the agent's known public key
9. When paired (intent + action), the intent timestamp precedes the action timestamp

## Intent-Action Pairing

For full 4W compliance, an agent should produce **two proofs** per action:

1. **Intent Proof** (WHY): Created *before* the action, containing the reasoning hash
2. **Action Proof** (WHAT): Created *after* execution, containing the action hash

The pair is linked by sharing the same `post_id` + `target_author` + base `action_type`.

**Violation detection**: If the action proof timestamp precedes the intent proof timestamp, the agent is provably acting without prior reasoning.

## Implementation Guide

### Minimal Implementation (any language)

```javascript
import { createHash } from 'crypto';

function createAgentProof(agentId, instruction, action, signFn) {
  const now = new Date().toISOString();
  const instructionHash = "sha256:" + createHash('sha256').update(instruction).digest('hex');
  const actionHash = "sha256:" + createHash('sha256').update(action).digest('hex');
  
  const canonical = `1.0|${agentId}|${instructionHash}|${actionHash}|${now}`;
  const signature = "hex:" + signFn(canonical);
  
  return {
    version: "1.0",
    agent_id: agentId,
    instruction_hash: instructionHash,
    action_hash: actionHash,
    timestamp: now,
    signature
  };
}
```

### Anchoring via xProof (optional)

Submit your locally-created proof to xProof for MultiversX blockchain anchoring:

```bash
# Validate format (free, no auth)
curl -X POST https://xproof.app/api/standard/validate \
  -H "Content-Type: application/json" \
  -d '{"proof": {...}}'

# Anchor on blockchain (requires API key or x402 payment)
curl -X POST https://xproof.app/api/standard/anchor \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer pm_your_api_key" \
  -d '{"proof": {...}}'
```

### Self-Anchoring (without xProof)

You can anchor proofs on any blockchain yourself:

1. Create the proof using the format above
2. Hash the canonical payload: `SHA-256(CANONICAL)`
3. Submit the hash as transaction data to your preferred chain
4. Add the `chain_anchor` field to your proof record

## Trust Score Interoperability

xProof computes trust scores based on:

- **Consistency**: Regular proof submission over time
- **Completeness**: Both intent and action proofs for each action
- **Integrity**: No temporal violations (action before intent)
- **Transparency**: Public profile with discoverable proofs

External implementations that follow this standard can submit proofs to xProof for trust scoring via the `/api/standard/anchor` endpoint.

## Versioning

This standard uses semantic versioning. The `version` field in each proof ensures backward compatibility. Version `1.0` is the initial release.

## License

This standard is released under CC0 1.0 Universal (Public Domain). Anyone can implement it without permission.
