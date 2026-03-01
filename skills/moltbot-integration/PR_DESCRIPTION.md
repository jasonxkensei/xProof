# Add xProof certification & audit enforcement skills

## Summary

Adds `xproof_skills.ts` -- off-chain certification and pre-execution audit enforcement for agent outputs via the [xProof](https://xproof.app) API, with a composite flow that chains xProof certification with MX-8004 Validation Registry `submit_proof`. Implements the [Agent Audit Log Standard](https://xproof.app/.well-known/agent-audit-schema.json).

Ref: multiversx/mx-openclaw-skills#1, issue #679

## What it does

| Function | Description |
|---|---|
| `certifyFile(params)` | Hash a local file (SHA-256) and certify on MultiversX via xProof |
| `certifyHash(params)` | Certify a pre-computed hash (no local file needed) |
| `certifyBatch(params)` | Certify up to 50 files in a single API call |
| `verifyProof(certId)` | Check certification status and blockchain details |
| `certifyAndSubmitProof(params)` | **Composite**: xProof certify + Validation Registry `submit_proof` in one call |
| `auditAgentSession(params)` | **Audit enforcement**: certify agent decision on-chain BEFORE executing critical action. Throws `AuditRequiredError` on failure -- no soft fail |

## Integration architecture

```
Agent Output
    |
    v
certifyAndSubmitProof()
    |
    +-- Step 1: certifyFile() / certifyHash()
    |       POST /api/proof → xProof API
    |       Returns: { id, hash, status, txHash }
    |
    +-- Step 2: submitProof()
    |       On-chain submit_proof(jobId, proofHash)
    |       → Validation Registry (MX-8004)
    |
    v
Two-layer proof:
  - xProof: immutable content hash + timestamp + explorer link
  - MX-8004: on-chain job proof for the agent economy
```

## Audit enforcement architecture

```
Critical Action Intent
    |
    v
auditAgentSession()
    |
    +-- POST /api/audit → xProof API
    |   Body: { agent_id, session_id, action_type, inputs_hash, risk_level, decision }
    |
    +-- Success: proof_id returned → proceed with action
    |
    +-- Failure (API error, timeout, no proof_id):
            → throw AuditRequiredError
            → EXECUTION BLOCKED
            → No soft fail. No fallback.
```

The `AuditRequiredError` is a dedicated error class. Every failure path (network error, timeout via `AbortSignal.timeout(15_000)`, HTTP error, missing proof_id) throws this error. There is no `return false` anywhere in the function.

## Auth modes

- **API key**: `Authorization: Bearer pm_...` (set via `XPROOF_API_KEY` env var)
- **x402**: HTTP 402 payment protocol -- USDC on Base, no account needed. Pass `useX402: true` + `x402Payment` header value.

## x402 payment challenge

When calling without an API key and without a valid `x402Payment`, the xProof API returns HTTP 402 with a JSON body:

```json
{
  "x402Version": 1,
  "accepts": [{ "scheme": "exact", "price": "50000", "network": "base", "payTo": "0x..." }]
}
```

The skill throws `XProofPaymentRequired` with the full payment details. The caller is responsible for completing the x402 payment and retrying with the `x402Payment` parameter (base64-encoded payment receipt).

## Files changed

- `src/skills/xproof_skills.ts` -- new skill module
- `src/skills/index.ts` -- barrel export updated
- `src/config.ts` -- added `CONFIG.XPROOF` block (`BASE_URL`, `API_KEY`)
- `.env.example` -- added `XPROOF_API_KEY`, `XPROOF_BASE_URL`

## Code conventions

- Follows existing patterns: `Logger`, `CONFIG`, JSDoc headers, exported types
- Routes env vars through `CONFIG.XPROOF` (not raw `process.env`)
- Imports `submitProof` from `validation_skills.ts` for the composite flow
- No new dependencies -- uses Node built-in `crypto` and native `fetch`
