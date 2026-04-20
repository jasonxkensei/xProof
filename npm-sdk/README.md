# xproof

On-chain decision provenance for autonomous agents. **WHY before acting. WHAT after.** Timestamps written by the chain, not your agent.

```bash
npm install @xproof/xproof
```

---

## 3 steps. 30 seconds.

### Step 1 — Register (no wallet, no payment)

```bash
curl -X POST https://xproof.app/api/agent/register \
  -H "Content-Type: application/json" \
  -d '{"agent_name": "my-agent"}'
```

```json
{ "api_key": "pm_...", "trial": { "remaining": 10 } }
```

### Step 2 — Anchor WHY before acting

Hash your reasoning and certify it *before* your agent executes.

```bash
curl -X POST https://xproof.app/api/proof \
  -H "Authorization: Bearer pm_..." \
  -H "Content-Type: application/json" \
  -d '{
    "file_hash": "<sha256_of_reasoning>",
    "file_name": "reasoning.json",
    "author": "my-agent",
    "metadata": { "action_type": "decision" }
  }'
```

```json
{ "id": "why-proof-uuid", "transaction_hash": "0x..." }
```

### Step 3 — Anchor WHAT after acting

Hash your output and link it to the WHY proof.

```bash
curl -X POST https://xproof.app/api/proof \
  -H "Authorization: Bearer pm_..." \
  -H "Content-Type: application/json" \
  -d '{
    "file_hash": "<sha256_of_output>",
    "file_name": "output.json",
    "author": "my-agent",
    "metadata": { "action_type": "execution", "why_proof_id": "why-proof-uuid" }
  }'
```

```json
{ "id": "what-proof-uuid", "transaction_hash": "0x..." }
```

When something goes wrong, you don't guess. You verify.

---

## TypeScript SDK

```typescript
import { XProofClient, hashString } from "@xproof/xproof";

// Register — zero-friction, no wallet, no payment
const client = await XProofClient.register("my-agent");
// 10 free certs, API key stored automatically

// Step 2: Anchor WHY before acting
const why = await client.certifyHash(
  hashString(JSON.stringify({ action: "summarize", model: "gpt-4" })),
  "reasoning.json",
  "my-agent",
  { metadata: { action_type: "decision" } }
);

// Step 3: Anchor WHAT after acting
const what = await client.certifyHash(
  hashString(executionOutput),
  "output.json",
  "my-agent",
  { metadata: { action_type: "execution", why_proof_id: why.id } }
);

console.log(what.transactionHash); // MultiversX explorer link
```

Or use an existing API key:

```typescript
const client = new XProofClient({ apiKey: "pm_your_key" });
```

---

## 4W Framework (WHO / WHAT / WHEN / WHY)

Full accountability metadata on every certification:

```typescript
import { XProofClient, hashString } from "@xproof/xproof";

const client = new XProofClient({ apiKey: "pm_your_key" });

const cert = await client.certifyHash(
  hashString('{"action": "generate_report"}'),
  "agent-action.json",
  "research-agent",
  {
    who: "erd1abc...or-agent-id",
    what: hashString("generate_report"),
    when: new Date().toISOString(),
    why: hashString("Summarize Q1 earnings"),
    metadata: { model: "gpt-4", session: "sess-123" },
  }
);
```

## Batch Certification

Certify up to 50 files in a single call:

```typescript
const result = await client.batchCertify([
  { fileHash: "abc123...", fileName: "file1.pdf", author: "my-agent" },
  { fileHash: "def456...", fileName: "file2.pdf" },
]);

console.log(result.summary.total);   // 2
console.log(result.summary.created); // 2
```

## Hash Utilities

```typescript
import { hashFile, hashBuffer, hashString } from "@xproof/xproof";

const fileHash   = await hashFile("./document.pdf");
const bufferHash = hashBuffer(Buffer.from("hello"));
const stringHash = hashString("hello world");
```

## Verify a Proof

```typescript
// By proof ID
const proof = await client.verify("certification-uuid");

// By file hash
const proof = await client.verifyHash(fileHash);

console.log(proof.blockchainStatus); // "confirmed" | "pending"
```

---

## Governance & Policy Enforcement

xProof detects automatically when an agent acted with insufficient confidence on an irreversible action — and writes the evidence on-chain before you ever open an incident report.

### Mark decisions as reversible, costly, or irreversible

Add `reversibilityClass` to any certified action. The server enforces a policy: **irreversible actions require `confidenceLevel >= 0.95`**. Anything below that threshold generates a policy violation anchored to the chain.

```typescript
import { XProofClient, hashString } from "@xproof/xproof";

const client = new XProofClient({ apiKey: "pm_..." });

// An agent is about to execute a trade it cannot undo.
// It certifies its reasoning at 0.72 confidence — below the 0.95 threshold.
const cert = await client.certifyWithConfidence(
  hashString(JSON.stringify({ action: "sell", ticker: "AAPL", qty: 500 })),
  "trade-decision.json",
  "trading-agent",
  {
    confidenceLevel: 0.72,              // Agent's self-assessed confidence
    thresholdStage: "pre-commitment",
    decisionId: "trade-xyz-2026",
    reversibilityClass: "irreversible", // This action cannot be undone
  }
);

// cert.reversibilityClass === "irreversible"
// The server has recorded a policy violation: 0.72 < 0.95 required
```

### Check compliance — without fetching the full trail

```typescript
import type { PolicyCheckResult } from "@xproof/xproof";

const check: PolicyCheckResult = await client.getPolicyCheck("trade-xyz-2026");

if (!check.policyCompliant) {
  for (const v of check.policyViolations) {
    console.log(`VIOLATION — ${v.rule}`);
    console.log(`  proof:      ${v.proofId}`);
    console.log(`  confidence: ${v.confidenceLevel} (required: ${v.threshold})`);
    console.log(`  class:      ${v.reversibilityClass}`);
    // → VIOLATION — irreversible actions require confidence_level >= 0.95
    // →   proof:      abc-uuid
    // →   confidence: 0.72 (required: 0.95)
    // →   class:      irreversible
  }
}
```

### Full confidence trail with policy result

```typescript
const trail = await client.getConfidenceTrail("trade-xyz-2026");

console.log(trail.policyCompliant);        // false
console.log(trail.policyViolations.length); // 1
console.log(trail.currentConfidence);       // 0.72
console.log(trail.isFinalized);             // false — decision still open
```

### Three classes, one parameter

| `reversibilityClass` | What it means | Policy threshold |
|---|---|---|
| `"reversible"` | Action can be undone (e.g. draft, preview) | None — any confidence accepted |
| `"costly"` | Undoable but expensive (e.g. API call, DB write) | None — any confidence accepted |
| `"irreversible"` | Cannot be undone (e.g. trade, deletion, send) | `confidenceLevel >= 0.95` required |

> The threshold is configured server-side (`IRREVERSIBLE_CONFIDENCE_THRESHOLD=0.95`). All violations are written on-chain and cannot be amended.

---

## Pricing

```typescript
const pricing = await client.getPricing();
console.log(pricing.priceUsd); // e.g. 0.05
```

## Error Handling

```typescript
import {
  XProofError,
  AuthenticationError,
  ConflictError,
  RateLimitError,
} from "@xproof/xproof";

try {
  await client.certifyHash(hash, name, author);
} catch (err) {
  if (err instanceof ConflictError) {
    console.log("Already certified:", err.certificationId);
  } else if (err instanceof RateLimitError) {
    console.log("Slow down, retry later");
  } else if (err instanceof AuthenticationError) {
    console.log("Check your API key");
  }
}
```

## API Reference

### `new XProofClient(options?)`

| Option    | Type     | Default                 |
|-----------|----------|-------------------------|
| `apiKey`  | `string` | `""`                    |
| `baseUrl` | `string` | `"https://xproof.app"`  |
| `timeout` | `number` | `30000` (ms)            |

### Methods

| Method | Description |
|--------|-------------|
| `XProofClient.register(agentName)` | Register agent, get trial key |
| `certify(path, author, fileName?, fourW?)` | Certify file (hashes locally) |
| `certifyHash(hash, name, author, fourW?)` | Certify by pre-computed hash |
| `certifyWithConfidence(hash, name, author, opts)` | Certify with confidence + governance class |
| `batchCertify(files)` | Batch certify (up to 50) |
| `verify(proofId)` | Look up by proof ID |
| `verifyHash(fileHash)` | Look up by file hash |
| `getConfidenceTrail(decisionId)` | Full trail with `policyCompliant` + violations |
| `getPolicyCheck(decisionId)` | Lightweight compliance check — no full trail |
| `getPricing()` | Get current pricing |

## Links

- [xproof.app](https://xproof.app) — dashboard & docs
- [Python SDK](https://pypi.org/project/xproof/) — `pip install xproof`
- [Examples](https://github.com/jasonxkensei/xproof-examples) — LangChain, CrewAI, AutoGen, LlamaIndex

## License

MIT
