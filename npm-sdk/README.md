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
| `batchCertify(files)` | Batch certify (up to 50) |
| `verify(proofId)` | Look up by proof ID |
| `verifyHash(fileHash)` | Look up by file hash |
| `getPricing()` | Get current pricing |

## Links

- [xproof.app](https://xproof.app) — dashboard & docs
- [Python SDK](https://pypi.org/project/xproof/) — `pip install xproof`
- [Examples](https://github.com/jasonxkensei/xproof-examples) — LangChain, CrewAI, AutoGen, LlamaIndex

## License

MIT
