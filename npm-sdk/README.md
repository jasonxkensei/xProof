# xproof

Official TypeScript/JavaScript SDK for the [xProof](https://xproof.app) blockchain certification API — proof and accountability layer for autonomous agents.

## Installation

```bash
npm install xproof
```

Requires Node.js 18+ (uses native `fetch`).

## Quick Start

```typescript
import { XProofClient } from "xproof";

// 1. Register (zero-friction, no wallet needed)
const client = await XProofClient.register("my-agent");
console.log(client.registration?.trial.remaining); // 10 free certs

// 2. Certify
const cert = await client.certifyHash(
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "report.pdf",
  "my-agent"
);
console.log(cert.transactionHash);

// 3. Verify
const proof = await client.verifyHash(cert.fileHash);
console.log(proof.id);
```

Or use an existing API key:

```typescript
const client = new XProofClient({ apiKey: "pm_your_key" });
```

## 4W Framework (WHO / WHAT / WHEN / WHY)

Certifications support the 4W accountability framework:

```typescript
import { XProofClient, hashString } from "xproof";

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
import { hashFile, hashBuffer, hashString } from "xproof";

const fileHash = await hashFile("./document.pdf");
const bufferHash = hashBuffer(Buffer.from("hello"));
const stringHash = hashString("hello world");
```

## Pricing

```typescript
const pricing = await client.getPricing();
console.log(pricing.priceUsd);
```

## Error Handling

```typescript
import {
  XProofError,
  AuthenticationError,
  ConflictError,
  RateLimitError,
} from "xproof";

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
| `certifyHash(hash, name, author, fourW?)` | Certify by hash |
| `batchCertify(files)` | Batch certify (up to 50) |
| `verify(proofId)` | Look up by proof ID |
| `verifyHash(fileHash)` | Look up by file hash |
| `getPricing()` | Get current pricing |

## License

MIT
