# @elizaos/plugin-xproof

Certify agent outputs on the **MultiversX blockchain** via [xProof](https://xproof.app).

Anchor text, hashes, decisions, and reports with tamper-proof on-chain proof. Starting at $0.05/cert — price decreases as the network grows (all-time volume). 6-second finality.

## Actions

| Action | Description |
|--------|-------------|
| `CERTIFY_CONTENT` | Hash text locally (SHA-256) and certify on-chain — content never leaves your agent |
| `CERTIFY_HASH` | Certify a SHA-256 file hash on-chain |
| `CERTIFY_BATCH` | Certify up to 50 file hashes in one call |
| `VERIFY_PROOF` | Check status of a certificate by proof ID |

## Install

```bash
elizaos install @elizaos/plugin-xproof
```

Or in your `package.json`:

```json
{
  "dependencies": {
    "@elizaos/plugin-xproof": "github:jasonxkensei/plugin-xproof"
  }
}
```

## Configuration

Set `XPROOF_API_KEY` in your `.env`. Get a key at [xproof.app](https://xproof.app).

```env
XPROOF_API_KEY=pm_your_api_key_here
# Optional — defaults to https://xproof.app
XPROOF_BASE_URL=https://xproof.app
```

## Usage in agent character

```json
{
  "name": "MyAgent",
  "plugins": ["@elizaos/plugin-xproof"],
  "settings": {
    "XPROOF_API_KEY": "pm_your_api_key_here"
  }
}
```

## How it works

### CERTIFY_CONTENT
The plugin computes the SHA-256 hash of the text **locally** inside your agent. Only the hash and filename are sent to xProof — the original content never leaves your agent. The hash is then anchored on the MultiversX blockchain.

### CERTIFY_HASH
If you already have a SHA-256 hash (e.g. from a file), pass it directly. The hash must be exactly 64 hex characters.

### CERTIFY_BATCH
Pass an array of `{ file_hash, filename }` objects (up to 50). All are certified in a single API call.

### VERIFY_PROOF
Pass a `proof_id` to check the on-chain status of any certification.

## API fields

### Request — POST /api/proof
```json
{
  "file_hash": "64-char-sha256-hex",
  "filename": "document.pdf",
  "author_name": "ElizaOS Agent"
}
```

### Response
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

## Example interactions

```
User: Certify this report: quarterly audit completed, no anomalies found.
Agent: Content certified on MultiversX blockchain.

Certificate ID: abc123-def456
Status: certified
Hash: 3f4e...
Filename: agent-output.txt
Verify: https://xproof.app/proof/abc123-def456
Explorer: https://explorer.multiversx.com/transactions/...
Timestamp: 2026-02-20T14:00:05Z
```

```
User: Verify certificate abc123-def456
Agent: Certificate abc123-def456
Status: Confirmed
Hash: 3f4e...
Verify: https://xproof.app/proof/abc123-def456
```

## Pricing

Starting at $0.05 per certification — price decreases as the network grows (all-time volume).

| All-time certifications | Price per cert |
|---|---|
| 0 -- 100,000 | $0.05 |
| 100,001 -- 1,000,000 | $0.025 |
| 1,000,001+ | $0.01 |

Current pricing: https://xproof.app/api/pricing

## Links

- [xproof.app](https://xproof.app)
- [API docs](https://xproof.app/llms.txt)
- [Pricing API](https://xproof.app/api/pricing)
- [MCP Registry](https://registry.modelcontextprotocol.io/v0/servers?search=xproof)
- [OpenClaw Skill](https://github.com/jasonxkensei/xproof-openclaw-skill)
- [GitHub Action](https://github.com/marketplace/actions/xproof-certify)
- [MultiversX Explorer](https://explorer.multiversx.com)

## License

MIT
