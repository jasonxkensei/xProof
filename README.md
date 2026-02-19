<p align="center">
  <strong>xProof</strong><br>
  <em>Trust primitive for AI agents & humans on MultiversX</em>
</p>

<p align="center">
  <a href="https://xproof.app">Live App</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#api-reference">API</a> &bull;
  <a href="#for-agents">Agent Integration</a> &bull;
  <a href="docs/architecture.md">Architecture</a> &bull;
  <a href="CHANGELOG.md">Changelog</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/blockchain-MultiversX-23F7931E?style=flat-square" alt="MultiversX" />
  <img src="https://img.shields.io/badge/protocol-MCP-blue?style=flat-square" alt="MCP" />
  <img src="https://img.shields.io/badge/protocol-x402-purple?style=flat-square" alt="x402" />
  <img src="https://img.shields.io/badge/protocol-ACP-orange?style=flat-square" alt="ACP" />
  <img src="https://img.shields.io/badge/standard-MX--8004-teal?style=flat-square" alt="MX-8004" />
  <img src="https://img.shields.io/badge/price-$0.05%2Fcert-brightgreen?style=flat-square" alt="$0.05/cert" />
</p>

---

> **Trust is programmable.**
> xProof anchors verifiable proofs of existence, authorship, and agent output on the MultiversX blockchain -- composable, API-first, built for both humans and autonomous agents.

---

## What is xProof?

**xProof** is a trust primitive. It records SHA-256 file hashes on the [MultiversX](https://multiversx.com) blockchain, producing tamper-proof, publicly verifiable proofs of existence and ownership.

- **Client-side hashing** -- SHA-256 is computed locally. Your file never leaves your device.
- **On-chain anchoring** -- the hash is recorded as an immutable transaction on MultiversX mainnet with 6-second finality.
- **Verifiable output** -- PDF certificate, QR code, public proof page, machine-readable JSON, and embeddable badge.
- **Agent-native** -- discoverable and consumable by AI agents via MCP, ACP, x402, LangChain, CrewAI, Conway/Automaton, and OpenClaw.
- **MX-8004 compliant** -- full Trustless Agents Standard integration with on-chain validation loop and reputation scoring.

### Why MultiversX?

MultiversX is a European, carbon-negative blockchain with 6-second finality, negligible fees ($0.001/tx), and a growing ecosystem of AI-native protocols. xProof leverages its security and efficiency to deliver enterprise-grade certification at minimal cost.

---

## Pricing

**$0.05 per certification** -- pay-as-you-go. No subscriptions. No monthly fees.

| Payment Method | Currency | Account Required |
|---|---|---|
| **x402** (HTTP 402) | USDC on Base | No |
| **xMoney** | EGLD | No |
| **Stripe** | Fiat (USD/EUR) | No |

Agents can pay per-proof via x402 with zero onboarding -- send a request, receive payment requirements, sign, resend.

---

## Quick Start

### Use the API (fastest)

```bash
# Certify a file in one call
curl -X POST https://xproof.app/api/proof \
  -H "Authorization: Bearer pm_your_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "filename": "report.pdf",
    "author_name": "Your Name"
  }'
```

Response:

```json
{
  "proof_id": "uuid",
  "status": "certified",
  "file_hash": "e3b0c44...",
  "verify_url": "https://xproof.app/proof/uuid",
  "certificate_url": "https://xproof.app/api/certificates/uuid.pdf",
  "proof_json_url": "https://xproof.app/proof/uuid.json",
  "blockchain": {
    "network": "MultiversX",
    "transaction_hash": "txhash...",
    "explorer_url": "https://explorer.multiversx.com/transactions/txhash..."
  }
}
```

### Use the Web App

Go to [xproof.app](https://xproof.app), connect your MultiversX wallet, drop a file, certify. Done.

### Self-Host

```bash
git clone https://github.com/jasonxkensei/xproof.git
cd xproof
npm install
cp .env.example .env   # configure your environment
npm run db:push         # initialize database
npm run dev             # starts on http://localhost:5000
```

**Prerequisites:** Node.js 20+, PostgreSQL (or Neon), MultiversX wallet.

See [docs/environment-variables.md](docs/environment-variables.md) for configuration details.

---

## For Developers

### POST /api/proof -- Single Certification

Certify one file hash on-chain in a single API call.

```bash
curl -X POST https://xproof.app/api/proof \
  -H "Authorization: Bearer pm_your_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "file_hash": "<64-char-sha256-hex>",
    "filename": "output.txt",
    "author_name": "Agent Name",
    "webhook_url": "https://your-server.com/webhook"
  }'
```

| Field | Type | Required | Description |
|---|---|---|---|
| `file_hash` | string | Yes | SHA-256 hex hash (exactly 64 characters) |
| `filename` | string | Yes | Original filename |
| `author_name` | string | No | Defaults to "AI Agent" |
| `webhook_url` | string | No | HTTPS URL for on-chain confirmation callback |

### POST /api/batch -- Batch Certification

Certify up to 50 files in a single call.

```bash
curl -X POST https://xproof.app/api/batch \
  -H "Authorization: Bearer pm_your_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "files": [
      {"file_hash": "<hash1>", "filename": "file1.txt"},
      {"file_hash": "<hash2>", "filename": "file2.py"}
    ],
    "author_name": "Agent Name"
  }'
```

### Verification

| Endpoint | Returns |
|---|---|
| `GET /api/proof/:id` | Full certification record (JSON) |
| `GET /proof/:id.json` | Structured proof document (JSON) |
| `GET /proof/:id` | Human-readable proof page (HTML) |
| `GET /api/certificates/:id.pdf` | PDF certificate with QR code |
| `GET /badge/:id` | Dynamic SVG badge (shields.io style) |

### Webhooks

When a proof is anchored on-chain, xProof sends a POST to your `webhook_url` with HMAC-SHA256 signature in the `X-Webhook-Signature` header. Retry policy: 3 attempts with exponential backoff.

### API Keys

Generate API keys from the [Settings](https://xproof.app/settings) page after connecting your wallet. Keys use the `pm_` prefix and support per-key rate limiting.

---

## For Agents

xProof is designed to be discovered, consumed, and paid by autonomous agents across every major protocol.

### Universal Compatibility

| Protocol | Endpoint / Resource | Description |
|---|---|---|
| **MCP** | `POST /mcp` | JSON-RPC 2.0 endpoint with `certify_file` and `verify_proof` tools |
| **x402** | `POST /api/proof`, `POST /api/batch` | HTTP 402 payment flow -- no account needed |
| **ACP** | `GET /api/acp/products` | Agent Commerce Protocol -- discover, checkout, confirm |
| **MX-8004** | On-chain registries | Trustless Agents Standard -- validation loop + reputation |
| **OpenAI Plugin** | `GET /.well-known/ai-plugin.json` | ChatGPT plugin manifest |
| **MCP Manifest** | `GET /.well-known/mcp.json` | Model Context Protocol discovery |
| **Agent Protocol** | `GET /.well-known/agent.json` | Agent discovery manifest |
| **LangChain** | `GET /agent-tools/langchain.py` | Python tool definition |
| **CrewAI** | `GET /agent-tools/crewai.py` | Python tool definition |
| **llms.txt** | `GET /llms.txt`, `GET /llms-full.txt` | LLM-friendly documentation |

### x402 -- Pay Per Proof, No Account

Any agent can certify without an API key using the x402 payment protocol:

1. Send `POST /api/proof` without auth
2. Receive HTTP 402 with payment requirements (USDC on Base, `eip155:8453`)
3. Sign the payment and resend with `X-PAYMENT` header
4. Receive the proof

Cost: **$0.05 per certification**. No signup. No API key. No account.

### MCP -- Model Context Protocol

xProof exposes a live MCP server at `POST /mcp` with two tools:

- `certify_file` -- certify a file hash on MultiversX
- `verify_proof` -- verify an existing certification

Any MCP-compatible agent can discover and call these tools directly.

### ACP -- Agent Commerce Protocol

Full commerce flow for programmatic purchasing:

```
GET  /api/acp/products       # Discover products and pricing
GET  /api/acp/openapi.json   # OpenAPI 3.0 specification
POST /api/acp/checkout       # Start checkout session
POST /api/acp/confirm        # Confirm transaction
GET  /api/acp/health          # Health check
```

### MX-8004 -- MultiversX Trustless Agents Standard

xProof is natively integrated with MX-8004, providing:

- **Identity Registry** -- agent registration with soulbound NFTs
- **Validation Registry** -- full validation loop for certifications reaching "Verified" status on-chain
- **Reputation Registry** -- cumulative on-chain reputation scoring with feedback
- **Persistent TX Queue** -- PostgreSQL-backed transaction queue with nonce management and exponential backoff retry

Every certification registered through xProof can be validated and scored on-chain, building a verifiable reputation for the certifying agent.

### Conway/Automaton Skill

xProof ships a ready-made skill for [Conway Automatons](https://github.com/Conway-Research/automaton):

```
skills/xproof/SKILL.md
```

An Automaton installs the skill and can immediately certify its outputs on MultiversX -- proving the value it creates to its creator, to clients, and to peer agents. This aligns directly with the Automaton survival-by-work model.

### OpenClaw Skill

ClawHub-standard skill for the OpenClaw ecosystem:

- Repository: [`github.com/jasonxkensei/xproof-openclaw-skill`](https://github.com/jasonxkensei/xproof-openclaw-skill)
- Includes `SKILL.md`, `certify.sh`, and full API reference

### GitHub Action

Integrate xProof into your CI/CD pipeline:

```yaml
- uses: jasonxkensei/xproof/github-action@main
  with:
    api_key: ${{ secrets.XPROOF_API_KEY }}
    files: dist/**
```

Hashes build artifacts and certifies them on MultiversX automatically on every deployment.

See [`github-action/README.md`](github-action/README.md) for full documentation.

---

## How It Works

```
User/Agent                    xProof                     MultiversX
    |                           |                           |
    |  1. Submit file hash      |                           |
    |     (API / Web / MCP)     |                           |
    |-------------------------->|                           |
    |                           |                           |
    |  2. SHA-256 validated     |                           |
    |     (client-side or API)  |                           |
    |                           |                           |
    |                           |  3. Transaction signed    |
    |                           |     & broadcast           |
    |                           |-------------------------->|
    |                           |                           |
    |                           |  4. Anchored on-chain     |
    |                           |     (6s finality)         |
    |                           |<--------------------------|
    |                           |                           |
    |  5. Proof returned        |  6. MX-8004 validation    |
    |     (JSON + PDF + URL)    |     registered            |
    |<--------------------------|-------------------------->|
    |                           |                           |
    |  7. Webhook notification  |                           |
    |     (HMAC-signed)         |                           |
    |<--------------------------|                           |
```

---

## Core Capabilities

| Capability | Description |
|---|---|
| **Client-Side Hashing** | SHA-256 computed in-browser. Zero data leaves your device. |
| **Blockchain Anchoring** | Immutable proof on MultiversX mainnet. |
| **MX-8004 Compliance** | On-chain validation loop, reputation scoring, soulbound identity. |
| **x402 Payments** | HTTP 402 native payment -- USDC on Base, no account needed. |
| **PDF Certificates** | Downloadable certificate with QR code linking to blockchain explorer. |
| **Public Proof Pages** | Shareable `/proof/:id` pages for independent verification. |
| **Verification Badges** | Dynamic SVG badges (shields.io style) with embeddable Markdown. |
| **Wallet Authentication** | Native Auth via xPortal, MultiversX Web Wallet, WalletConnect. |
| **Agent Commerce Protocol** | Agents discover, purchase, and consume certifications programmatically. |
| **MCP Server** | JSON-RPC 2.0 endpoint with `certify_file` and `verify_proof` tools. |
| **LangChain / CrewAI** | Ready-made Python tool definitions. |
| **Webhook Delivery** | HMAC-SHA256 signed notifications with retry and exponential backoff. |
| **API Keys** | `pm_`-prefixed bearer tokens with per-key rate limiting. |
| **LLM Discovery** | `llms.txt`, OpenAI plugin, MCP manifest, agent.json -- all served. |
| **GitHub Action** | CI/CD integration -- hash and certify build artifacts automatically. |
| **Conway/Automaton Skill** | Ready-made SKILL.md for sovereign agent output certification. |
| **OpenClaw Skill** | ClawHub-standard skill with shell script and API reference. |

---

## API Reference

Full documentation: [docs/api-reference.md](docs/api-reference.md)

### Core Endpoints

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/api/proof` | API Key / x402 | Certify a file hash (single call) |
| `POST` | `/api/batch` | API Key / x402 | Batch certification (up to 50 files) |
| `GET` | `/api/proof/:id` | Public | Get proof data |
| `GET` | `/proof/:id.json` | Public | Structured proof document |
| `GET` | `/proof/:id` | Public | Human-readable proof page |
| `GET` | `/api/certificates/:id.pdf` | Public | Download PDF certificate |
| `GET` | `/badge/:id` | Public | Dynamic SVG badge |

### Authentication

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/api/auth/wallet/sync` | Native Auth | Authenticate via wallet signature |
| `GET` | `/api/auth/me` | Session | Get current user |
| `POST` | `/api/auth/logout` | Session | End session |

### Agent Commerce Protocol

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/api/acp/products` | Public | Discover products and pricing |
| `GET` | `/api/acp/openapi.json` | Public | OpenAPI 3.0 specification |
| `POST` | `/api/acp/checkout` | API Key | Start checkout session |
| `POST` | `/api/acp/confirm` | API Key | Confirm transaction |
| `GET` | `/api/acp/health` | Public | Health check |

### API Key Management

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/api/keys` | Wallet | Generate API key |
| `GET` | `/api/keys` | Wallet | List API keys |
| `DELETE` | `/api/keys/:keyId` | Wallet | Revoke API key |

### MCP Server

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/mcp` | API Key | JSON-RPC 2.0 (tools: `certify_file`, `verify_proof`) |

### Discovery

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/.well-known/ai-plugin.json` | OpenAI plugin manifest |
| `GET` | `/.well-known/mcp.json` | MCP manifest |
| `GET` | `/.well-known/agent.json` | Agent Protocol manifest |
| `GET` | `/llms.txt` | LLM-friendly summary |
| `GET` | `/llms-full.txt` | Full LLM documentation |
| `GET` | `/agent-tools/langchain.py` | LangChain tool definition |
| `GET` | `/agent-tools/crewai.py` | CrewAI tool definition |

### Health & Monitoring

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/api/acp/health` | Public | ACP health check |
| `GET` | `/api/admin/stats` | Admin | Certification counts, API usage, queue stats |

---

## Tech Stack

| Layer | Technology |
|---|---|
| **Frontend** | React 18, TypeScript, Vite, Tailwind CSS, Shadcn/ui, Wouter, TanStack Query v5 |
| **Backend** | Node.js, Express.js, TypeScript |
| **Database** | PostgreSQL (Neon), Drizzle ORM |
| **Blockchain** | MultiversX SDK (sdk-core, sdk-dapp, sdk-network-providers, sdk-wallet) |
| **Payments** | xMoney (EGLD), Stripe (fiat), x402 (USDC on Base) |
| **Auth** | MultiversX Native Auth (cryptographic wallet signatures) |
| **Agent Protocols** | MCP, ACP, x402, MX-8004, OpenAI Plugin, LangChain, CrewAI |
| **PDF** | jsPDF with QR code generation |
| **Monitoring** | Structured JSON logging, transaction latency percentiles, alerting |

---

## Project Structure

```
xproof/
  client/
    src/
      components/              # UI components (wallet modal, shadcn/ui)
      lib/
        hashFile.ts            # SHA-256 client-side hashing
        generateProofPDF.ts    # PDF certificate generation
        multiversxTransaction.ts  # Transaction building
        walletAuth.ts          # Wallet authentication helpers
      pages/
        landing.tsx            # Homepage
        certify.tsx            # File certification flow
        dashboard.tsx          # User certifications history
        proof.tsx              # Public proof verification page
        agents.tsx             # Agent integration showcase
        settings.tsx           # User settings & API keys
        admin.tsx              # Admin dashboard
  server/
    index.ts                   # Express server entry point
    routes.ts                  # All API routes (REST + ACP + MCP + discovery)
    db.ts                      # Database connection (Drizzle + Neon)
    blockchain.ts              # MultiversX blockchain interactions
    mx8004.ts                  # MX-8004 Trustless Agents Standard
    mcp.ts                     # MCP server implementation
    x402.ts                    # x402 payment protocol
    webhook.ts                 # HMAC-signed webhook delivery
    txQueue.ts                 # Persistent transaction queue
    txAlerts.ts                # Transaction failure alerting
    metrics.ts                 # Blockchain latency monitoring
    logger.ts                  # Structured JSON logging
    certificateGenerator.ts    # Server-side PDF generation
    nativeAuth.ts              # Native Auth token verification
    walletAuth.ts              # Session & wallet middleware
    pricing.ts                 # Dynamic pricing logic
    xmoney.ts                  # xMoney payment integration
    prerender.ts               # SEO pre-rendering for crawlers
    reliability.ts             # Rate limiting
  shared/
    schema.ts                  # Database schema (Drizzle) + Zod validators + ACP types
  github-action/               # Composite GitHub Action for CI/CD
  openclaw-skill/              # OpenClaw ecosystem skill
  skills/
    xproof/                    # Conway/Automaton skill
  docs/                        # Documentation
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

See [SECURITY.md](SECURITY.md) for our security policy and how to report vulnerabilities.

## Code of Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

---

## Legal

Copyright (c) 2025-2026 xProof. All rights reserved.

This software is proprietary. Unauthorized copying, modification, distribution, or use of this software, via any medium, is strictly prohibited without prior written permission from the copyright holder.

For licensing inquiries, contact the repository owner.
