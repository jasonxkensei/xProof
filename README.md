<p align="center">
  <strong>xproof</strong><br>
  <em>Proof primitive for agents &amp; humans on MultiversX</em>
</p>

<p align="center">
  <a href="https://xproof.app">Website</a> &bull;
  <a href="#api-reference">API</a> &bull;
  <a href="docs/agent-integration.md">Agent Integration</a> &bull;
  <a href="docs/architecture.md">Architecture</a> &bull;
  <a href="CHANGELOG.md">Changelog</a>
</p>

---

> **Trust is programmable.**
> xproof anchors verifiable proofs of existence, authorship, and agent output on MultiversX &mdash; composable, API-first, built for both humans and autonomous agents.

---

## What is xproof?

**xproof** is a trust primitive that records SHA-256 file hashes on the [MultiversX](https://multiversx.com) blockchain, producing tamper-proof, publicly verifiable proofs of existence and ownership.

- **Client-side hashing** &mdash; SHA-256 is computed locally in the browser. Your file never leaves your device.
- **On-chain anchoring** &mdash; the hash is recorded as an immutable transaction on MultiversX mainnet.
- **Verifiable output** &mdash; PDF certificate, QR code, public proof page, and machine-readable JSON.
- **Agent-native** &mdash; discoverable and consumable by AI agents via ACP, MCP, LangChain, CrewAI, and x402.

### Why MultiversX?

MultiversX is a European, carbon-negative blockchain with 6-second finality, negligible fees, and a growing ecosystem of AI-native protocols. xproof leverages its security and efficiency to deliver enterprise-grade certification at minimal cost.

---

## Core Capabilities

| Capability | Description |
|---|---|
| **Client-Side Hashing** | SHA-256 computed in-browser. Zero data leaves your device. |
| **Blockchain Anchoring** | On-chain proof via MultiversX mainnet. |
| **MX-8004 Compliance** | Validation loop, cumulative scoring, on-chain feedback. |
| **PDF Certificates** | Downloadable certificate with QR code linking to the blockchain explorer. |
| **Public Proof Pages** | Shareable `/proof/:id` pages for independent verification. |
| **Wallet Authentication** | Native Auth via xPortal, MultiversX Web Wallet, or WalletConnect. |
| **Agent Commerce Protocol** | AI agents discover, purchase, and consume certifications programmatically. |
| **x402 Payment Protocol** | HTTP 402 native payment flow &mdash; no account needed. |
| **MCP / LangChain / CrewAI** | Ready-made tool definitions for major AI agent frameworks. |
| **Webhook Delivery** | HMAC-signed notifications with retry logic and exponential backoff. |
| **API Keys** | `pm_`-prefixed bearer tokens for programmatic access with per-key rate limiting. |
| **LLM Discovery** | `llms.txt`, OpenAI plugin manifest, MCP manifest, agent.json &mdash; served automatically. |

---

## For Developers

xproof is API-first. A single `POST /api/proof` call with an API key certifies a file hash on-chain and returns a structured proof.

```bash
curl -X POST https://xproof.app/api/proof \
  -H "Authorization: Bearer pm_your_api_key" \
  -H "Content-Type: application/json" \
  -d '{"file_hash": "sha256_of_your_file", "filename": "report.pdf"}'
```

Full API documentation: [docs/api-reference.md](docs/api-reference.md)

## For Agents

xproof is designed to be discovered and consumed by autonomous agents. It exposes machine-readable endpoints across multiple standards:

| Endpoint | Standard | Purpose |
|---|---|---|
| `/.well-known/ai-plugin.json` | OpenAI Plugin | ChatGPT plugin manifest |
| `/.well-known/mcp.json` | MCP | Model Context Protocol manifest |
| `/.well-known/agent.json` | Agent Protocol | Agent discovery manifest |
| `/llms.txt` | llms.txt | LLM-friendly summary |
| `/agent-tools/langchain.py` | LangChain | Python tool definition |
| `/agent-tools/crewai.py` | CrewAI | Python tool definition |

Agents can also pay per-proof via x402 (HTTP 402) without needing an account or API key.

For detailed integration guides, see [docs/agent-integration.md](docs/agent-integration.md).

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
| **PDF** | jsPDF with QR code generation |

---

## Project Structure

```
xproof/
  client/
    src/
      components/        # UI components (wallet modal, shadcn/ui)
      lib/               # Client utilities
        hashFile.ts          # SHA-256 client-side hashing
        generateProofPDF.ts  # PDF certificate generation
        multiversxTransaction.ts  # Transaction building
        walletAuth.ts        # Wallet authentication helpers
      pages/
        landing.tsx          # Homepage
        certify.tsx          # File certification flow
        dashboard.tsx        # User certifications history
        proof.tsx            # Public proof verification page
        agents.tsx           # AI agent integration showcase
        settings.tsx         # User settings & API keys
        legal/               # Legal pages
  server/
    index.ts             # Express server entry point
    routes.ts            # All API routes (REST + ACP + discovery)
    db.ts                # Database connection (Drizzle + Neon)
    blockchain.ts        # MultiversX blockchain interactions
    webhook.ts           # HMAC-signed webhook delivery
    certificateGenerator.ts  # Server-side PDF generation
    nativeAuth.ts        # Native Auth token verification
    walletAuth.ts        # Session & wallet middleware
    pricing.ts           # Dynamic pricing logic
    xmoney.ts            # xMoney payment integration
    storage.ts           # Storage interface
  shared/
    schema.ts            # Database schema (Drizzle) + Zod validators + ACP types
```

---

## Quick Start

### Prerequisites

- Node.js 20+
- PostgreSQL database (or a Neon account)
- A MultiversX wallet (for signing transactions)

### Installation

```bash
git clone https://github.com/jasonxkensei/xproof.git
cd xproof
npm install
```

### Environment Variables

```bash
cp .env.example .env
```

See [docs/environment-variables.md](docs/environment-variables.md) for detailed descriptions.

### Database Setup

```bash
npm run db:push
```

### Development

```bash
npm run dev
```

The app starts on `http://localhost:5000` with hot-reload for both frontend and backend.

### Production Build

```bash
npm run build
npm start
```

---

## API Reference

Full documentation: [docs/api-reference.md](docs/api-reference.md)

### Core Endpoints

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/api/proof` | API Key | Certify a file hash (single call) |
| `POST` | `/api/batch` | API Key | Batch certification |
| `POST` | `/api/auth/wallet/sync` | - | Authenticate via Native Auth token |
| `GET` | `/api/auth/me` | Wallet | Get current user |
| `POST` | `/api/certifications` | Wallet | Create a certification (web flow) |
| `GET` | `/api/certifications` | Wallet | List user certifications |
| `GET` | `/api/proof/:id` | - | Get public proof data |
| `GET` | `/api/certificates/:id.pdf` | - | Download PDF certificate |

### Agent Commerce Protocol (ACP)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/api/acp/products` | - | Discover available products |
| `GET` | `/api/acp/openapi.json` | - | OpenAPI 3.0 specification |
| `POST` | `/api/acp/checkout` | API Key | Start a checkout session |
| `POST` | `/api/acp/confirm` | API Key | Confirm transaction execution |
| `GET` | `/api/acp/health` | - | Health check |

### API Keys

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/api/keys` | Wallet | Generate API key |
| `GET` | `/api/keys` | Wallet | List API keys |
| `DELETE` | `/api/keys/:keyId` | Wallet | Revoke API key |

---

## How It Works

```
User/Agent                    xproof                     MultiversX
    |                           |                           |
    |  1. Submit file/hash      |                           |
    |-------------------------->|                           |
    |                           |                           |
    |  2. SHA-256 verified      |                           |
    |     (client-side or API)  |                           |
    |                           |                           |
    |  3. Transaction signed    |                           |
    |     & broadcast           |                           |
    |-------------------------->|                           |
    |                           |  4. Anchored on-chain     |
    |                           |-------------------------->|
    |                           |                           |
    |                           |  5. Confirmed (6s)        |
    |                           |<--------------------------|
    |                           |                           |
    |  6. Proof returned        |                           |
    |     (PDF + JSON + URL)    |                           |
    |<--------------------------|                           |
```

---

## Pricing

**$0.05 per certification** &mdash; pay-as-you-go. No subscriptions, no monthly fees.

Payment accepted in **EGLD** via **xMoney**, fiat via **Stripe**, or **USDC on Base** via x402.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to contribute to xproof.

## Security

See [SECURITY.md](SECURITY.md) for our security policy and how to report vulnerabilities.

## Code of Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

---

## Legal

Copyright (c) 2025-2026 xproof. All rights reserved.

This software is proprietary. Unauthorized copying, modification, distribution, or use of this software, via any medium, is strictly prohibited without prior written permission from the copyright holder.

For licensing inquiries, contact the repository owner.
