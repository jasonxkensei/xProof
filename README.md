<p align="center">
  <strong>xproof</strong><br>
  <em>Blockchain Certification Service &mdash; Immutable Proof of Existence on MultiversX</em>
</p>

<p align="center">
  <a href="https://xproof.app">Website</a> &bull;
  <a href="#api-reference">API</a> &bull;
  <a href="docs/agent-integration.md">Agent Integration</a> &bull;
  <a href="docs/architecture.md">Architecture</a> &bull;
  <a href="CHANGELOG.md">Changelog</a>
</p>

---

## What is xproof?

**xproof** is a proof-of-existence service that anchors SHA-256 file hashes on the [MultiversX](https://multiversx.com) blockchain, creating tamper-proof certificates of existence and ownership.

- Upload any file. Its SHA-256 hash is computed **locally** in the browser &mdash; your file never leaves your device.
- The hash is recorded on-chain as an immutable, publicly verifiable transaction.
- A PDF certificate with QR code is generated for offline verification.
- Public proof pages allow anyone to independently verify a certification.

xproof is designed for both **human users** (via the web interface) and **AI agents** (via the Agent Commerce Protocol, MCP, LangChain tools, and more).

### Why MultiversX?

MultiversX is a European, carbon-negative blockchain with 6-second finality, negligible fees, and a growing ecosystem of AI-native protocols. xproof leverages its security and efficiency to provide enterprise-grade certification at minimal cost.

---

## Features

| Feature | Description |
|---|---|
| **Client-Side Hashing** | SHA-256 computed in-browser. Zero data leaves your device. |
| **Blockchain Anchoring** | On-chain proof via MultiversX (Mainnet / Devnet / Testnet). |
| **PDF Certificates** | Downloadable certificate with QR code linking to the blockchain explorer. |
| **Public Proof Pages** | Shareable `/proof/:id` pages for independent verification. |
| **Wallet Authentication** | Native Auth via xPortal, MultiversX Web Wallet, or WalletConnect. |
| **Agent Commerce Protocol** | AI agents can discover, purchase, and use certifications programmatically. |
| **MCP / LangChain / CrewAI** | Ready-made tool definitions for major AI agent frameworks. |
| **Pay Per Use** | $0.05 per certification, paid in EGLD via xMoney. |
| **API Keys** | Generate `pm_` prefixed bearer tokens for programmatic access. |
| **LLM Discovery** | `llms.txt`, OpenAI plugin manifest, MCP manifest, agent.json &mdash; all served automatically. |

---

## Tech Stack

| Layer | Technology |
|---|---|
| **Frontend** | React 18, TypeScript, Vite, Tailwind CSS, Shadcn/ui, Wouter, TanStack Query v5 |
| **Backend** | Node.js, Express.js, TypeScript |
| **Database** | PostgreSQL (Neon), Drizzle ORM |
| **Blockchain** | MultiversX SDK (sdk-core, sdk-dapp, sdk-network-providers, sdk-wallet) |
| **Payments** | xMoney (EGLD payments on MultiversX) |
| **Auth** | MultiversX Native Auth (cryptographic wallet signatures) |
| **PDF** | jsPDF 4.x with QR code generation |

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

Copy the example file and fill in your credentials:

```bash
cp .env.example .env
```

See [docs/environment-variables.md](docs/environment-variables.md) for detailed descriptions of each variable.

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
| `POST` | `/api/auth/wallet/sync` | - | Authenticate via Native Auth token |
| `GET` | `/api/auth/me` | Wallet | Get current user |
| `POST` | `/api/certifications` | Wallet | Create a certification |
| `GET` | `/api/certifications` | Wallet | List user certifications |
| `POST` | `/api/blockchain/broadcast` | Wallet | Broadcast signed transaction |
| `GET` | `/api/proof/:id` | - | Get public proof data |
| `GET` | `/api/certificates/:id.pdf` | - | Download PDF certificate |

### Agent Commerce Protocol (ACP)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/api/acp/products` | - | Discover available products |
| `GET` | `/api/acp/openapi.json` | - | OpenAPI 3.0 specification |
| `POST` | `/api/acp/checkout` | API Key | Start a checkout session |
| `POST` | `/api/acp/confirm` | API Key | Confirm transaction execution |
| `GET` | `/api/acp/checkout/:id` | API Key | Check checkout status |
| `GET` | `/api/acp/health` | - | Health check |

### Payments

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/api/xmoney/create-payment` | Wallet | Create EGLD payment via xMoney |
| `GET` | `/api/xmoney/order/:orderId` | Wallet | Check payment order status |

### API Keys

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/api/keys` | Wallet | Generate API key |
| `GET` | `/api/keys` | Wallet | List API keys |
| `DELETE` | `/api/keys/:keyId` | Wallet | Revoke API key |

---

## AI Agent Discovery

xproof is built to be **discovered and used by AI agents automatically**. The following machine-readable endpoints are served:

| Endpoint | Standard | Purpose |
|---|---|---|
| `/.well-known/xproof.md` | Custom | Full xproof specification |
| `/.well-known/ai-plugin.json` | OpenAI Plugin | ChatGPT plugin manifest |
| `/.well-known/mcp.json` | MCP | Model Context Protocol manifest |
| `/.well-known/agent.json` | Agent Protocol | Agent discovery manifest |
| `/llms.txt` | llms.txt | LLM-friendly summary |
| `/llms-full.txt` | llms.txt | Extended documentation for LLMs |
| `/robots.txt` | Standard | SEO with AI discovery hints |
| `/sitemap.xml` | Standard | SEO sitemap |

### Agent Tool Definitions

Ready-to-use tool definitions for popular AI frameworks:

| Endpoint | Framework | Language |
|---|---|---|
| `/agent-tools/langchain.py` | LangChain | Python |
| `/agent-tools/crewai.py` | CrewAI | Python |
| `/agent-tools/openapi-actions.json` | GPT Actions / Custom GPTs | OpenAPI 3.0 |

### Machine-Readable Proofs

| Endpoint | Format | Description |
|---|---|---|
| `/proof/:id.json` | JSON | Structured proof data |
| `/proof/:id.md` | Markdown | LLM-friendly proof |
| `/genesis.proof.json` | JSON | Genesis certification |

### Learn & Documentation

| Endpoint | Description |
|---|---|
| `/learn/proof-of-existence.md` | Concept explanation |
| `/learn/verification.md` | How to verify proofs |
| `/learn/api.md` | API usage guide |

For detailed integration guides, see [docs/agent-integration.md](docs/agent-integration.md).

---

## How It Works

```
User/Agent                    xproof                     MultiversX
    |                           |                           |
    |  1. Upload file           |                           |
    |-------------------------->|                           |
    |                           |                           |
    |  2. SHA-256 computed      |                           |
    |     locally in browser    |                           |
    |                           |                           |
    |  3. Sign transaction      |                           |
    |     (xPortal / wallet)    |                           |
    |-------------------------->|                           |
    |                           |  4. Broadcast to chain    |
    |                           |-------------------------->|
    |                           |                           |
    |                           |  5. Transaction confirmed |
    |                           |<--------------------------|
    |                           |                           |
    |  6. PDF certificate       |                           |
    |     + public proof page   |                           |
    |<--------------------------|                           |
```

---

## Pricing

**$0.05 per certification** &mdash; simple, transparent, pay-as-you-go. No subscriptions, no monthly fees.

Payment accepted in **EGLD** via **xMoney** on MultiversX, converted at real-time market rate.

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
