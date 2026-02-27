# xproof — Proof primitive for agents & humans on MultiversX

## Overview
xproof is an API-first, composable trust primitive that anchors verifiable proofs of existence, authorship, and agent output on the MultiversX blockchain. It is designed for both human users and autonomous agents, providing a robust and verifiable proof system within the MultiversX ecosystem for decentralized applications and agent-based systems. Key capabilities include immutable proof storage, support for various payment protocols (ACP, x402), and comprehensive AI agent discovery and integration tools. The project aims to provide trust infrastructure for the AI economy, enabling verifiable and attributable agent outputs.

## User Preferences
Preferred communication style: Simple, everyday language.
Positioning tone: "Hybride stratégique" — precise, credible, strategic, mixing institutional authority with tech-forward language.

## System Architecture

### Frontend
The frontend uses React 18, TypeScript, Vite, Wouter for routing, and TanStack Query v5 for data management. UI design follows a "New York" aesthetic with Shadcn/ui (Radix UI primitives), Tailwind CSS, emerald green primary color, and dark mode support. Typography uses Space Grotesk and Inter. Forms are handled with React Hook Form and Zod validation. A pre-rendering middleware supports SEO for non-browser clients.

### Backend
The backend is built with Express.js, TypeScript, and Node.js. It integrates MultiversX SDK-dApp for secure Native Auth, handling client-side signature verification for user sessions stored in PostgreSQL. RESTful APIs under `/api/*` include middleware for logging and error handling, with protected routes enforcing wallet authentication. File processing involves client-side SHA-256 hashing.

### Blockchain Integration
xproof integrates with the MultiversX blockchain for immutable proof storage, supporting both XPortal (user-signed transactions) and server-side signing. It handles transaction broadcasting and generation of explorer URLs across Mainnet, Devnet, and Testnet. Transaction verification occurs server-side to confirm successful payments and certifications. A persistent transaction queue (`tx_queue`) manages blockchain transactions, ensuring reliable execution with smart retry logic and nonce management.

### MX-8004 Integration (Trustless Agents Standard)
xproof is natively integrated with MX-8004, the MultiversX Trustless Agents Standard, providing:
-   **Identity Registry**: Agent registration with soulbound NFTs.
-   **Validation Registry**: Full ERC-8004 validation for certifications, achieving "Verified" status on-chain.
-   **Reputation Registry**: On-chain reputation scoring for agents.
-   **Views**: Query job lifecycle, agent reputation, and feedback from on-chain data.

### Data Storage
PostgreSQL, hosted on Neon, is used for data persistence with Drizzle ORM for type-safe operations. Key tables include `users`, `certifications`, `sessions`, and `tx_queue`. Drizzle Kit manages database migrations.

### Prepaid Credits System
Trial users who exhaust their 10-cert quota can purchase prepaid credit packs (USDC on Base) without needing a wallet session. Three packages: Starter (100 certs/$5), Pro (1000/$40), Business (10k/$300). Flow: `GET /api/credits/packages` → `POST /api/credits/purchase` → send USDC on Base → `POST /api/credits/confirm` with tx_hash. Server verifies the USDC Transfer event on Base mainnet via viem, records the purchase in `credit_purchases` table (unique tx_hash prevents double-claim), and increments `users.credit_balance`. Credits are consumed at `/api/proof` and `/api/batch` before falling back to x402. Response header `X-Credits-Remaining` tracks balance in real time. Logic lives in `server/credits.ts` (package constants + Base verification).

### Agent Commerce Protocol (ACP)
xproof implements the ACP for programmatic interaction by AI agents, providing endpoints for product discovery, OpenAPI specification, checkout, transaction confirmation, and status checks. It includes API key management for secure agent access and rate limiting.

### x402 Payment Protocol (HTTP 402)
xproof supports the x402 payment protocol for per-request payments, allowing certification via HTTP 402 with USDC on Base, without requiring an account or API key.

### Agent APIs & Batch Certification
A simplified single-call certification endpoint (`POST /api/proof`) accepts file metadata and handles server-side blockchain recording. Batch certification (`POST /api/batch`) allows certifying up to 50 files in a single API call.

### Verification Badges & GitHub Action
Dynamic SVG badges display certification status. A Composite GitHub Action integrates xproof into CI/CD pipelines for artifact certification.

### Webhook Notifications
xProof sends POST notifications to specified `webhook_url`s upon on-chain proof confirmation, with HMAC-SHA256 signed headers and a retry policy.

### LLM-Ready Routes & AI Agent Discovery
The platform offers machine-readable documentation and endpoints for AI agent discovery:
-   **MCP Server**: Live MCP JSON-RPC 2.0 endpoint with tools.
-   **Discovery Endpoints**: `.well-known` files for canonical specification, OpenAI ChatGPT plugin manifest, Model Context Protocol manifest, Agent Protocol manifest, and LLM-friendly summaries.
-   **Agent Tool Integrations**: LangChain, CrewAI, and OpenAPI tool definitions.

### Monitoring & Admin
A health endpoint provides structured component checks and operational metrics. A metrics module tracks transaction latency, success/failure rates, and MX-8004 queue size. An admin dashboard provides certification counts, source breakdown, blockchain status, API key usage, and webhook delivery stats, protected by wallet authentication. Structured JSON logging is used for all backend logs.

## External Dependencies

### Payment Processing
-   EGLD via ACP (MultiversX)
-   USDC on Base via x402

### Blockchain Services
-   MultiversX blockchain
-   MultiversX Explorer

### Third-Party UI Libraries
-   Radix UI primitives
-   Lucide React
-   date-fns
-   Vaul

### Font Loading
-   Google Fonts CDN

### Environment Configuration
-   `DATABASE_URL`
-   `SESSION_SECRET`
-   MultiversX API keys and configurations
-   MX-8004 registry addresses
-   `ADMIN_WALLETS`
-   `REPL_ID`