# xproof — Proof primitive for agents & humans on MultiversX

## Overview
xproof is a trust primitive that anchors verifiable proofs of existence, authorship, and agent output on the MultiversX blockchain. It is API-first, composable, and built for both human users and autonomous agents. The project aims to provide a robust and verifiable proof system within the MultiversX ecosystem, catering to the growing needs of decentralized applications and agent-based systems.

## Recent Changes (Feb 26, 2026)
- **Unified discovery entry point**: New `/.well-known/xproof.json` — compact, machine-readable JSON with `quickstart` (trial/x402/api_key step-by-step), all endpoints, protocols, pricing, and docs. Referenced from sitemap and `agent.json`. Priority 0.9 in sitemap.
- **Improved agent discoverability**: `GET /api/trial` and `GET /api/agent` endpoints return trial registration instructions. 402 responses include `free_trial` hint. 401 responses include structured `options` array (trial/api_key/x402). `llms.txt` now opens with "Free Trial — Start Here" as 2nd section.
- **Blockchain signing fixed**: `@noble/ed25519` v3 requires explicit SHA-512 config — fixed in `server/blockchain.ts`. Nonce bug fixed: switched from `/address/` (gateway path) to `/accounts/` (API path) returning correct nonce at top level.
- **Stats/metrics fixed**: Certification `by_source` now correctly separates `api` (system agent), `trial` (trial users), and `user` (wallet users). Admin dashboard shows 3-way breakdown. Active Agents counter excludes trial users.
- **Agent trial mode**: New `POST /api/agent/register` endpoint for zero-friction agent onboarding. Agents send `{"agent_name": "..."}`, receive an API key (`pm_xxx`) with 10 free certifications. No wallet, no browser, no payment needed. Trial quota tracked in `users` table (`is_trial`, `trial_quota`, `trial_used`). Both `/api/proof` and `/api/batch` enforce quota checks. When trial exhausted, returns 402 with upgrade instructions (x402 or ACP). Discovery documents (`agent.json`, `llms.txt`, `llms-full.txt`) updated with trial info. Admin dashboard shows trial agent count. Rate limited: 3 registrations/hour/IP.

## Recent Changes (Feb 23, 2026)
- **Server-side payment verification**: Added on-chain transaction verification before confirming certifications. Server now calls the MultiversX API to verify: transaction exists, status is "success", receiver is the xproof wallet, and payment value matches the certification price (2% tolerance). Both `/api/certifications` and `/api/blockchain/broadcast` routes enforce verification. PDF certificate download blocked for pending payments. Files: `server/verifyTransaction.ts`, `server/routes.ts`.
- **Transaction confirmation notifications**: Added blockchain transaction status polling and notification system. After certifying a file, the app now polls the MultiversX API every 3s (up to 3 min) and shows a toast + visual indicator when the transaction is confirmed or fails. Uses scoped `watchTransaction()` to avoid cross-transaction interference and `notifyOnce` deduplication. Files: `client/src/lib/multiversxTransaction.ts`, `client/src/pages/certify.tsx`.

## Recent Changes (Feb 21, 2026)
- **Stripe removed**: Removed Stripe/card payment integration. Two active payment channels: EGLD (ACP), USDC on Base (x402).

## Recent Changes (Feb 20, 2026)
- **Wallet auth fix (mainnet)**: Fixed critical bug where `server/nativeAuth.ts` pointed to DEVNET API while frontend used MAINNET. Updated to `https://api.multiversx.com` and added `xproof.app` to acceptedOrigins. Also fixed `client/src/lib/walletAuth.ts` wallet URL to mainnet.
- **Public stats page**: Transformed `/admin` into public `/stats` page accessible without authentication. New `GET /api/stats` endpoint returns aggregate metrics (certifications, webhooks, blockchain) without sensitive data (no API keys or alert config). Dashboard "Stats" button visible to all users. `/admin` route kept for backward compatibility.
- **Global tiered pricing**: Certification pricing is now dynamic and decreases globally as the platform grows. Tiers: 0-100K=$0.05, 100K-1M=$0.025, 1M+=$0.01. Centralized in `server/pricing.ts` with 60s cached DB count. All endpoints, discovery docs, frontend pages, and prerender updated to use dynamic pricing.
- **Public pricing endpoint**: `GET /api/pricing` returns current price, tier info, total certifications, and all tier definitions.
- **Admin dashboard access**: `/api/auth/me` now returns `isAdmin` boolean. Dashboard shows Admin button for wallets listed in `ADMIN_WALLETS` env var.

## Recent Changes (Feb 18, 2026)
- **Universal agent compatibility**: All discovery endpoints (`.well-known/agent.json`, `.well-known/mcp.json`, `ai-plugin.json`, MCP `discover_services`, `llms.txt`, `llms-full.txt`) now explicitly surface x402/openx402 compatibility, OpenClaw skill link, and full list of supported protocols (MCP, ACP, x402, MX-8004, OpenAI Plugin, LangChain, CrewAI).
- **Agent Integrations page**: New `/agents` page listing all supported protocols and developer tools with links to docs, OpenClaw skill, GitHub Action, and REST API.
- **Landing page "Universal Compatibility" section**: New section showcasing MCP, x402, ACP, MX-8004, OpenClaw, and GitHub Action with link to full integrations page.
- **OpenClaw skill published**: `github.com/jasonxkensei/xproof-openclaw-skill` — ClawHub-standard skill with SKILL.md, certify.sh, API reference.
- **Conway/openx402 positioning**: xProof is x402-compatible, meaning any Conway automaton or x402-enabled agent can pay and certify via HTTP 402 with USDC on Base — no API key needed.

## Recent Changes (Feb 16, 2026)
- **Webhook anti-replay**: Added `verifyWebhookSignature()` with asymmetric timestamp validation (+1min future / -5min past), timing-safe HMAC comparison, and documented signature contract.
- **Structured JSON logging**: All backend logs now emit structured JSON (`server/logger.ts`) with timestamp, level, service, requestId, route, method, message, metadata. RequestId middleware correlates requests end-to-end including into tx_queue payloads.
- **TX queue alerting**: New `server/txAlerts.ts` monitors failed transactions with threshold + cooldown (env: `TX_ALERT_THRESHOLD`, `TX_ALERT_COOLDOWN_MINUTES`, `TX_ALERT_WINDOW_MINUTES`, `TX_ALERT_WEBHOOK_URL`). Categorizes errors: nonce, gateway_timeout, contract_revert, unknown.
- **Blockchain latency monitoring**: Rolling 1h window percentiles (p50/p95/p99) in `server/metrics.ts`. Health endpoint (`/health`) exposes `blockchain_latency` summary (avg_ms, p95_ms, queue_depth, failure_rate).

## User Preferences
Preferred communication style: Simple, everyday language.
Positioning tone: "Hybride stratégique" — precise, credible, strategic, mixing institutional authority with tech-forward language.

## System Architecture

### Frontend
The frontend is built with React 18 and TypeScript, using Vite for development and optimized builds. It utilizes Wouter for routing and TanStack Query v5 for data management. The UI follows a "New York" aesthetic with Shadcn/ui (Radix UI primitives) and Tailwind CSS, featuring an emerald green primary color and dark mode support. Typography uses Space Grotesk and Inter. Form handling is managed with React Hook Form and Zod validation.

### Backend
The backend utilizes Express.js with TypeScript and Node.js. It integrates MultiversX SDK-dApp for secure, cryptographic authentication using Native Auth, supporting various wallets. Authentication involves client-side signature generation and backend verification to establish secure user sessions, stored in PostgreSQL. A pre-rendering middleware (`server/prerender.ts`) detects crawler User-Agents for SEO purposes, serving full semantic HTML for specific routes while normal browser requests access the React SPA.

### API Architecture
RESTful APIs are provided under `/api/*`, with middleware for logging and error handling. Protected routes enforce wallet authentication. Key API endpoints include wallet synchronization, user data retrieval, session logout, and certification services. File processing involves client-side SHA-256 hashing for privacy and performance, sending only metadata to the server.

### Blockchain Integration
xproof integrates with the MultiversX blockchain for immutable proof storage. It supports both XPortal (user-signed transactions) and an optional server-side signing mode, handling transaction signing, broadcasting, and generation of explorer URLs across Mainnet, Devnet, and Testnet.

### MX-8004 Integration (Trustless Agents Standard)
xproof is natively integrated with MX-8004, the MultiversX Trustless Agents Standard, providing:
- **Identity Registry**: Agent registration with soulbound NFTs.
- **Validation Registry**: Full ERC-8004 validation loop for certifications, reaching "Verified" status on-chain.
- **Reputation Registry**: On-chain reputation scoring for agents.
- **Validation Views**: Query job lifecycle from on-chain.
- **Reputation Views**: Query agent reputation and feedback.
- **Persistent Transaction Queue**: All MX-8004 blockchain transactions are processed through a PostgreSQL-backed queue (`tx_queue` table) to manage nonce contention and ensure reliable execution with exponential backoff retry.
- **Smart Retry**: Execution resumes from the failed step on retry, saving gas and time.
- MX-8004 job registration happens asynchronously after certification.

### Data Storage
PostgreSQL, hosted on Neon, is used for data persistence. Drizzle ORM provides type-safe database operations. Key tables include `users`, `certifications`, `sessions`, and `tx_queue`. Drizzle Kit manages database migrations.

### Agent Commerce Protocol (ACP)
xproof implements the ACP to allow AI agents to programmatically interact with its certification services. It provides endpoints for product discovery, OpenAPI specification, checkout, transaction confirmation, and status checks. The pricing model is $0.05 per certification, paid in EGLD. API key management is included for secure agent access and rate limiting.

### x402 Payment Protocol (HTTP 402)
xproof supports the x402 payment protocol for per-request payments via HTTP, eliminating the need for an account or API key. Endpoints POST /api/proof and POST /api/batch accept x402 payments at $0.05 per certification in USDC on Base.

### Simplified Agent API & Batch Certification
A single-call certification endpoint (POST /api/proof) simplifies the process for AI agents, accepting file metadata and handling blockchain recording server-side. Batch certification (POST /api/batch) allows certifying up to 50 files in a single API call.

### Verification Badges
Dynamic SVG badges (shields.io-style) display certification status ("Verified", "Pending", "Not Found") and respect privacy settings. Markdown snippets are available for embedding.

### GitHub Action
A Composite GitHub Action integrates xproof into CI/CD pipelines, hashing build artifacts and calling the certification API.

### Webhook Notifications
xProof sends POST notifications to specified `webhook_url`s upon on-chain proof confirmation, including proof details and blockchain information. Security is ensured with HMAC-SHA256 signed headers, and a retry policy is implemented.

### LLM-Ready Routes & AI Agent Discovery
The platform offers comprehensive machine-readable documentation and endpoints for AI agent discovery and integration:
- **MCP Server**: Live MCP JSON-RPC 2.0 endpoint with tools like `certify_file`, `verify_proof`.
- **Discovery Endpoints**: `.well-known` files for canonical specification, OpenAI ChatGPT plugin manifest, Model Context Protocol manifest, Agent Protocol manifest, and LLM-friendly summaries.
- **Agent Tool Integrations**: LangChain, CrewAI, and OpenAPI tool definitions.
- **Proof Access**: Structured JSON and Markdown proofs.
- **Documentation**: Explanations and API guides.

### Monitoring & Admin
- **Health endpoint**: Provides structured component checks, operational metrics, and status.
- **Metrics module**: Tracks transaction latency, success/failure rates, and MX-8004 queue size.
- **Admin stats**: Protected by wallet authentication, provides certification counts, source breakdown, blockchain status, API key usage, and webhook delivery stats.
- **Admin dashboard**: React page displaying system health and various statistics with auto-refresh.

## External Dependencies

### Payment Processing
- **EGLD & USDC**: Payments via EGLD (ACP on MultiversX) and USDC on Base (x402).

### Blockchain Services
- **MultiversX blockchain**: Core blockchain for proof-of-existence.
- **MultiversX Explorer**: For transaction verification links.

### Third-Party UI Libraries
- Radix UI primitives
- Lucide React (icon system)
- date-fns
- Vaul (drawer components)

### Font Loading
- Google Fonts CDN (Space Grotesk, Inter)

### Environment Configuration
- `DATABASE_URL`
- `SESSION_SECRET`
- `MULTIVERSX_PRIVATE_KEY`, `MULTIVERSX_SENDER_ADDRESS`, `MULTIVERSX_CHAIN_ID`, `MULTIVERSX_GATEWAY_URL`
- `MX8004_IDENTITY_REGISTRY`, `MX8004_VALIDATION_REGISTRY`, `MX8004_REPUTATION_REGISTRY`, `MX8004_XPROOF_AGENT_NONCE`
- `ADMIN_WALLETS`
- `REPL_ID`