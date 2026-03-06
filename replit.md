# xproof — The on-chain notary for AI agents

## Overview
xproof is the on-chain notary for AI agents — it anchors verifiable proofs of what an agent saw, decided, and produced on the MultiversX blockchain. It serves both human users and autonomous agents by providing a robust, verifiable proof system for decentralized applications and agent-based systems within the MultiversX ecosystem. The project aims to establish trust infrastructure for the AI economy through verifiable and attributable agent outputs.

## User Preferences
Preferred communication style: Simple, everyday language.
Positioning tone: "Hybride stratégique" — precise, credible, strategic, mixing institutional authority with tech-forward language.

## System Architecture

### Frontend
The frontend is a React 18 application built with TypeScript and Vite. It uses Wouter for routing, TanStack Query v5 for data management, and Shadcn/ui (Radix UI primitives) with Tailwind CSS for styling, adhering to a "New York" aesthetic. It features an emerald green primary color, dark mode support, and uses Space Grotesk and Inter for typography. Forms are managed with React Hook Form and Zod validation. A pre-rendering middleware supports SEO.

### Backend
The backend uses Express.js, TypeScript, and Node.js. It integrates MultiversX SDK-dApp for secure Native Auth, handling client-side signature verification for user sessions stored in PostgreSQL. RESTful APIs include middleware for logging, error handling, and wallet authentication for protected routes. File processing involves client-side SHA-256 hashing.

### Blockchain Integration
xproof integrates with the MultiversX blockchain for immutable proof storage, supporting XPortal and server-side signing. It manages transaction broadcasting, explorer URL generation, and server-side verification of payments and certifications. A persistent `tx_queue` handles blockchain transactions with retry logic and nonce management.

### MX-8004 Integration (Trustless Agents Standard)
xproof is integrated with MX-8004, the MultiversX Trustless Agents Standard, providing:
-   **Identity Registry**: Agent registration with soulbound NFTs.
-   **Validation Registry**: On-chain certification validation.
-   **Reputation Registry**: On-chain reputation scoring for agents.
-   **Views**: Querying job lifecycle, agent reputation, and feedback.

### Data Storage
PostgreSQL, hosted on Neon, is used for data persistence with Drizzle ORM for type-safe operations. Key tables include `users`, `certifications`, `sessions`, `tx_queue`, and `wallet_nonces`. Drizzle Kit manages database migrations. Distributed nonce management is handled via atomic PostgreSQL `UPDATE ... RETURNING` statements to ensure autoscale safety.

### Deployment
The system is configured for autoscale on Replit. It's designed to be safe for multi-instance deployments due to atomic nonce management, atomic `tx_queue` claims, and the absence of shared in-memory state.

### Prepaid Credits System
Users can purchase prepaid credit packs with USDC on Base. The system verifies USDC transfers via viem, records purchases, and increments user credit balances. Credits are consumed for certifications before falling back to x402 payments.

### Agent Commerce Protocol (ACP) & x402 Payment Protocol
xproof implements ACP for programmatic interaction by AI agents, offering endpoints for product discovery, OpenAPI specs, checkout, and status checks. It supports x402 for per-request payments using USDC on Base, allowing certification without an account or API key.

### Agent APIs & Batch Certification
A single API endpoint (`POST /api/proof`) handles individual certifications, accepting file hash, filename, and optional structured `metadata` (JSON) for server-side blockchain recording. Batch certification (`POST /api/batch`) allows certifying up to 50 files in one call, each with optional metadata.

### Structured Metadata & Search
Certifications support an optional `metadata` field (jsonb) that accepts any JSON object. Common fields include `model_hash`, `strategy_hash`, and `version_number` for AI/trading agent use cases. All metadata fields are queryable via `GET /api/proofs/search` with parameters: `?model_hash=`, `?strategy_hash=`, `?version_number=`, `?key=&value=`, `?wallet=`. Supports pagination (`?limit=&offset=`). Metadata is returned in all proof responses.

### Verification Badges & Webhook Notifications
Dynamic SVG badges display certification status. A Composite GitHub Action integrates xproof into CI/CD pipelines. Webhooks send POST notifications upon on-chain proof confirmation with HMAC-SHA256 signed headers and retry policies.

### Agent Audit Log Standard
xProof is the canonical implementation of the Agent Audit Log Standard, providing a compliance primitive for AI agents. It requires agents to certify sessions before critical actions. This includes a dedicated audit endpoint (`POST /api/audit`), a canonical JSON Schema, a frontend audit view, blocking templates for various agent frameworks, and an MCP tool.

### LLM-Ready Routes & AI Agent Discovery
The platform offers machine-readable documentation and discovery endpoints for AI agents, including an MCP JSON-RPC 2.0 endpoint with tools like `certify_file`, `verify_proof`, `audit_agent_session`, and `.well-known` files for various specifications.

### Monitoring & Admin
A health endpoint provides component checks and metrics. A metrics module tracks performance indicators. An admin dashboard offers insights into certifications, blockchain status, API key usage, and webhook delivery stats, protected by wallet authentication. Structured JSON logging is used for backend logs.

### Agent Trust Leaderboard
A public trust registry for AI agents calculates a "Trust Score" based on confirmed certifications, recency, seniority, streaks, attestations, and transparency bonus. Agents can opt-in to public profiles. The system provides public leaderboard and agent profile pages, API endpoints for trust lookup, and dynamic SVG trust badges. The leaderboard supports server-side pagination (`?page=&limit=`), filters (`?category=&search=&attested=true&sort=`), 7-day score decay arrows, "Just promoted" badges, and agent comparison (`/compare?wallets=...`). A trust score preview card in Settings shows rank and next-level hints. The API returns `{ entries, total, page, limit, totalPages }`. Daily maintenance computes rank in `trust_score_snapshots`.

### Transparency Tiers & Audit Timeline
A 3-tier transparency model rewards agents for architectural openness: Tier 1 (identity, default), Tier 2 (≥3 certs with structured metadata like `model_hash`, `strategy_hash`), Tier 3 (≥5 audit sessions). Transparency bonus: min(50, metadata×5) + min(100, audits×15), capped at 200 pts. Public Audit Timeline at `GET /api/agents/:wallet/timeline` shows chronological certified events with type classification (cert/metadata_cert/audit) and extracted metadata fields. Frontend displays color-coded timeline with badges, model hash transitions, and explorer links. Implemented in `server/trust.ts` (`computeTransparencyBonus`, `getTransparencyTier`) and `client/src/pages/agent-profile.tsx`.

### Domain-Specific Attestations
Third-party certifying bodies can issue on-chain-anchored attestations linked to agent wallets, adding to their trust score. Features include attestation issuance, revocation, public detail pages, an MCP tool, integration with the leaderboard, expanded categories, and PDF compliance export. Additional features include agent search by attestation, issuer profiles, rate limiting for issuance, trust history, expiring attestation alerts, revocation webhooks, batch attestation, and an embeddable trust widget. A daily maintenance worker handles trust score snapshots and expiry notifications.

**Issuer Reputation Weighting** (anti-gaming): Attestation bonus is weighted by the issuer's own confirmed certification count — Newcomer (0-2 certs) = +10 pts, Active (3-9) = +25 pts, Trusted (10-29) = +40 pts, Verified (30+) = +50 pts. Issuers must have ≥ 3 confirmed on-chain certifications to issue at all. Top 3 attestations by issuer quality count (max +150). Issuer level displayed as badge on agent profile. Implemented in `server/trust.ts` (`computeAttestationBonus`) and enforced at `POST /api/attestation` in `server/routes.ts`.

### API Documentation Page
A public `/docs` page provides a comprehensive, searchable API reference with collapsible endpoint groups covering all API sections (Core, Trust & Leaderboard, Attestations, Agent Protocols, Discovery, Webhooks, Credits & Payments). Includes curl examples with copy buttons, authentication overview, and method badges. Linked from the landing page header and footer.

### Onboarding UX
First-time authenticated users see a guided onboarding card on the Dashboard with 4 steps: Connect wallet (auto-completed), Certify first file, View proof, Go public on leaderboard. Steps reflect actual user state (`isPublicProfile`, certification count). Card is dismissible via localStorage and re-openable. The landing page includes a Quick Start section with 3 integration path cards (REST API, MCP, Web Interface).

### Trial Account Claim System
Users who test xproof via `POST /api/agent/register` get a trial account with a temporary `erd1trial...` wallet. To link trial certifications and API keys to a real wallet, `POST /api/trial/claim` accepts `{ trial_api_key }` with wallet session auth. It transfers all certifications and the API key, recalculates the trust score immediately, and updates the leaderboard snapshot. The Settings page (`/settings`) includes a "Claim a trial API key" card with input and feedback. Admin endpoints `GET /api/admin/trial/orphans` and `POST /api/admin/trial/migrate` allow bulk management of orphaned trial accounts.

### Rate Limiting
Endpoint-specific rate limiters complement the global 100 req/min limit: `publicReadRateLimiter` (60/min) on agent profiles, trust lookups, and ACP discovery; `publicSearchRateLimiter` (30/min) on leaderboard, agent search, and trust history; `publicCompareRateLimiter` (20/min) on agent comparison. Defined in `server/reliability.ts`.

### ElizaOS Plugin NPM Package
The `xproof-eliza-plugin` (v2.0.0) provides modular actions for ElizaOS agents, including `AUDIT_BEFORE_EXECUTE`, `CERTIFY_CONTENT`, `CERTIFY_HASH`, `CERTIFY_BATCH`, `VERIFY_PROOF`, and an audit state provider. A key feature is the `AuditRequiredError` for enforcing on-chain proof before execution.

## External Dependencies

### Payment Processing
-   EGLD (MultiversX)
-   USDC on Base

### Blockchain Services
-   MultiversX blockchain
-   MultiversX Explorer

### Third-Party UI Libraries
-   Radix UI
-   Lucide React
-   date-fns
-   Vaul

### Font Loading
-   Google Fonts CDN