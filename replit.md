# xproof - Blockchain Certification Platform

## Overview
xproof is a Web3 certification platform designed to provide immutable and verifiable proof of digital file ownership. It achieves this by recording SHA-256 hashes of files on the MultiversX blockchain. The platform aims to offer a professional and accessible interface for non-technical users to certify various digital assets, positioning itself as a "truth primitive" for both human and AI agents. It offers features like public proof pages, certificate generation, and blockchain verification.

**Rebranding Note (Feb 2026):** Previously known as "ProofMint", the service was rebranded to "xproof" to better align with the MultiversX ecosystem ("x" prefix).

## User Preferences
Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend
The frontend is built with React 18 and TypeScript, using Vite for fast development and optimized builds. It incorporates Wouter for routing and TanStack Query v5 for data management. The UI is designed with Shadcn/ui (Radix UI primitives) and Tailwind CSS, following a "New York" aesthetic with an emerald green primary color and support for dark mode. Typography uses Space Grotesk and Inter. Form handling is managed with React Hook Form and Zod validation.

### Backend
The backend utilizes Express.js with TypeScript and Node.js. It integrates MultiversX SDK-dApp for secure, cryptographic authentication using Native Auth, supporting various wallets like Extension, Web Wallet, and WalletConnect. The authentication flow involves client-side signature generation and backend verification to establish secure user sessions, stored in PostgreSQL.

### API Architecture
RESTful APIs are provided under `/api/*`, with middleware for logging and error handling. Protected routes enforce wallet authentication. Key API endpoints include wallet synchronization, user data retrieval, and session logout. File processing involves client-side SHA-256 hashing for privacy and performance, sending only metadata to the server.

### Blockchain Integration
xproof integrates with the MultiversX blockchain for immutable proof storage. It supports both XPortal (user-signed transactions with their own gas fees) and an optional server-side signing mode. The system handles transaction signing, broadcasting, and generation of explorer URLs. It supports Mainnet, Devnet, and Testnet.

### Data Storage
PostgreSQL, hosted on Neon, is used for data persistence. Drizzle ORM provides type-safe database operations with a schema-first approach. Key tables include `users` (wallet-based profiles with Stripe integration), `certifications` (file certification records), and `sessions` (Express session storage). Drizzle Kit manages database migrations.

### Agent Commerce Protocol (ACP)
xproof implements the ACP to allow AI agents to programmatically interact with its certification services. It provides endpoints for product discovery, OpenAPI specification, checkout, transaction confirmation, and status checks. The pricing model is 0.03€ per certification, paid in EGLD. API key management is included for secure agent access and rate limiting.

### LLM-Ready Routes & AI Agent Discovery
The platform offers comprehensive machine-readable documentation for AI agent discovery:

**Discovery Endpoints:**
- `/.well-known/xproof.md` - Canonical specification v1.0 (also at `/.well-known/proofmint.md` for backwards compatibility)
- `/.well-known/ai-plugin.json` - OpenAI ChatGPT plugin manifest
- `/.well-known/mcp.json` - Model Context Protocol manifest with tool schemas
- `/.well-known/agent.json` - Agent Protocol manifest
- `/llms.txt` - LLM-friendly summary (llms.txt standard)
- `/llms-full.txt` - Extended LLM documentation with full API details
- `/api/acp/health` - Health check (public)
- `/robots.txt` - SEO with AI agent discovery hints
- `/sitemap.xml` - SEO sitemap

**Agent Tool Integrations:**
- `/agent-tools/langchain.py` - LangChain tool definitions (Python)
- `/agent-tools/crewai.py` - CrewAI tool definitions (Python)
- `/agent-tools/openapi-actions.json` - GPT Actions / Custom GPTs OpenAPI spec

**Proof Access:**
- `/proof/{id}.json` - Structured JSON proof
- `/proof/{id}.md` - Markdown proof for LLMs
- `/genesis.proof.json` - Genesis certification

**Documentation:**
- `/learn/proof-of-existence.md` - Concept explanation
- `/learn/verification.md` - Verification guide
- `/learn/api.md` - API documentation

**Authentication:**
- Public endpoints: `/api/acp/products`, `/api/acp/openapi.json`, `/api/acp/health`, `/llms.txt`, `/llms-full.txt`
- Authenticated endpoints: `/api/acp/checkout`, `/api/acp/confirm` (require `pm_` API key)

**Domain:** xproof.app (all references updated from xproof.io)

## External Dependencies

### Payment Processing
- **Stripe**: For traditional card payments and subscription management, including client-side integration (`@stripe/stripe-js`, `@stripe/react-stripe-js`) and server-side webhook handling.
- **xMoney**: For MultiversX blockchain payments, integrating via REST API calls and webhook handling with HMAC SHA256 signature verification.

### Blockchain Services
- **MultiversX blockchain**: The core blockchain for proof-of-existence.
- **MultiversX Explorer**: For transaction verification links.

### Development Tools
- Replit-specific plugins
- Cartographer (for Replit IDE)

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
- `STRIPE_SECRET_KEY`, `VITE_STRIPE_PUBLIC_KEY`
- `XMONEY_API_KEY`, `XMONEY_SITE_ID`, `XMONEY_WEBHOOK_SECRET`
- `MULTIVERSX_PRIVATE_KEY`, `MULTIVERSX_SENDER_ADDRESS`, `MULTIVERSX_CHAIN_ID`, `MULTIVERSX_GATEWAY_URL` (optional, for server-side signing)
- `REPL_ID`