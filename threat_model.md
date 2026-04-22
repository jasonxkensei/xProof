# Threat Model

## Project Overview

xproof is an on-chain notary and accountability layer for AI agents and human users. It lets clients anchor SHA-256 proofs, staged decision records, and audit logs on MultiversX, then exposes those proofs through public verification pages, REST APIs, and an MCP endpoint. The production stack is a Node.js/Express TypeScript backend, a React/Vite frontend, Neon/PostgreSQL via Drizzle, express-session for wallet-backed browser sessions, MultiversX Native Auth for wallet login, and Base/USDC + x402 for payment flows.

Production security analysis should focus on `server/`, `shared/`, and production-rendered client/server content. `python-sdk/`, `npm-sdk/`, `xproof-examples/`, tests, and task artifacts are normally dev/distribution surfaces and should be ignored unless production reachability is demonstrated. Replit handles TLS in production; sandbox/mock environments are not production.

## Assets

- **Wallet-backed user identities and sessions** — browser sessions represent a MultiversX wallet and gate API-key management, profile changes, trust operations, and admin routes.
- **API keys** — `pm_` keys authorize proof issuance, agent status, MCP usage, and credit consumption. Compromise or misbinding lets attackers issue proofs or spend another tenant's quota.
- **Admin authority** — admin routes expose metrics, maintenance, migration, and governance operations. These controls must fail closed.
- **Payment entitlements** — prepaid credits, ACP/EGLD payments, and x402/USDC payments determine whether proof issuance is authorized. Server-side verification must prevent free proof creation.
- **Proof ownership and trust state** — certifications, audit logs, attestations, trust scores, and violation records form the integrity core of the product. Misattribution or unauthorized mutation undermines the service's main value proposition.
- **Webhook secrets and callback URLs** — outbound proof/attestation callbacks are cross-system trust boundaries and must preserve authenticity without exposing broader application secrets.
- **Application secrets and infrastructure access** — `DATABASE_URL`, `SESSION_SECRET`, blockchain/payment credentials, and any signer keys enable full compromise if exposed or reused unsafely.

## Trust Boundaries

- **Browser / API boundary** — all browser input is untrusted. Wallet sessions must only be created from cryptographically verified Native Auth material.
- **Agent / API boundary** — REST and MCP clients can be autonomous and high-volume. API keys, payment evidence, quota usage, and ownership attribution must be enforced server-side on every write path.
- **API / Database boundary** — the Express server has authority to create proofs, credits, users, and trust artifacts. Input-driven writes must preserve tenant boundaries and payment rules.
- **API / External service boundary** — the server trusts MultiversX APIs, Base/x402 verification, and webhook destinations. Payment status and webhook authenticity must not degrade when upstream calls fail.
- **Public / Authenticated / Admin boundary** — proof lookup and discovery are public; wallet-backed account management is authenticated; maintenance and governance routes are admin-only. These boundaries must remain explicit and fail closed.
- **Per-tenant / Shared system-user boundary** — some flows fall back to a synthetic system user for anonymous or commerce-driven proofs. That boundary is sensitive because shared identities can hide actor attribution and bypass per-user accounting.

## Scan Anchors

- **Production entry points**: `server/index.ts`, `server/routes.ts`, `server/routes/*`
- **Highest-risk files**: `server/routes/auth.ts`, `server/walletAuth.ts`, `server/replitAuth.ts`, `server/routes/helpers.ts`, `server/routes/proof-write.ts`, `server/routes/acp.ts`, `server/routes/credits.ts`, `server/mcp.ts`, `server/webhook.ts`, `server/routes/admin.ts`, `server/routes/attestations.ts`, `client/src/hooks/useWalletAuth.ts`, `client/src/components/wallet-login-modal.tsx`
- **Public surfaces**: `server/routes/proof-read.ts`, `server/routes/attestations.ts`, embeddable trust-widget routes, discovery/content/docs routes, prerendered pages in `server/prerender.ts`
- **Usually dev-only**: `python-sdk/`, `npm-sdk/`, `xproof-examples/`, tests, local task files

## Threat Categories

### Spoofing

xproof relies on wallet identity for browser sessions and on `pm_` keys for agent access. The system must only create wallet sessions from valid MultiversX Native Auth proofs and must never accept a claimed wallet address as sufficient evidence. Admin access must be derived from a trusted authenticated identity and must fail closed if configuration is missing. Webhook consumers must be able to distinguish genuine xproof callbacks from attacker-generated traffic.

Required guarantees:
- Wallet sessions MUST be created only after cryptographic verification of a Native Auth token or equivalent signed proof.
- Admin-only routes MUST require both authentication and a fail-closed authorization check.
- Webhook authenticity MUST rely on a secret scoped to the callback relationship, not a shared application-wide secret.

### Tampering

The main tampering risk is unauthorized proof creation or mutation of trust/business state without valid payment or quota consumption. Every path that records a certification or audit log must enforce the same entitlement checks, payment verification, and actor attribution. ACP confirmation must verify the exact transaction properties required by the checkout, not merely a generic success status. Shared fallback identities are dangerous because they can hide who actually caused state changes.

Required guarantees:
- Proof and audit creation MUST consume the correct quota or verify the required payment on every write-capable API and MCP path.
- Payment confirmation MUST verify recipient, amount, chain/context, and transaction success before creating a proof.
- Certifications MUST be attributed to the actual authenticated account when an API key is used; shared system-user fallbacks MUST be limited to intentionally anonymous paid flows.

### Repudiation

xproof's value proposition is a verifiable audit trail. If proofs, audits, or attestations can be created under the wrong identity or without a real payment event, the resulting ledger stops being trustworthy. The system must preserve a reliable mapping between the actor, the payment method, and the recorded artifact.

Required guarantees:
- Every persisted certification/audit MUST be traceable to the actual caller or payment flow that authorized it.
- Sensitive mutations such as admin actions, attestation revocations, key creation, and proof issuance MUST log the acting identity and outcome.

### Information Disclosure

Most proof data is intentionally public, but not every internal secret or owner attribute should be. Public APIs must continue to avoid exposing non-public wallet relationships, raw secrets, or unnecessary internal details. Scanner hits in SDK examples and standalone demos should not be treated as production issues unless those files are actually served or executed in production.

Required guarantees:
- Public proof and trust APIs MUST only expose data intentionally designated as public.
- Session secrets, API keys, and signing secrets MUST never appear in client-facing responses or logs.
- Example/demo code outside the production runtime SHOULD be documented as out of scope for production scans unless later wired into the deployed app.

### Denial of Service

Because xproof exposes public discovery/read APIs and expensive write paths that call blockchains and webhook destinations, rate limits and bounded external calls matter. A caller should not be able to trigger unlimited blockchain writes, unbounded retries, or slow external waits from an unauthenticated or low-cost position.

Required guarantees:
- Public auth, search, read, and payment endpoints MUST remain rate-limited.
- External verification and webhook calls MUST use bounded timeouts and bounded retries.
- Write paths MUST not allow low-privilege users to force unlimited paid work or blockchain traffic.

### Elevation of Privilege

The most serious project-specific EoP risks are broken wallet auth, fail-open admin checks, and alternate write paths that bypass the normal entitlement logic. Because wallet identity is reused for API-key issuance and some governance functions, any spoofing flaw can cascade into long-lived account takeover. Likewise, any MCP or admin route that skips the usual checks can effectively grant broader privileges than intended.

Required guarantees:
- Alternate auth or convenience endpoints MUST not grant broader access than the primary auth path.
- Admin helpers MUST default to deny when configuration or session context is missing.
- MCP, REST, and commerce flows MUST enforce the same authorization, accounting, and attribution rules for equivalent operations.
