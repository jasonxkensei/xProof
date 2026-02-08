# Changelog

All notable changes to xproof will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] - 2026-02-08

### Added
- Core file certification flow: upload, SHA-256 hashing (client-side), blockchain anchoring on MultiversX.
- PDF certificate generation with QR code verification (jsPDF 4.x).
- Public proof pages (`/proof/:id`) for independent verification.
- Machine-readable proofs in JSON and Markdown formats.
- MultiversX Native Auth for secure wallet authentication (xPortal, Web Wallet, WalletConnect).
- User dashboard with certification history.
- Subscription tiers (Free, Pro, Business) with Stripe payment integration.
- xMoney integration for EGLD-based payments.
- Agent Commerce Protocol (ACP) for programmatic AI agent access.
- API key management (`pm_` prefixed bearer tokens).
- AI agent discovery endpoints:
  - `/.well-known/xproof.md` (specification)
  - `/.well-known/ai-plugin.json` (OpenAI plugin manifest)
  - `/.well-known/mcp.json` (Model Context Protocol manifest)
  - `/.well-known/agent.json` (Agent Protocol manifest)
  - `/llms.txt` and `/llms-full.txt` (LLM-friendly documentation)
- Agent tool definitions for LangChain, CrewAI, and GPT Actions.
- Learning documentation (`/learn/proof-of-existence.md`, `/learn/verification.md`, `/learn/api.md`).
- Genesis certification proof (`/genesis.proof.json`).
- SEO optimization with `robots.txt` and `sitemap.xml`.
- Dark mode support.
- Rebranding from "ProofMint" to "xproof".

### Security
- Updated `qs` to 6.14.1 (all dependency tree instances via npm overrides).
- Updated `jspdf` from 3.x to 4.1.0.
