# ProofMint - Blockchain Certification Platform

## Overview

ProofMint is a Web3 certification platform that enables users to create immutable, verifiable proofs of file ownership by recording digital fingerprints (SHA-256 hashes) on the MultiversX blockchain. The application provides a professional, trust-focused interface for non-technical users to certify documents, designs, code, or any digital asset without requiring blockchain expertise.

The platform is 100% free with unlimited certifications, offering features like public proof pages, certificate generation, and blockchain verification. Users only pay the minimal blockchain gas fees (~0.002€) when signing transactions.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture

**Framework & Build System**
- **React 18** with TypeScript for type-safe component development
- **Vite** as the build tool and development server, providing fast HMR and optimized production builds
- **Wouter** for lightweight client-side routing (alternative to React Router)
- **TanStack Query v5** for server state management, data fetching, and caching

**UI Component System**
- **Shadcn/ui** component library with Radix UI primitives for accessible, customizable components
- **Tailwind CSS** for utility-first styling with custom design tokens
- **Class Variance Authority (CVA)** for component variant management
- Design system follows "New York" style with emerald green primary color (MultiversX-inspired)
- Dark mode support with CSS custom properties for theme switching

**Key Design Decisions**
- Typography: Space Grotesk for headings, Inter for body text (professional Web3 aesthetic)
- Color system based on HSL with semantic tokens (primary, secondary, destructive, muted, accent)
- Component aliases configured via `@/` path mapping for clean imports
- Form handling with React Hook Form and Zod validation via `@hookform/resolvers`

### Backend Architecture

**Server Framework**
- **Express.js** with TypeScript running on Node.js
- ESM module system (type: "module" in package.json)
- Custom Vite middleware integration for development with HMR support
- Production build uses esbuild for server bundling

**Authentication & Session Management**
- **MultiversX SDK-dApp Integration** with Native Auth for cryptographically secure authentication
- Client-side wallet authentication using `@multiversx/sdk-dapp` v5+ with signature-based verification
- **Native Auth Implementation**:
  - Enabled in initApp() config (24h token expiry, 5min warning before expiration)
  - Generates JWT-like token with cryptographic signature, block hash, and origin validation
  - Token stored in sessionStorage and sent to backend via Authorization header
  - Backend verification using `@multiversx/sdk-native-auth-server`
- **Polyfills Required**: Custom polyfills.ts defines `global` and `process` for browser compatibility (imported before SDK initialization)
- **Multiple Wallet Support**:
  - **Extension Wallet**: MultiversX DeFi Wallet browser extension via ProviderFactory.extension
  - **Web Wallet**: Cross-window authentication via ProviderFactory.crossWindow  
  - **WalletConnect**: xPortal mobile app via ProviderFactory.walletConnect
- **Secure Authentication Flow**:
  1. User clicks "Connect Wallet" → WalletLoginModal opens
  2. User selects wallet type → SDK-dApp handles cryptographic signature challenge
  3. SDK-dApp generates Native Auth token (signed with user's private key)
  4. Frontend receives wallet address + Native Auth token → POST to `/api/auth/wallet/sync` with Bearer token
  5. Backend verifies token cryptographically (signature + expiration + origin + block hash)
  6. Backend creates/fetches user record and establishes PostgreSQL session only after successful verification
- **Session Management**:
  - Hybrid approach: SDK-dApp manages client-side wallet state, backend maintains session for data persistence
  - Session storage in PostgreSQL using `connect-pg-simple` with wallet addresses as identifiers
  - HTTP-only cookies for secure session management
  - Session expires when browser closes (session cookie without maxAge)
- **Security Guarantees**:
  - Cryptographic proof of wallet ownership (private key signature verification)
  - Prevents wallet impersonation attacks (cannot forge signatures)
  - Origin validation (prevents cross-site token theft)
  - Block hash validation (prevents replay attacks)
  - Token expiration enforcement (24h validity)
  - Legacy insecure endpoint `/api/auth/wallet/login` disabled (returns 410 Gone)

**API Architecture**
- RESTful endpoints under `/api/*` prefix
- Express middleware for request logging with duration tracking
- JSON request/response handling with centralized error handling
- Protected routes using `isWalletAuthenticated` middleware
- **Wallet Auth Endpoints:**
  - `POST /api/auth/wallet/sync`: Sync SDK-dApp wallet state with backend, create user session (used by useWalletAuth hook)
  - `GET /api/auth/me`: Get current authenticated user (requires valid session)
  - `POST /api/auth/logout`: Destroy wallet session (backend) + SDK-dApp logout (frontend)

**File Processing**
- Client-side SHA-256 hashing using Web Crypto API (no file uploads to server)
- Hash computation happens in browser for privacy and performance
- Server receives only hash metadata for blockchain recording

**Blockchain Integration**
- **MultiversX blockchain** for immutable proof storage with dual modes:
  - **XPortal Mode (Recommended)**: Users connect their XPortal wallet, sign transactions client-side, and pay their own gas fees
  - **Server Mode (Optional)**: Automated signing using server-side private key for seamless UX
- Real MultiversX SDK integration (`@multiversx/sdk-core`, `@multiversx/sdk-wallet`, `@noble/ed25519`)
- Transaction signing and broadcasting to MultiversX Gateway
- Support for Mainnet, Devnet, and Testnet networks
- Transaction hash and explorer URL generation for verification
- Public proof pages accessible via `/proof/:id` for verification
- Broadcast endpoint (`/api/blockchain/broadcast`) for XPortal-signed transactions

### Data Storage Solutions

**Database**
- **PostgreSQL** via Neon serverless platform (`@neondatabase/serverless`)
- **Drizzle ORM** for type-safe database operations with schema-first approach
- WebSocket connection for serverless compatibility (using `ws` package)
- Connection pooling with Neon Pool for efficient resource usage

**Schema Design**
- `users`: Wallet-based profiles with `walletAddress` as primary identifier, Stripe integration fields (customerId, subscriptionId, tier, status), and optional email
- `certifications`: File certification records (hash, metadata, blockchain references, visibility settings) linked to users via `userId`
- `sessions`: Express session storage for wallet authentication state (stores `walletAddress`)
- Subscription tier tracking with monthly usage limits and reset dates
- Cascade deletion for user-owned certifications
- All queries use `walletAddress` for user lookups (wallet-first architecture)

**Migration Strategy**
- Drizzle Kit for schema migrations in `./migrations` directory
- Schema defined in `shared/schema.ts` for type sharing between client/server
- Database provisioning check in drizzle.config.ts

### External Dependencies

**Payment Processing**
- **Dual Payment System**: Stripe and xMoney integration for flexible payment options
- **Stripe** for traditional card payments and subscription management
  - Stripe API version: 2025-09.30.clover
  - Client-side integration with `@stripe/stripe-js` and `@stripe/react-stripe-js`
  - Server-side subscription creation and webhook handling at `/api/webhooks/stripe`
  - Payment intents for one-time and recurring payments
- **xMoney** for MultiversX blockchain payments
  - Native MultiversX payment gateway integration
  - REST API calls to xMoney service for order creation and status tracking
  - Webhook handler at `/api/webhooks/xmoney` with HMAC SHA256 signature verification
  - Constant-time signature verification for timing-attack protection
  - Support for cryptocurrency payments via MultiversX network

**Blockchain Services**
- **MultiversX** blockchain for proof-of-existence certification
- Explorer integration for transaction verification links
- Planned REST API integration (currently simulated)

**Development Tools**
- Replit-specific plugins for development environment (`@replit/vite-plugin-*`)
- Runtime error overlay for development debugging
- Cartographer for code navigation in Replit IDE

**Third-Party UI Libraries**
- Radix UI primitives (20+ component packages for accessible UI)
- Lucide React for icon system
- date-fns for date formatting and manipulation
- Vaul for drawer components (mobile UI patterns)

**Font Loading**
- Google Fonts CDN for Space Grotesk and Inter font families
- Preconnect hints for performance optimization

**Environment Configuration**
- `DATABASE_URL`: PostgreSQL connection string (required)
- `SESSION_SECRET`: Express session encryption key (required)
- `STRIPE_SECRET_KEY`: Stripe API key (required)
- `VITE_STRIPE_PUBLIC_KEY`: Stripe publishable key for client (required)
- `XMONEY_API_KEY`: xMoney API key for payment processing (optional)
- `XMONEY_SITE_ID`: xMoney site identifier (optional)
- `XMONEY_WEBHOOK_SECRET`: xMoney webhook signature verification secret (optional)
- **MultiversX Configuration (Optional - for server-side signing mode):**
  - `MULTIVERSX_PRIVATE_KEY`: Private key for signing transactions server-side (hex format)
  - `MULTIVERSX_SENDER_ADDRESS`: Wallet address that pays gas fees (erd1... format)
  - `MULTIVERSX_CHAIN_ID`: Network ID ("1" = Mainnet, "D" = Devnet, "T" = Testnet)
  - `MULTIVERSX_GATEWAY_URL`: Gateway URL (e.g., "https://devnet-gateway.multiversx.com")
  - **Note**: If not configured, app uses XPortal wallet mode (users sign with their own wallets)
- `REPL_ID`: Replit environment identifier

## Milestones & Current Status

### First Certification Success (Dec 12, 2025)
- **MILESTONE ACHIEVED**: First document certified on MultiversX Mainnet!
- **Transaction**: `f376c0809d5c8fd91f854d39cf6f9f83ac3d80231477538a1b423db0537aad7e`
- **Document**: PROOFMINT - Genesis.pdf
- **Author**: Jason Petitfourg  
- **Cost**: 0.0002935 EGLD (~$0.002)
- **Method**: DeFi Wallet Extension (browser)

### Working Features
- ✅ Extension Wallet login + transaction signing (FULLY WORKING with polling mechanism)
- ✅ Web Wallet login (FULLY WORKING - recommended for Guardian 2FA users)
- ✅ File hashing (SHA-256 client-side)
- ✅ Blockchain certification on Mainnet
- ✅ Transaction data encoding (certify:hash|filename|author)
- ✅ User session management with PostgreSQL persistence
- ✅ Automatic redirect to landing page for unauthenticated users
- ✅ Branded loading screen during wallet connection

### Known Issues
- ⚠️ **xPortal Mobile (Deep Link)**: Connection works in xPortal app, but session may not sync back to browser after deep link return. Root cause: JavaScript execution interrupted when browser navigates to xPortal app. The SDK's ProviderFactory handles WalletConnect sessions, but mobile browsers may kill/reload the tab.
- ⚠️ **Extension Wallet + Guardian 2FA**: Known SDK bug with cross-window communication. Workaround: Use Web Wallet for 2FA accounts.

### Recommended Wallet Methods
1. **Extension Wallet** (Desktop) - Best experience, fully working with polling
2. **Web Wallet** (Any device) - Works with Guardian 2FA, reliable cross-window flow
3. **xPortal Mobile** - Use QR code on desktop browser for best results; deep link on mobile may have issues

## ACP (Agent Commerce Protocol) - Proof-as-a-Service

ProofMint implements the Agent Commerce Protocol, enabling AI agents to automatically discover and use certification services without human UI interaction.

### ACP Endpoints

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /api/acp/products` | Public | Discover available products |
| `GET /api/acp/openapi.json` | Public | OpenAPI 3.0 specification |
| `POST /api/acp/checkout` | API Key | Create checkout session |
| `POST /api/acp/confirm` | API Key | Confirm transaction |
| `GET /api/acp/checkout/:id` | API Key | Check checkout status |

### Pricing Model
- **Certification price**: 0.03€ per certification
- **Payment**: EGLD (converted at checkout via CoinGecko real-time rate)
- **Recipient**: ProofMint wallet (`PROOFMINT_WALLET_ADDRESS`)

### API Key Management
- Users generate API keys via `POST /api/keys` (requires wallet auth)
- Keys are prefixed with `pm_` (e.g., `pm_abc123...`)
- Rate limit: 1000 requests/minute per key
- Headers: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`

### ACP Flow
1. Agent calls `GET /api/acp/products` to discover services
2. Agent calls `POST /api/acp/checkout` with file hash → receives tx_payload
3. Agent/User signs and broadcasts transaction on MultiversX
4. Agent calls `POST /api/acp/confirm` with tx_hash → receives certification ID

### Database Tables
- `api_keys`: API key storage with hashed keys, usage tracking
- `acp_checkouts`: Checkout session tracking with expiry (1 hour)