# ProofMint - Blockchain Certification Platform

## Overview

ProofMint is a Web3 certification platform that enables users to create immutable, verifiable proofs of file ownership by recording digital fingerprints (SHA-256 hashes) on the MultiversX blockchain. The application provides a professional, trust-focused interface for non-technical users to certify documents, designs, code, or any digital asset without requiring blockchain expertise.

The platform operates on a freemium subscription model with tiered access (Free, Pro, Business), integrating Stripe for payment processing and offering features like public proof pages, certificate generation, and blockchain verification.

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
- **Replit Auth** via OpenID Connect (OIDC) for user authentication
- Passport.js strategy for OIDC integration
- Session storage in PostgreSQL using `connect-pg-simple`
- HTTP-only cookies for secure session management
- Session TTL: 7 days with automatic refresh

**API Architecture**
- RESTful endpoints under `/api/*` prefix
- Express middleware for request logging with duration tracking
- JSON request/response handling with centralized error handling
- Protected routes using `isAuthenticated` middleware

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
- `users`: Authentication profiles with Stripe integration fields (customerId, subscriptionId, tier, status)
- `certifications`: File certification records (hash, metadata, blockchain references, visibility settings)
- `sessions`: Express session storage for authentication state
- Subscription tier tracking with monthly usage limits and reset dates
- Cascade deletion for user-owned certifications

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
- `ISSUER_URL`: OIDC provider URL for Replit Auth
- `REPL_ID`: Replit environment identifier
- `REPLIT_DOMAINS`: Domain configuration for authentication callbacks