# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in xproof, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please contact the maintainers directly via email or GitHub private vulnerability reporting.

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: within 48 hours
- **Initial assessment**: within 5 business days
- **Fix or mitigation**: as soon as possible depending on severity

## Security Architecture

### File Privacy

xproof **never stores or transmits user files**. SHA-256 hashing is performed entirely in the browser using the Web Crypto API. Only the hash (a 64-character hex string) is sent to the server and recorded on-chain.

### Authentication

- Wallet authentication uses MultiversX **Native Auth**, which requires cryptographic proof (signature) from the user's wallet.
- Sessions are stored server-side in PostgreSQL.
- API keys for agent access use `pm_` prefixed bearer tokens, hashed before storage.

### Blockchain Security

- Transactions are signed client-side by the user's wallet (xPortal, Web Wallet, or WalletConnect).
- Optional server-side signing uses a private key stored in environment variables &mdash; never committed to the repository.
- All transaction hashes are independently verifiable on the MultiversX Explorer.

### Payment Security

- Stripe handles all card payment processing. xproof never stores card details.
- xMoney webhooks use HMAC SHA-256 signature verification.
- Stripe webhooks are verified using Stripe's signature verification.

### Data Protection

- Database credentials and API keys are stored as encrypted secrets, never in source code.
- HTTPS is enforced in production.
- Session cookies use `httpOnly`, `sameSite`, and `secure` flags in production.

## Supported Versions

| Version | Supported |
|---|---|
| Latest (main branch) | Yes |
| Previous releases | Best effort |

## Dependencies

We monitor and update dependencies regularly to address known vulnerabilities. Security-critical updates (such as `qs`, `jspdf`, and framework dependencies) are prioritized.
