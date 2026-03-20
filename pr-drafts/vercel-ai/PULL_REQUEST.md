# PR: Add xProof middleware cookbook example

**Target repo:** `vercel/ai`
**Target branch:** `main`
**File to add:** `examples/next-xproof-certification/` (cookbook entry)
**Or:** `content/docs/cookbook/xproof-certification.mdx`

---

## PR Title
`cookbook: add xProof blockchain certification middleware for AI SDK`

## PR Body

### Description

This PR adds a cookbook example showing how to use [xProof](https://xproof.app) middleware with the Vercel AI SDK to automatically certify every AI generation on the MultiversX blockchain.

The middleware wraps `streamText` / `generateText` transparently — zero changes to existing application code.

### What it demonstrates

- Drop-in `xproofMiddleware()` wrapping `streamText` and `generateText`
- Automatic SHA-256 hashing of prompts + outputs (no PII sent)
- Batch mode for high-throughput applications
- `shouldCertify` filter to certify only production-critical generations

### Install

```bash
npm install @xproof/xproof
```

### Checklist
- [x] Works with App Router route handlers
- [x] Works with `streamText` and `generateText`
- [x] TypeScript types included
- [x] Free tier available (10 certs/day)
