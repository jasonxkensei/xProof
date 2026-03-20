# Vercel AI SDK + xProof Example

Demonstrates automatic certification of AI model calls using the
xProof middleware for Vercel AI SDK.

## Setup

```bash
cd npm-sdk/examples/vercel-ai-nextjs
npm install
```

## Run

```bash
npm run dev
```

The script will:
1. Register a trial xProof agent
2. Simulate AI generation calls with manual certification
3. Show the resulting proof trail with 4W metadata

For a full Next.js integration, see `nextjs-route.ts` which shows
how to use `wrapLanguageModel` with the xProof middleware for
automatic certification of every `generateText`/`streamText` call.

Each proof is anchored on MultiversX and verifiable at
`https://xproof.app/verify/<proofId>`.
