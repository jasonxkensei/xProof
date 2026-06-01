# Vercel AI SDK + xProof

Certify every AI generation in your Next.js / Vercel application.

## What gets certified

Each `generateText` or `streamText` call produces one certification with:
- **WHO** — your chatbot/agent name
- **WHAT** — SHA-256 hash of the generated text
- **WHEN** — UTC timestamp
- **WHY** — your configured reason (e.g. `"customer-support"`)

## Install

```bash
npm install xproof ai @ai-sdk/openai
```

Set environment variables:

```
XPROOF_API_KEY=pm_...
OPENAI_API_KEY=sk-...
```

Get an xProof API key at **[xproof.app](https://xproof.app)**.

## Usage — Next.js API route (automatic middleware)

Copy `certify-route.ts` to your app at `app/api/chat/route.ts`:

```typescript
import { openai } from "@ai-sdk/openai";
import { generateText, wrapLanguageModel } from "ai";
import { XProofClient } from "xproof";
import { xproofMiddleware } from "xproof/vercel";

const xproof = xproofMiddleware({
  apiKey: process.env.XPROOF_API_KEY!,
  agentName: "my-chatbot",
  why: "customer-support",
});

const model = wrapLanguageModel({
  model: openai("gpt-4o"),
  middleware: xproof.middleware,
});

export async function POST(req: Request) {
  const { prompt } = await req.json();
  const { text } = await generateText({ model, prompt });

  const proof = xproof.proofs[xproof.proofs.length - 1];
  return Response.json({
    text,
    proof: { id: proof.proofId, verify: `https://xproof.app/verify/${proof.proofId}` },
  });
}
```

## Usage — manual certification (any runtime)

```typescript
import { XProofClient } from "xproof";
import { xproofMiddleware } from "xproof/vercel";

const client = new XProofClient({ apiKey: process.env.XPROOF_API_KEY! });
const mw = xproofMiddleware({ client, agentName: "my-agent", why: "qa" });

const proof = await mw.certifyGeneration({
  model: "gpt-4o",
  prompt: "What is AI?",
  result: "AI is...",
});
console.log(`Proof: https://xproof.app/verify/${proof.proofId}`);
```

## Links

- [xproof.app](https://xproof.app)
- Docs (LLM-readable): [xproof.app/llms.txt](https://xproof.app/llms.txt)
- [npm: xproof](https://www.npmjs.com/package/xproof)
- [Vercel AI SDK](https://sdk.vercel.ai)
