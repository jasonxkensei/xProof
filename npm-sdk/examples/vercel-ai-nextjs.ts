/**
 * Example: Next.js API route with xProof + Vercel AI SDK middleware.
 *
 * Every AI generation is automatically certified on-chain with
 * a verifiable proof trail including 4W metadata.
 *
 * Setup:
 *   npm install xproof ai @ai-sdk/openai
 *
 * Usage in a Next.js app:
 *   1. Copy this file to `app/api/chat/route.ts`
 *   2. Set XPROOF_API_KEY and OPENAI_API_KEY environment variables
 *   3. POST /api/chat with { "prompt": "your question" }
 *
 * Each response includes a proofId that can be verified at:
 *   https://xproof.app/verify/<proofId>
 */

// import { openai } from "@ai-sdk/openai";
// import { generateText, streamText, wrapLanguageModel } from "ai";
// import { xproofMiddleware } from "xproof/vercel";
//
// const xproof = xproofMiddleware({
//   apiKey: process.env.XPROOF_API_KEY!,
//   agentName: "my-nextjs-chatbot",
//   why: "customer-support",
//   metadata: { env: process.env.NODE_ENV },
// });
//
// const model = wrapLanguageModel({
//   model: openai("gpt-4o"),
//   middleware: xproof.middleware,
// });
//
// // --- Example 1: generateText (automatic certification) ---
//
// export async function POST(req: Request) {
//   const { prompt } = await req.json();
//
//   const { text } = await generateText({ model, prompt });
//
//   const latestProof = xproof.proofs[xproof.proofs.length - 1];
//
//   return Response.json({
//     text,
//     proof: {
//       id: latestProof.proofId,
//       hash: latestProof.fileHash,
//       tx: latestProof.transactionHash,
//       verify: `https://xproof.app/verify/${latestProof.proofId}`,
//     },
//   });
// }
//
// // --- Example 2: Manual certification (without wrapping) ---
//
// async function manualExample() {
//   const xproof = xproofMiddleware({
//     apiKey: process.env.XPROOF_API_KEY!,
//     agentName: "manual-bot",
//   });
//
//   const { text } = await generateText({
//     model: openai("gpt-4o"),
//     prompt: "Summarize our Q1 report",
//   });
//
//   const proof = await xproof.certifyGeneration({
//     model: "gpt-4o",
//     prompt: "Summarize our Q1 report",
//     result: text,
//     functionId: "report-summarizer",
//     metadata: { department: "finance" },
//   });
//
//   console.log("Proof ID:", proof.proofId);
//   console.log("Verify:", `https://xproof.app/verify/${proof.proofId}`);
// }
//
// // --- Example 3: Batch mode for high-throughput ---
//
// async function batchExample() {
//   const xproof = xproofMiddleware({
//     apiKey: process.env.XPROOF_API_KEY!,
//     agentName: "batch-processor",
//     batchMode: true,
//     batchFlushSize: 10,
//   });
//
//   const model = wrapLanguageModel({
//     model: openai("gpt-4o-mini"),
//     middleware: xproof.middleware,
//   });
//
//   const prompts = [
//     "Translate to French: Hello",
//     "Translate to Spanish: World",
//     "Translate to German: Goodbye",
//   ];
//
//   for (const prompt of prompts) {
//     await generateText({ model, prompt });
//   }
//
//   // Flush remaining batch
//   const results = await xproof.flushBatch();
//   console.log(`Certified ${results.length} interactions in one batch`);
// }
//
// // --- Example 4: Selective certification (filter by model) ---
//
// async function selectiveExample() {
//   const xproof = xproofMiddleware({
//     apiKey: process.env.XPROOF_API_KEY!,
//     agentName: "selective-bot",
//     shouldCertify: ({ model }) => {
//       // Only certify GPT-4 calls, skip cheaper models
//       return model.includes("gpt-4");
//     },
//   });
// }
