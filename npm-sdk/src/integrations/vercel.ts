/**
 * Vercel AI SDK middleware for automatic xProof certification.
 *
 * Intercepts generateText/streamText calls and certifies each AI interaction
 * on-chain with 4W metadata (WHO/WHAT/WHEN/WHY).
 *
 * @example
 * ```typescript
 * import { xproofMiddleware } from "xproof/vercel";
 * import { generateText } from "ai";
 *
 * const middleware = xproofMiddleware({ apiKey: "pm_..." });
 *
 * const result = await generateText({
 *   model: openai("gpt-4"),
 *   prompt: "Hello",
 *   experimental_telemetry: { functionId: "chat" },
 * });
 * ```
 */

import { createHash } from "crypto";
import { XProofClient } from "../client.js";
import type { FourWOptions } from "../types.js";

export interface XProofMiddlewareOptions {
  apiKey?: string;
  client?: XProofClient;
  agentName?: string;
  certifyGenerate?: boolean;
  certifyStream?: boolean;
}

function hashData(data: unknown): string {
  const serialized =
    typeof data === "string" ? data : JSON.stringify(data, null, 0);
  return createHash("sha256").update(serialized, "utf8").digest("hex");
}

export interface MiddlewareResult {
  proofId: string;
  fileHash: string;
  transactionHash: string;
}

/**
 * Create a middleware-compatible wrapper for Vercel AI SDK calls.
 *
 * Since the Vercel AI SDK middleware API is still experimental and evolving,
 * this provides a `wrapGenerate` function that you call after generateText
 * or streamText completes, to certify the interaction.
 */
export function xproofMiddleware(options: XProofMiddlewareOptions = {}) {
  const client =
    options.client ?? new XProofClient({ apiKey: options.apiKey ?? "" });
  const agentName = options.agentName ?? "vercel-ai-agent";
  const certifyGenerate = options.certifyGenerate ?? true;
  const certifyStream = options.certifyStream ?? true;

  return {
    /**
     * Certify a generateText result.
     */
    async certifyGeneration(params: {
      model: string;
      prompt: string | Array<unknown>;
      result: string;
      functionId?: string;
      metadata?: Record<string, unknown>;
    }): Promise<MiddlewareResult> {
      const promptHash = hashData(params.prompt);
      const resultHash = hashData(params.result);
      const interactionHash = hashData({
        model: params.model,
        prompt: promptHash,
        result: resultHash,
      });

      const cert = await client.certifyHash(
        interactionHash,
        `ai-${params.functionId ?? "generate"}-${Date.now()}.json`,
        agentName,
        {
          who: agentName,
          what: interactionHash,
          when: new Date().toISOString(),
          why: params.functionId ?? "ai-generation",
          metadata: {
            framework: "vercel-ai-sdk",
            model: params.model,
            prompt_hash: promptHash,
            result_hash: resultHash,
            ...(params.metadata ?? {}),
          },
        }
      );

      return {
        proofId: cert.id,
        fileHash: cert.fileHash,
        transactionHash: cert.transactionHash,
      };
    },

    /**
     * Certify a streamText result (call after stream completes).
     */
    async certifyStream(params: {
      model: string;
      prompt: string | Array<unknown>;
      fullText: string;
      functionId?: string;
      metadata?: Record<string, unknown>;
    }): Promise<MiddlewareResult> {
      return this.certifyGeneration({
        ...params,
        result: params.fullText,
        functionId: params.functionId ?? "stream",
      });
    },

    client,
    agentName,
  };
}
