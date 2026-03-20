/**
 * Vercel AI SDK middleware for automatic xProof certification.
 *
 * Provides two integration modes:
 *
 * 1. **Automatic middleware** — wraps a language model so every
 *    `generateText` / `streamText` call is certified automatically.
 *
 * 2. **Manual helpers** — `certifyGeneration` / `certifyStream` for
 *    post-hoc certification of individual calls.
 *
 * @example Automatic middleware
 * ```typescript
 * import { xproofMiddleware } from "xproof/vercel";
 * import { generateText, wrapLanguageModel } from "ai";
 * import { openai } from "@ai-sdk/openai";
 *
 * const mw = xproofMiddleware({ apiKey: "pm_...", agentName: "my-app" });
 *
 * const model = wrapLanguageModel({
 *   model: openai("gpt-4"),
 *   middleware: mw.middleware,
 * });
 *
 * const { text } = await generateText({ model, prompt: "Hello" });
 * // proof is created automatically
 * console.log(mw.proofs); // [{ proofId, fileHash, transactionHash }]
 * ```
 *
 * @example Manual certification
 * ```typescript
 * import { xproofMiddleware } from "xproof/vercel";
 * import { generateText } from "ai";
 *
 * const mw = xproofMiddleware({ apiKey: "pm_..." });
 *
 * const { text } = await generateText({
 *   model: openai("gpt-4"),
 *   prompt: "Hello",
 * });
 *
 * const proof = await mw.certifyGeneration({
 *   model: "gpt-4",
 *   prompt: "Hello",
 *   result: text,
 *   functionId: "chat",
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
  why?: string;
  metadata?: Record<string, unknown>;
  shouldCertify?: (params: { type: string; model: string }) => boolean;
  batchMode?: boolean;
  batchFlushSize?: number;
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

interface PendingCertification {
  interactionHash: string;
  fileName: string;
  model: string;
  promptHash: string;
  resultHash: string;
  timestamp: string;
  metadata?: Record<string, unknown>;
}

export function xproofMiddleware(options: XProofMiddlewareOptions = {}) {
  const client =
    options.client ?? new XProofClient({ apiKey: options.apiKey ?? "" });
  const agentName = options.agentName ?? "vercel-ai-agent";
  const defaultWhy = options.why ?? "ai-generation";
  const defaultMetadata = options.metadata ?? {};
  const shouldCertify = options.shouldCertify ?? (() => true);
  const batchMode = options.batchMode ?? false;
  const batchFlushSize = options.batchFlushSize ?? 10;

  const proofs: MiddlewareResult[] = [];
  const pendingBatch: PendingCertification[] = [];

  function buildCertPayload(
    model: string,
    promptHash: string,
    resultHash: string,
    functionId?: string,
    extraMetadata?: Record<string, unknown>
  ): { interactionHash: string; fileName: string; fourW: FourWOptions } {
    const interactionHash = hashData({
      model,
      prompt: promptHash,
      result: resultHash,
    });
    const timestamp = new Date().toISOString();
    const fileName = `ai-${functionId ?? "generate"}-${Date.now()}.json`;

    return {
      interactionHash,
      fileName,
      fourW: {
        who: agentName,
        what: interactionHash,
        when: timestamp,
        why: functionId ?? defaultWhy,
        metadata: {
          framework: "vercel-ai-sdk",
          model,
          prompt_hash: promptHash,
          result_hash: resultHash,
          ...defaultMetadata,
          ...(extraMetadata ?? {}),
        },
      },
    };
  }

  async function certifyOne(
    interactionHash: string,
    fileName: string,
    fourW: FourWOptions
  ): Promise<MiddlewareResult> {
    const cert = await client.certifyHash(
      interactionHash,
      fileName,
      agentName,
      fourW
    );

    const result: MiddlewareResult = {
      proofId: cert.id,
      fileHash: cert.fileHash,
      transactionHash: cert.transactionHash,
    };
    proofs.push(result);
    return result;
  }

  function extractModelId(model: unknown): string {
    if (!model) return "unknown";
    if (typeof model === "string") return model;
    if (typeof model === "object" && model !== null) {
      const m = model as Record<string, unknown>;
      if (typeof m.modelId === "string") return m.modelId;
      if (typeof m.id === "string") return m.id;
    }
    return "unknown";
  }

  function extractPromptText(params: Record<string, unknown>): string {
    if (typeof params.prompt === "string") return params.prompt;
    if (Array.isArray(params.prompt)) return JSON.stringify(params.prompt);
    if (params.messages) return JSON.stringify(params.messages);
    return JSON.stringify(params);
  }

  const middlewareObj = {
    wrapGenerate: async (opts: {
      doGenerate: () => Promise<Record<string, unknown>>;
      params: Record<string, unknown>;
      model: unknown;
    }) => {
      const result = await opts.doGenerate();

      const modelId = extractModelId(opts.model);
      if (!shouldCertify({ type: "generate", model: modelId })) {
        return result;
      }

      const promptText = extractPromptText(opts.params);
      const promptHash = hashData(promptText);

      const responseText =
        typeof result.text === "string"
          ? result.text
          : JSON.stringify(result.text ?? result);
      const resultHash = hashData(responseText);

      const { interactionHash, fileName, fourW } = buildCertPayload(
        modelId,
        promptHash,
        resultHash
      );

      if (batchMode) {
        pendingBatch.push({
          interactionHash,
          fileName,
          model: modelId,
          promptHash,
          resultHash,
          timestamp: fourW.when!,
          metadata: fourW.metadata,
        });
        if (pendingBatch.length >= batchFlushSize) {
          await flushBatch();
        }
      } else {
        await certifyOne(interactionHash, fileName, fourW);
      }

      return result;
    },

    wrapStream: async (opts: {
      doStream: () => Promise<{
        stream: ReadableStream;
        [key: string]: unknown;
      }>;
      params: Record<string, unknown>;
      model: unknown;
    }) => {
      const result = await opts.doStream();

      const modelId = extractModelId(opts.model);
      if (!shouldCertify({ type: "stream", model: modelId })) {
        return result;
      }

      const promptText = extractPromptText(opts.params);
      const promptHash = hashData(promptText);

      const originalStream = result.stream;
      const chunks: string[] = [];
      let finishText: string | undefined;

      const transformStream = new TransformStream({
        transform(chunk, controller) {
          if (typeof chunk === "string") {
            chunks.push(chunk);
          } else if (chunk && typeof chunk === "object") {
            const c = chunk as Record<string, unknown>;
            if (c.type === "text-delta" && typeof c.textDelta === "string") {
              chunks.push(c.textDelta);
            } else if (c.type === "finish" && typeof c.text === "string") {
              finishText = c.text as string;
            } else if (typeof c.content === "string") {
              chunks.push(c.content);
            }
          }
          controller.enqueue(chunk);
        },
        async flush() {
          const fullText = finishText ?? chunks.join("");
          const resultHash = hashData(fullText);
          const { interactionHash, fileName, fourW } = buildCertPayload(
            modelId,
            promptHash,
            resultHash,
            "stream"
          );

          if (batchMode) {
            pendingBatch.push({
              interactionHash,
              fileName,
              model: modelId,
              promptHash,
              resultHash,
              timestamp: fourW.when!,
              metadata: fourW.metadata,
            });
            if (pendingBatch.length >= batchFlushSize) {
              await flushBatch();
            }
          } else {
            await certifyOne(interactionHash, fileName, fourW).catch(() => {});
          }
        },
      });

      return {
        ...result,
        stream: originalStream.pipeThrough(transformStream),
      };
    },
  };

  async function flushBatch(): Promise<MiddlewareResult[]> {
    if (pendingBatch.length === 0) return [];

    const items = pendingBatch.splice(0, pendingBatch.length);
    const results: MiddlewareResult[] = [];

    const batchFiles = items.map((item) => ({
      fileHash: item.interactionHash,
      fileName: item.fileName,
      author: agentName,
      metadata: {
        framework: "vercel-ai-sdk",
        model: item.model,
        prompt_hash: item.promptHash,
        result_hash: item.resultHash,
        who: agentName,
        what: item.interactionHash,
        when: item.timestamp,
        why: defaultWhy,
        ...defaultMetadata,
        ...(item.metadata ?? {}),
      },
    }));

    const batchResult = await client.batchCertify(batchFiles);
    for (const cert of batchResult.results) {
      const r: MiddlewareResult = {
        proofId: cert.id,
        fileHash: cert.fileHash,
        transactionHash: cert.transactionHash,
      };
      results.push(r);
      proofs.push(r);
    }

    return results;
  }

  return {
    middleware: middlewareObj,

    async certifyGeneration(params: {
      model: string;
      prompt: string | Array<unknown>;
      result: string;
      functionId?: string;
      metadata?: Record<string, unknown>;
    }): Promise<MiddlewareResult> {
      const promptHash = hashData(params.prompt);
      const resultHash = hashData(params.result);
      const { interactionHash, fileName, fourW } = buildCertPayload(
        params.model,
        promptHash,
        resultHash,
        params.functionId,
        params.metadata
      );
      return certifyOne(interactionHash, fileName, fourW);
    },

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

    flushBatch,

    get proofs(): MiddlewareResult[] {
      return proofs;
    },

    get pendingCount(): number {
      return pendingBatch.length;
    },

    client,
    agentName,
  };
}

export type XProofVercelMiddleware = ReturnType<typeof xproofMiddleware>;
