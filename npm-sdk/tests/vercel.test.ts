import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { xproofMiddleware } from "../src/integrations/vercel.js";

function mockFetch(status: number, body: unknown) {
  return vi.fn().mockResolvedValue({
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
    headers: new Headers({ "content-type": "application/json" }),
  });
}

const CERT_RESPONSE = {
  id: "proof-vercel",
  fileName: "ai-generate.json",
  fileHash: "h",
  transactionHash: "tx-vercel",
  transactionUrl: "",
  createdAt: "",
};

describe("xproofMiddleware", () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  describe("manual certifyGeneration", () => {
    it("sends correct payload", async () => {
      const fetchMock = mockFetch(201, CERT_RESPONSE);
      globalThis.fetch = fetchMock;

      const mw = xproofMiddleware({
        apiKey: "pm_test",
        agentName: "my-ai-app",
      });

      const result = await mw.certifyGeneration({
        model: "gpt-4",
        prompt: "What is 2+2?",
        result: "4",
        functionId: "math-helper",
      });

      expect(result.proofId).toBe("proof-vercel");
      expect(result.transactionHash).toBe("tx-vercel");

      const body = JSON.parse(fetchMock.mock.calls[0][1].body);
      expect(body.author_name).toBe("my-ai-app");
      expect(body.metadata.framework).toBe("vercel-ai-sdk");
      expect(body.metadata.model).toBe("gpt-4");
      expect(body.metadata.who).toBe("my-ai-app");
      expect(body.metadata.why).toBe("math-helper");
      expect(body.metadata.prompt_hash).toBeDefined();
      expect(body.metadata.result_hash).toBeDefined();
    });

    it("includes custom metadata", async () => {
      const fetchMock = mockFetch(201, CERT_RESPONSE);
      globalThis.fetch = fetchMock;

      const mw = xproofMiddleware({ apiKey: "pm_test" });
      await mw.certifyGeneration({
        model: "claude-3",
        prompt: "Hello",
        result: "Hi",
        metadata: { session_id: "sess-123", user_id: "u-1" },
      });

      const body = JSON.parse(fetchMock.mock.calls[0][1].body);
      expect(body.metadata.session_id).toBe("sess-123");
      expect(body.metadata.user_id).toBe("u-1");
    });

    it("uses default agent name", async () => {
      const fetchMock = mockFetch(201, CERT_RESPONSE);
      globalThis.fetch = fetchMock;

      const mw = xproofMiddleware({ apiKey: "pm_test" });
      await mw.certifyGeneration({
        model: "gpt-4",
        prompt: "test",
        result: "response",
      });

      expect(mw.agentName).toBe("vercel-ai-agent");
      const body = JSON.parse(fetchMock.mock.calls[0][1].body);
      expect(body.author_name).toBe("vercel-ai-agent");
    });
  });

  describe("manual certifyStream", () => {
    it("calls certifyGeneration internally", async () => {
      const fetchMock = mockFetch(201, {
        ...CERT_RESPONSE,
        id: "proof-stream",
        transactionHash: "tx-stream",
      });
      globalThis.fetch = fetchMock;

      const mw = xproofMiddleware({ apiKey: "pm_test" });
      const result = await mw.certifyStream({
        model: "gpt-4o",
        prompt: "Tell me a joke",
        fullText: "Why did the chicken...",
      });

      expect(result.proofId).toBe("proof-stream");
      const body = JSON.parse(fetchMock.mock.calls[0][1].body);
      expect(body.metadata.model).toBe("gpt-4o");
    });
  });

  describe("automatic middleware.wrapGenerate", () => {
    it("certifies after doGenerate completes", async () => {
      const fetchMock = mockFetch(201, CERT_RESPONSE);
      globalThis.fetch = fetchMock;

      const mw = xproofMiddleware({
        apiKey: "pm_test",
        agentName: "auto-app",
      });

      const fakeResult = { text: "Paris is the capital of France." };
      const doGenerate = vi.fn().mockResolvedValue(fakeResult);

      const result = await mw.middleware.wrapGenerate({
        doGenerate,
        params: { prompt: "What is the capital of France?" },
        model: { modelId: "gpt-4o" },
      });

      expect(result).toBe(fakeResult);
      expect(doGenerate).toHaveBeenCalledOnce();
      expect(fetchMock).toHaveBeenCalledOnce();

      const body = JSON.parse(fetchMock.mock.calls[0][1].body);
      expect(body.author_name).toBe("auto-app");
      expect(body.metadata.framework).toBe("vercel-ai-sdk");
      expect(body.metadata.model).toBe("gpt-4o");
      expect(body.metadata.prompt_hash).toBeDefined();
      expect(body.metadata.result_hash).toBeDefined();
      expect(body.metadata.who).toBe("auto-app");
    });

    it("extracts model ID from different model shapes", async () => {
      const fetchMock = mockFetch(201, CERT_RESPONSE);
      globalThis.fetch = fetchMock;

      const mw = xproofMiddleware({ apiKey: "pm_test" });

      await mw.middleware.wrapGenerate({
        doGenerate: vi.fn().mockResolvedValue({ text: "ok" }),
        params: { prompt: "test" },
        model: { id: "claude-3-sonnet" },
      });

      const body = JSON.parse(fetchMock.mock.calls[0][1].body);
      expect(body.metadata.model).toBe("claude-3-sonnet");
    });

    it("handles string model", async () => {
      const fetchMock = mockFetch(201, CERT_RESPONSE);
      globalThis.fetch = fetchMock;

      const mw = xproofMiddleware({ apiKey: "pm_test" });

      await mw.middleware.wrapGenerate({
        doGenerate: vi.fn().mockResolvedValue({ text: "ok" }),
        params: { prompt: "test" },
        model: "gpt-3.5-turbo",
      });

      const body = JSON.parse(fetchMock.mock.calls[0][1].body);
      expect(body.metadata.model).toBe("gpt-3.5-turbo");
    });

    it("extracts prompt from messages array", async () => {
      const fetchMock = mockFetch(201, CERT_RESPONSE);
      globalThis.fetch = fetchMock;

      const mw = xproofMiddleware({ apiKey: "pm_test" });

      const messages = [
        { role: "user", content: "Hello" },
        { role: "assistant", content: "Hi!" },
      ];

      await mw.middleware.wrapGenerate({
        doGenerate: vi.fn().mockResolvedValue({ text: "response" }),
        params: { messages },
        model: { modelId: "gpt-4" },
      });

      const body = JSON.parse(fetchMock.mock.calls[0][1].body);
      expect(body.metadata.prompt_hash).toBeDefined();
    });

    it("tracks proofs array", async () => {
      const fetchMock = mockFetch(201, CERT_RESPONSE);
      globalThis.fetch = fetchMock;

      const mw = xproofMiddleware({ apiKey: "pm_test" });
      expect(mw.proofs).toHaveLength(0);

      await mw.middleware.wrapGenerate({
        doGenerate: vi.fn().mockResolvedValue({ text: "a" }),
        params: { prompt: "x" },
        model: { modelId: "gpt-4" },
      });

      expect(mw.proofs).toHaveLength(1);
      expect(mw.proofs[0].proofId).toBe("proof-vercel");
    });
  });

  describe("shouldCertify filter", () => {
    it("skips certification when filter returns false", async () => {
      const fetchMock = mockFetch(201, CERT_RESPONSE);
      globalThis.fetch = fetchMock;

      const mw = xproofMiddleware({
        apiKey: "pm_test",
        shouldCertify: ({ model }) => model !== "gpt-3.5-turbo",
      });

      await mw.middleware.wrapGenerate({
        doGenerate: vi.fn().mockResolvedValue({ text: "ok" }),
        params: { prompt: "test" },
        model: { modelId: "gpt-3.5-turbo" },
      });

      expect(fetchMock).not.toHaveBeenCalled();
      expect(mw.proofs).toHaveLength(0);
    });

    it("certifies when filter returns true", async () => {
      const fetchMock = mockFetch(201, CERT_RESPONSE);
      globalThis.fetch = fetchMock;

      const mw = xproofMiddleware({
        apiKey: "pm_test",
        shouldCertify: ({ model }) => model === "gpt-4",
      });

      await mw.middleware.wrapGenerate({
        doGenerate: vi.fn().mockResolvedValue({ text: "ok" }),
        params: { prompt: "test" },
        model: { modelId: "gpt-4" },
      });

      expect(fetchMock).toHaveBeenCalledOnce();
    });
  });

  describe("default why and metadata options", () => {
    it("uses custom why from options", async () => {
      const fetchMock = mockFetch(201, CERT_RESPONSE);
      globalThis.fetch = fetchMock;

      const mw = xproofMiddleware({
        apiKey: "pm_test",
        why: "customer-support-bot",
      });

      await mw.middleware.wrapGenerate({
        doGenerate: vi.fn().mockResolvedValue({ text: "ok" }),
        params: { prompt: "test" },
        model: { modelId: "gpt-4" },
      });

      const body = JSON.parse(fetchMock.mock.calls[0][1].body);
      expect(body.metadata.why).toBe("customer-support-bot");
    });

    it("merges default metadata from options", async () => {
      const fetchMock = mockFetch(201, CERT_RESPONSE);
      globalThis.fetch = fetchMock;

      const mw = xproofMiddleware({
        apiKey: "pm_test",
        metadata: { env: "production", region: "us-east-1" },
      });

      await mw.middleware.wrapGenerate({
        doGenerate: vi.fn().mockResolvedValue({ text: "ok" }),
        params: { prompt: "test" },
        model: { modelId: "gpt-4" },
      });

      const body = JSON.parse(fetchMock.mock.calls[0][1].body);
      expect(body.metadata.env).toBe("production");
      expect(body.metadata.region).toBe("us-east-1");
      expect(body.metadata.framework).toBe("vercel-ai-sdk");
    });
  });

  describe("batch mode", () => {
    it("queues certifications until flush", async () => {
      const fetchMock = mockFetch(201, {
        batch_id: "b-1",
        total: 2,
        created: 2,
        existing: 0,
        results: [
          { ...CERT_RESPONSE, id: "p1" },
          { ...CERT_RESPONSE, id: "p2" },
        ],
      });
      globalThis.fetch = fetchMock;

      const mw = xproofMiddleware({
        apiKey: "pm_test",
        batchMode: true,
        batchFlushSize: 100,
      });

      await mw.middleware.wrapGenerate({
        doGenerate: vi.fn().mockResolvedValue({ text: "a" }),
        params: { prompt: "q1" },
        model: { modelId: "gpt-4" },
      });
      await mw.middleware.wrapGenerate({
        doGenerate: vi.fn().mockResolvedValue({ text: "b" }),
        params: { prompt: "q2" },
        model: { modelId: "gpt-4" },
      });

      expect(fetchMock).not.toHaveBeenCalled();
      expect(mw.pendingCount).toBe(2);

      const results = await mw.flushBatch();
      expect(results).toHaveLength(2);
      expect(fetchMock).toHaveBeenCalledOnce();
      expect(mw.pendingCount).toBe(0);
    });

    it("auto-flushes when reaching batchFlushSize", async () => {
      const fetchMock = mockFetch(201, {
        batch_id: "b-auto",
        total: 2,
        created: 2,
        existing: 0,
        results: [
          { ...CERT_RESPONSE, id: "pa1" },
          { ...CERT_RESPONSE, id: "pa2" },
        ],
      });
      globalThis.fetch = fetchMock;

      const mw = xproofMiddleware({
        apiKey: "pm_test",
        batchMode: true,
        batchFlushSize: 2,
      });

      await mw.middleware.wrapGenerate({
        doGenerate: vi.fn().mockResolvedValue({ text: "a" }),
        params: { prompt: "q1" },
        model: { modelId: "gpt-4" },
      });

      expect(fetchMock).not.toHaveBeenCalled();

      await mw.middleware.wrapGenerate({
        doGenerate: vi.fn().mockResolvedValue({ text: "b" }),
        params: { prompt: "q2" },
        model: { modelId: "gpt-4" },
      });

      expect(fetchMock).toHaveBeenCalledOnce();
      expect(mw.pendingCount).toBe(0);
      expect(mw.proofs).toHaveLength(2);
    });

    it("flushBatch returns empty array when nothing pending", async () => {
      const mw = xproofMiddleware({ apiKey: "pm_test", batchMode: true });
      const results = await mw.flushBatch();
      expect(results).toHaveLength(0);
    });
  });

  describe("middleware.wrapStream", () => {
    it("certifies after stream completes", async () => {
      const fetchMock = mockFetch(201, {
        ...CERT_RESPONSE,
        id: "proof-wrapstream",
      });
      globalThis.fetch = fetchMock;

      const mw = xproofMiddleware({ apiKey: "pm_test" });

      const chunks = [
        { type: "text-delta", textDelta: "Hello" },
        { type: "text-delta", textDelta: " world" },
      ];

      const readable = new ReadableStream({
        start(controller) {
          for (const chunk of chunks) {
            controller.enqueue(chunk);
          }
          controller.close();
        },
      });

      const doStream = vi.fn().mockResolvedValue({ stream: readable });

      const result = await mw.middleware.wrapStream({
        doStream,
        params: { prompt: "Say hello" },
        model: { modelId: "gpt-4" },
      });

      const reader = result.stream.getReader();
      const readChunks: unknown[] = [];
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        readChunks.push(value);
      }

      expect(readChunks).toHaveLength(2);

      await new Promise((r) => setTimeout(r, 50));

      expect(fetchMock).toHaveBeenCalledOnce();
      const body = JSON.parse(fetchMock.mock.calls[0][1].body);
      expect(body.metadata.model).toBe("gpt-4");
      expect(body.metadata.prompt_hash).toBeDefined();
      expect(body.metadata.result_hash).toBeDefined();
    });
  });

  describe("4W metadata consistency", () => {
    it("prompt and result produce deterministic hashes", async () => {
      const fetchMock = mockFetch(201, CERT_RESPONSE);
      globalThis.fetch = fetchMock;

      const mw = xproofMiddleware({ apiKey: "pm_test" });

      await mw.certifyGeneration({
        model: "gpt-4",
        prompt: "same prompt",
        result: "same result",
      });
      await mw.certifyGeneration({
        model: "gpt-4",
        prompt: "same prompt",
        result: "same result",
      });

      const body1 = JSON.parse(fetchMock.mock.calls[0][1].body);
      const body2 = JSON.parse(fetchMock.mock.calls[1][1].body);

      expect(body1.file_hash).toBe(body2.file_hash);
      expect(body1.metadata.prompt_hash).toBe(body2.metadata.prompt_hash);
      expect(body1.metadata.result_hash).toBe(body2.metadata.result_hash);
    });

    it("different prompts produce different hashes", async () => {
      const fetchMock = mockFetch(201, CERT_RESPONSE);
      globalThis.fetch = fetchMock;

      const mw = xproofMiddleware({ apiKey: "pm_test" });

      await mw.certifyGeneration({
        model: "gpt-4",
        prompt: "prompt A",
        result: "same",
      });
      await mw.certifyGeneration({
        model: "gpt-4",
        prompt: "prompt B",
        result: "same",
      });

      const body1 = JSON.parse(fetchMock.mock.calls[0][1].body);
      const body2 = JSON.parse(fetchMock.mock.calls[1][1].body);

      expect(body1.file_hash).not.toBe(body2.file_hash);
      expect(body1.metadata.prompt_hash).not.toBe(body2.metadata.prompt_hash);
    });
  });
});
