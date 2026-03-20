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

describe("xproofMiddleware", () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("certifyGeneration sends correct payload", async () => {
    const fetchMock = mockFetch(201, {
      id: "proof-vercel",
      fileName: "ai-generate.json",
      fileHash: "h",
      transactionHash: "tx-vercel",
      transactionUrl: "",
      createdAt: "",
    });
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

  it("certifyStream calls certifyGeneration internally", async () => {
    const fetchMock = mockFetch(201, {
      id: "proof-stream",
      fileName: "ai-stream.json",
      fileHash: "hs",
      transactionHash: "tx-stream",
      transactionUrl: "",
      createdAt: "",
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

  it("includes custom metadata", async () => {
    const fetchMock = mockFetch(201, {
      id: "p",
      fileName: "f",
      fileHash: "h",
      transactionHash: "t",
      transactionUrl: "",
      createdAt: "",
    });
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
    const fetchMock = mockFetch(201, {
      id: "p",
      fileName: "f",
      fileHash: "h",
      transactionHash: "t",
      transactionUrl: "",
      createdAt: "",
    });
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
