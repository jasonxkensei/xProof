import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { XProofClient } from "../src/client.js";
import {
  XProofError,
  AuthenticationError,
  ValidationError,
  NotFoundError,
  ConflictError,
  RateLimitError,
  ServerError,
} from "../src/errors.js";

const BASE = "https://xproof.app";

function mockFetch(status: number, body: unknown, contentType = "application/json") {
  return vi.fn().mockResolvedValue({
    status,
    json: async () => body,
    text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
    headers: new Headers({ "content-type": contentType }),
  });
}

describe("XProofClient", () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("sends Bearer auth header", async () => {
    const fetchMock = mockFetch(201, {
      id: "p1",
      fileName: "f",
      fileHash: "h",
      transactionHash: "t",
      transactionUrl: "",
      createdAt: "",
    });
    globalThis.fetch = fetchMock;

    const client = new XProofClient({ apiKey: "pm_test_key" });
    await client.certifyHash("a".repeat(64), "test.pdf", "author");

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [, options] = fetchMock.mock.calls[0];
    expect(options.headers["Authorization"]).toBe("Bearer pm_test_key");
  });

  it("sends snake_case payload fields", async () => {
    const fetchMock = mockFetch(201, {
      id: "p1",
      fileName: "f",
      fileHash: "h",
      transactionHash: "t",
      transactionUrl: "",
      createdAt: "",
    });
    globalThis.fetch = fetchMock;

    const client = new XProofClient({ apiKey: "pm_test" });
    await client.certifyHash("b".repeat(64), "doc.pdf", "alice");

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.file_hash).toBe("b".repeat(64));
    expect(body.filename).toBe("doc.pdf");
    expect(body.author_name).toBe("alice");
    expect(body.fileHash).toBeUndefined();
    expect(body.fileName).toBeUndefined();
  });

  it("certifyHash includes 4W metadata", async () => {
    const fetchMock = mockFetch(201, {
      id: "p-4w",
      fileName: "f",
      fileHash: "h",
      transactionHash: "t",
      transactionUrl: "",
      createdAt: "",
    });
    globalThis.fetch = fetchMock;

    const client = new XProofClient({ apiKey: "pm_test" });
    await client.certifyHash("c".repeat(64), "action.json", "agent-x", {
      who: "erd1abc...",
      what: "sha256-of-action",
      when: "2026-03-20T12:00:00Z",
      why: "sha256-of-instruction",
      metadata: { custom_key: "custom_value" },
    });

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.metadata.who).toBe("erd1abc...");
    expect(body.metadata.what).toBe("sha256-of-action");
    expect(body.metadata.when).toBe("2026-03-20T12:00:00Z");
    expect(body.metadata.why).toBe("sha256-of-instruction");
    expect(body.metadata.custom_key).toBe("custom_value");
  });

  it("certifyHash omits metadata when no 4W provided", async () => {
    const fetchMock = mockFetch(201, {
      id: "p-no4w",
      fileName: "f",
      fileHash: "h",
      transactionHash: "t",
      transactionUrl: "",
      createdAt: "",
    });
    globalThis.fetch = fetchMock;

    const client = new XProofClient({ apiKey: "pm_test" });
    await client.certifyHash("d".repeat(64), "doc.pdf", "author");

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.metadata).toBeUndefined();
  });

  it("batchCertify sends correct payload", async () => {
    const fetchMock = mockFetch(201, {
      batch_id: "batch-001",
      total: 2,
      created: 2,
      existing: 0,
      results: [
        { file_hash: "h1", filename: "a.pdf", proof_id: "p-b1", status: "created" },
        { file_hash: "h2", filename: "b.pdf", proof_id: "p-b2", status: "created" },
      ],
    });
    globalThis.fetch = fetchMock;

    const client = new XProofClient({ apiKey: "pm_test" });
    const result = await client.batchCertify([
      { fileHash: "h1", fileName: "a.pdf", author: "agent" },
      { fileHash: "h2", fileName: "b.pdf" },
    ]);

    expect(result.batchId).toBe("batch-001");
    expect(result.summary.total).toBe(2);
    expect(result.summary.created).toBe(2);
    expect(result.summary.existing).toBe(0);
    expect(result.results).toHaveLength(2);
    expect(result.results[0].id).toBe("p-b1");

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.author_name).toBe("agent");
    expect(body.files[0].file_hash).toBe("h1");
    expect(body.files[0].filename).toBe("a.pdf");
  });

  it("batchCertify rejects more than 50 files", async () => {
    const client = new XProofClient({ apiKey: "pm_test" });
    const files = Array.from({ length: 51 }, (_, i) => ({
      fileHash: `h${i}`,
      fileName: `f${i}`,
    }));
    await expect(client.batchCertify(files)).rejects.toThrow("maximum of 50");
  });

  it("verify uses correct public endpoint", async () => {
    const fetchMock = mockFetch(200, {
      id: "proof-001",
      fileName: "doc.pdf",
      fileHash: "xyz",
      transactionHash: "tx-v",
      transactionUrl: "",
      createdAt: "",
    });
    globalThis.fetch = fetchMock;

    const client = new XProofClient({ apiKey: "pm_test" });
    const cert = await client.verify("proof-001");

    expect(cert.id).toBe("proof-001");
    expect(cert.fileName).toBe("doc.pdf");
    const [url] = fetchMock.mock.calls[0];
    expect(url).toBe(`${BASE}/api/proof/proof-001`);
    expect(fetchMock.mock.calls[0][1].headers["Authorization"]).toBeUndefined();
  });

  it("verifyHash uses /api/proof/hash/ endpoint", async () => {
    const fetchMock = mockFetch(200, {
      id: "proof-vh",
      fileName: "doc.pdf",
      fileHash: "abc123",
      transactionHash: "tx-vh",
      transactionUrl: "",
      createdAt: "",
    });
    globalThis.fetch = fetchMock;

    const client = new XProofClient();
    const cert = await client.verifyHash("abc123");

    expect(cert.id).toBe("proof-vh");
    const [url] = fetchMock.mock.calls[0];
    expect(url).toBe(`${BASE}/api/proof/hash/abc123`);
  });

  it("getPricing returns parsed pricing info", async () => {
    const fetchMock = mockFetch(200, {
      protocol: "xproof",
      version: "1.0",
      price_usd: 0.05,
      tiers: [{ min: 1, max: 100, price: 0.05 }],
    });
    globalThis.fetch = fetchMock;

    const client = new XProofClient();
    const pricing = await client.getPricing();

    expect(pricing.protocol).toBe("xproof");
    expect(pricing.priceUsd).toBe(0.05);
    expect(pricing.tiers).toHaveLength(1);
  });

  it("register creates authenticated client", async () => {
    const fetchMock = mockFetch(201, {
      api_key: "pm_new_trial",
      agent_name: "test-agent",
      trial: { quota: 10, used: 0, remaining: 10 },
      endpoints: { certify: "/api/proof" },
    });
    globalThis.fetch = fetchMock;

    const client = await XProofClient.register("test-agent");
    expect(client.registration).not.toBeNull();
    expect(client.registration!.apiKey).toBe("pm_new_trial");
    expect(client.registration!.trial.remaining).toBe(10);

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.agent_name).toBe("test-agent");
  });

  it("throws AuthenticationError on 401", async () => {
    globalThis.fetch = mockFetch(401, { message: "Invalid API key" });
    const client = new XProofClient({ apiKey: "pm_bad" });
    await expect(client.certifyHash("a".repeat(64), "f", "a")).rejects.toThrow(
      AuthenticationError
    );
  });

  it("throws ValidationError on 400", async () => {
    globalThis.fetch = mockFetch(400, { message: "Invalid request" });
    const client = new XProofClient({ apiKey: "pm_test" });
    await expect(client.certifyHash("bad", "f", "a")).rejects.toThrow(
      ValidationError
    );
  });

  it("throws NotFoundError on 404", async () => {
    globalThis.fetch = mockFetch(404, { message: "Not found" });
    const client = new XProofClient();
    await expect(client.verify("nonexistent")).rejects.toThrow(NotFoundError);
  });

  it("throws ConflictError on 409", async () => {
    globalThis.fetch = mockFetch(409, {
      message: "Already certified",
      certificationId: "existing-id",
    });
    const client = new XProofClient({ apiKey: "pm_test" });
    try {
      await client.certifyHash("a".repeat(64), "f", "a");
      expect.fail("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(ConflictError);
      expect((err as ConflictError).certificationId).toBe("existing-id");
    }
  });

  it("throws RateLimitError on 429", async () => {
    globalThis.fetch = mockFetch(429, { message: "Too many requests" });
    const client = new XProofClient({ apiKey: "pm_test" });
    await expect(client.certifyHash("a".repeat(64), "f", "a")).rejects.toThrow(
      RateLimitError
    );
  });

  it("throws ServerError on 500", async () => {
    globalThis.fetch = mockFetch(500, { message: "Internal error" });
    const client = new XProofClient({ apiKey: "pm_test" });
    await expect(client.certifyHash("a".repeat(64), "f", "a")).rejects.toThrow(
      ServerError
    );
  });

  it("throws XProofError on non-JSON success response", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      status: 200,
      json: async () => { throw new Error("not json"); },
      text: async () => "<html>Not Found</html>",
      headers: new Headers({ "content-type": "text/html" }),
    });
    const client = new XProofClient({ apiKey: "pm_test" });
    await expect(client.certifyHash("a".repeat(64), "f", "a")).rejects.toThrow(
      XProofError
    );
  });

  it("requires apiKey for certifyHash", async () => {
    const client = new XProofClient();
    await expect(client.certifyHash("a".repeat(64), "f", "a")).rejects.toThrow(
      "apiKey is required"
    );
  });

  it("parses timestamp field as createdAt", async () => {
    const fetchMock = mockFetch(201, {
      id: "p-ts",
      fileName: "f",
      fileHash: "h",
      transactionHash: "t",
      transactionUrl: "",
      timestamp: "2026-03-20T12:00:00Z",
    });
    globalThis.fetch = fetchMock;

    const client = new XProofClient({ apiKey: "pm_test" });
    const cert = await client.certifyHash("a".repeat(64), "f", "a");
    expect(cert.createdAt).toBe("2026-03-20T12:00:00Z");
  });
});
