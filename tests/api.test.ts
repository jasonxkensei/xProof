import { describe, it, expect } from "vitest";

const BASE_URL = "http://localhost:5000";

describe("xproof API", () => {
  describe("Discovery Endpoints", () => {
    it("GET /api/acp/health should return operational status", async () => {
      const res = await fetch(`${BASE_URL}/api/acp/health`);
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.status).toBe("operational");
      expect(body.service).toBe("xproof");
      expect(body.version).toBeDefined();
      expect(body.timestamp).toBeDefined();
      expect(body.endpoints).toBeDefined();
    });

    it("GET /api/acp/products should return ACP products", async () => {
      const res = await fetch(`${BASE_URL}/api/acp/products`);
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.protocol).toBe("ACP");
      expect(body.provider).toBe("xproof");
      expect(body.chain).toBe("MultiversX");
      expect(Array.isArray(body.products)).toBe(true);
      expect(body.products.length).toBeGreaterThan(0);
      const product = body.products[0];
      expect(product.id).toBe("xproof-certification");
      expect(product.pricing).toBeDefined();
      expect(product.inputs).toBeDefined();
      expect(product.outputs).toBeDefined();
    });

    it("GET /llms.txt should return text containing xproof", async () => {
      const res = await fetch(`${BASE_URL}/llms.txt`);
      expect(res.status).toBe(200);
      const contentType = res.headers.get("content-type");
      expect(contentType).toContain("text/plain");
      const text = await res.text();
      expect(text).toContain("xproof");
    });

    it("GET /.well-known/xproof.md should return xproof specification", async () => {
      const res = await fetch(`${BASE_URL}/.well-known/xproof.md`);
      expect(res.status).toBe(200);
      const contentType = res.headers.get("content-type");
      expect(contentType).toContain("text/markdown");
      const text = await res.text();
      expect(text).toContain("xproof Specification");
    });

    it("GET /robots.txt should return robots content", async () => {
      const res = await fetch(`${BASE_URL}/robots.txt`);
      expect(res.status).toBe(200);
      const contentType = res.headers.get("content-type");
      expect(contentType).toContain("text/plain");
      const text = await res.text();
      expect(text).toContain("User-agent");
      expect(text).toContain("Sitemap");
    });

    it("GET /sitemap.xml should return valid sitemap XML", async () => {
      const res = await fetch(`${BASE_URL}/sitemap.xml`);
      expect(res.status).toBe(200);
      const contentType = res.headers.get("content-type");
      expect(contentType).toContain("application/xml");
      const text = await res.text();
      expect(text).toContain("urlset");
      expect(text).toContain("<?xml");
    });

    it("GET /.well-known/mcp.json should return MCP manifest", async () => {
      const res = await fetch(`${BASE_URL}/.well-known/mcp.json`);
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.name).toBe("xproof");
      expect(body.schema_version).toBe("1.0");
      expect(body.endpoint).toBeDefined();
      expect(body.transport).toBe("streamable-http");
      expect(body.capabilities).toBeDefined();
      expect(Array.isArray(body.tools)).toBe(true);
      expect(Array.isArray(body.resources)).toBe(true);
      expect(body.authentication).toBeDefined();
      expect(body.authentication.token_prefix).toBe("pm_");
    });

    it("GET /.well-known/ai-plugin.json should return OpenAI plugin manifest", async () => {
      const res = await fetch(`${BASE_URL}/.well-known/ai-plugin.json`);
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.schema_version).toBe("v1");
      expect(body.name_for_human).toBe("xproof");
      expect(body.name_for_model).toBe("xproof");
      expect(body.description_for_human).toBeDefined();
      expect(body.description_for_model).toBeDefined();
      expect(body.auth).toBeDefined();
      expect(body.api).toBeDefined();
      expect(body.api.type).toBe("openapi");
    });
  });

  describe("POST /api/proof (auth required)", () => {
    it("should return 401 without Authorization header", async () => {
      const res = await fetch(`${BASE_URL}/api/proof`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          file_hash: "a".repeat(64),
          filename: "test.pdf",
        }),
      });
      expect(res.status).toBe(401);
      const body = await res.json();
      expect(body.error).toBe("UNAUTHORIZED");
    });

    it("should return 401 with invalid API key", async () => {
      const res = await fetch(`${BASE_URL}/api/proof`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer pm_invalid_key_that_does_not_exist",
        },
        body: JSON.stringify({
          file_hash: "a".repeat(64),
          filename: "test.pdf",
        }),
      });
      expect(res.status).toBe(401);
      const body = await res.json();
      expect(body.error).toBe("INVALID_API_KEY");
    });

    it("should return 401 with non-pm prefixed key", async () => {
      const res = await fetch(`${BASE_URL}/api/proof`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer sk_not_a_valid_prefix",
        },
        body: JSON.stringify({
          file_hash: "a".repeat(64),
          filename: "test.pdf",
        }),
      });
      expect(res.status).toBe(401);
      const body = await res.json();
      expect(body.error).toBe("INVALID_API_KEY");
    });

    it("should return 401 without Bearer prefix", async () => {
      const res = await fetch(`${BASE_URL}/api/proof`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "pm_some_key",
        },
        body: JSON.stringify({
          file_hash: "a".repeat(64),
          filename: "test.pdf",
        }),
      });
      expect(res.status).toBe(401);
      const body = await res.json();
      expect(["UNAUTHORIZED", "INVALID_API_KEY"]).toContain(body.error);
    });
  });

  describe("POST /api/batch (auth required)", () => {
    it("should return 401 or 429 without Authorization header", async () => {
      const res = await fetch(`${BASE_URL}/api/batch`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          files: [{ file_hash: "a".repeat(64), filename: "test.pdf" }],
        }),
      });
      expect([401, 429]).toContain(res.status);
      const body = await res.json();
      expect(["UNAUTHORIZED", "TOO_MANY_REQUESTS"]).toContain(body.error);
    });

    it("should return 401 or 429 with invalid API key", async () => {
      const res = await fetch(`${BASE_URL}/api/batch`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer pm_invalid_key_that_does_not_exist",
        },
        body: JSON.stringify({
          files: [{ file_hash: "a".repeat(64), filename: "test.pdf" }],
        }),
      });
      expect([401, 429]).toContain(res.status);
      const body = await res.json();
      expect(["INVALID_API_KEY", "TOO_MANY_REQUESTS"]).toContain(body.error);
    });
  });

  describe("GET /api/proof/:id (public)", () => {
    it("should return 404 for non-existent proof ID", async () => {
      const res = await fetch(`${BASE_URL}/api/proof/nonexistent-id-12345`);
      expect(res.status).toBe(404);
      const body = await res.json();
      expect(body.message).toBeDefined();
    });

    it("should return 404 for random UUID", async () => {
      const res = await fetch(`${BASE_URL}/api/proof/00000000-0000-0000-0000-000000000000`);
      expect(res.status).toBe(404);
    });
  });

  describe("Badge Endpoints", () => {
    it("GET /badge/nonexistent-id should return SVG with Not Found", async () => {
      const res = await fetch(`${BASE_URL}/badge/nonexistent-id`);
      expect(res.status).toBe(200);
      const contentType = res.headers.get("content-type");
      expect(contentType).toContain("image/svg+xml");
      const text = await res.text();
      expect(text).toContain("Not Found");
      expect(text).toContain("<svg");
      expect(text).toContain("xproof");
    });
  });

  describe("GET /api/acp/openapi.json", () => {
    it("should return valid OpenAPI 3.0 specification", async () => {
      const res = await fetch(`${BASE_URL}/api/acp/openapi.json`);
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.openapi).toBe("3.0.3");
      expect(body.info).toBeDefined();
      expect(body.info.title).toContain("xproof");
      expect(body.info.version).toBeDefined();
      expect(body.servers).toBeDefined();
      expect(Array.isArray(body.servers)).toBe(true);
      expect(body.components).toBeDefined();
      expect(body.components.securitySchemes).toBeDefined();
      expect(body.components.schemas).toBeDefined();
      expect(body.paths).toBeDefined();
      expect(body.paths["/api/acp/products"]).toBeDefined();
      expect(body.paths["/api/acp/checkout"]).toBeDefined();
      expect(body.paths["/api/acp/confirm"]).toBeDefined();
      expect(body.paths["/api/proof"]).toBeDefined();
    });
  });

  describe("Well-Known and Discovery Aliases", () => {
    it("GET /.well-known/agent.json should return agent protocol manifest", async () => {
      const res = await fetch(`${BASE_URL}/.well-known/agent.json`);
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.name).toBe("xproof");
      expect(body.version).toBe("1.0.0");
      expect(body.capabilities).toBeDefined();
      expect(Array.isArray(body.capabilities)).toBe(true);
      expect(body.protocols).toBeDefined();
      expect(body.authentication).toBeDefined();
      expect(body.authentication.type).toBe("bearer");
      expect(body.pricing).toBeDefined();
    });

    it("GET /genesis.proof.json should return genesis certification", async () => {
      const res = await fetch(`${BASE_URL}/genesis.proof.json`);
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.id).toBe("genesis");
      expect(body.type).toBe("proof_of_existence");
      expect(body.file_hash).toBeDefined();
      expect(body.blockchain).toBeDefined();
      expect(body.blockchain.transaction_hash).toBeDefined();
    });

    it("GET /genesis.md should return genesis markdown", async () => {
      const res = await fetch(`${BASE_URL}/genesis.md`);
      expect(res.status).toBe(200);
      const contentType = res.headers.get("content-type");
      expect(contentType).toContain("text/markdown");
      const text = await res.text();
      expect(text).toContain("Genesis");
    });

    it("GET /llms-full.txt should return extended LLM documentation", async () => {
      const res = await fetch(`${BASE_URL}/llms-full.txt`);
      expect(res.status).toBe(200);
      const contentType = res.headers.get("content-type");
      expect(contentType).toContain("text/plain");
      const text = await res.text();
      expect(text).toContain("xproof");
      expect(text).toContain("POST /api/proof");
    });
  });

  describe("ACP Checkout/Confirm Auth", () => {
    it("POST /api/acp/checkout should return 401 without auth", async () => {
      const res = await fetch(`${BASE_URL}/api/acp/checkout`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          product_id: "xproof-certification",
          inputs: { file_hash: "a".repeat(64), filename: "test.pdf" },
        }),
      });
      expect(res.status).toBe(401);
      const body = await res.json();
      expect(body.error).toBe("UNAUTHORIZED");
    });

    it("POST /api/acp/confirm should return 401 without auth", async () => {
      const res = await fetch(`${BASE_URL}/api/acp/confirm`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          checkout_id: "nonexistent",
          tx_hash: "abc123",
        }),
      });
      expect(res.status).toBe(401);
      const body = await res.json();
      expect(body.error).toBe("UNAUTHORIZED");
    });
  });

  describe("Learn Endpoints", () => {
    it("GET /learn/proof-of-existence.md should return markdown content", async () => {
      const res = await fetch(`${BASE_URL}/learn/proof-of-existence.md`);
      expect(res.status).toBe(200);
      const contentType = res.headers.get("content-type");
      expect(contentType).toContain("text/markdown");
      const text = await res.text();
      expect(text).toContain("Proof of Existence");
    });

    it("GET /learn/verification.md should return verification guide", async () => {
      const res = await fetch(`${BASE_URL}/learn/verification.md`);
      expect(res.status).toBe(200);
      const text = await res.text();
      expect(text).toContain("Verify");
    });

    it("GET /learn/api.md should return API documentation", async () => {
      const res = await fetch(`${BASE_URL}/learn/api.md`);
      expect(res.status).toBe(200);
      const text = await res.text();
      expect(text).toContain("API");
    });
  });

  describe("MCP Endpoint", () => {
    it("GET /mcp should return 405 Method Not Allowed", async () => {
      const res = await fetch(`${BASE_URL}/mcp`);
      expect(res.status).toBe(405);
      const body = await res.json();
      expect(body.jsonrpc).toBe("2.0");
      expect(body.error).toBeDefined();
      expect(body.error.message).toContain("Method not allowed");
    });
  });
});
