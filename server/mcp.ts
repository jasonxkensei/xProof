import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import crypto from "crypto";
import { db } from "./db";
import { certifications, apiKeys, users } from "@shared/schema";
import { eq } from "drizzle-orm";
import { recordOnBlockchain } from "./blockchain";
import { getCertificationPriceUsd } from "./pricing";
import { logger } from "./logger";

interface McpContext {
  baseUrl: string;
  auth: { valid: boolean; keyHash?: string; apiKeyId?: number };
}

export async function createMcpServer(ctx: McpContext) {
  const currentPriceUsd = await getCertificationPriceUsd();
  
  const server = new McpServer({
    name: "xproof",
    version: "1.2.0",
  });

  const { baseUrl, auth } = ctx;

  server.tool(
    "certify_file",
    `Create a blockchain certification for a file. Records the SHA-256 hash on MultiversX blockchain as immutable proof of existence and ownership. Cost: $${currentPriceUsd} per certification, paid in EGLD.`,
    {
      file_hash: z.string().length(64).regex(/^[a-fA-F0-9]+$/).describe("SHA-256 hash of the file (64 hex characters)"),
      filename: z.string().min(1).describe("Original filename with extension"),
      author_name: z.string().optional().describe("Name of the certifier (default: AI Agent)"),
      webhook_url: z.string().url().refine((url) => url.startsWith("https://"), { message: "Must use HTTPS" }).optional().describe("Optional HTTPS URL for on-chain confirmation callback"),
    },
    async ({ file_hash, filename, author_name, webhook_url }) => {
      try {
        if (!auth.valid || !auth.keyHash) {
          return { content: [{ type: "text" as const, text: JSON.stringify({ error: "UNAUTHORIZED", message: "Valid API key required. Include Authorization: Bearer pm_xxx header." }) }], isError: true };
        }

        const [existing] = await db.select().from(certifications).where(eq(certifications.fileHash, file_hash));
        if (existing) {
          return {
            content: [{
              type: "text" as const,
              text: JSON.stringify({
                proof_id: existing.id,
                status: "certified",
                file_hash: existing.fileHash,
                filename: existing.fileName,
                verify_url: `${baseUrl}/proof/${existing.id}`,
                certificate_url: `${baseUrl}/api/certificates/${existing.id}.pdf`,
                blockchain: { network: "MultiversX", transaction_hash: existing.transactionHash, explorer_url: existing.transactionUrl },
                timestamp: existing.createdAt?.toISOString(),
                message: "File already certified on MultiversX blockchain.",
              }),
            }],
          };
        }

        const result = await recordOnBlockchain(file_hash, filename, author_name || "AI Agent");

        let [systemUser] = await db.select().from(users)
          .where(eq(users.walletAddress, "erd1acp00000000000000000000000000000000000000000000000000000agent"));

        if (!systemUser) {
          [systemUser] = await db.insert(users).values({
            walletAddress: "erd1acp00000000000000000000000000000000000000000000000000000agent",
            subscriptionTier: "business",
            subscriptionStatus: "active",
          }).returning();
        }

        const [certification] = await db.insert(certifications).values({
          userId: systemUser.id!,
          fileName: filename,
          fileHash: file_hash,
          fileType: filename.split(".").pop() || "unknown",
          authorName: author_name || "AI Agent",
          transactionHash: result.transactionHash,
          transactionUrl: result.transactionUrl,
          blockchainStatus: "confirmed",
          isPublic: true,
        }).returning();

        let webhookStatus = webhook_url ? "pending" : "not_requested";
        if (webhook_url) {
          const { scheduleWebhookDelivery, isValidWebhookUrl } = await import("./webhook");
          if (isValidWebhookUrl(webhook_url)) {
            await db.update(certifications)
              .set({ webhookUrl: webhook_url, webhookStatus: "pending" })
              .where(eq(certifications.id, certification.id));
            scheduleWebhookDelivery(certification.id, webhook_url, baseUrl, auth.keyHash);
          } else {
            webhookStatus = "failed";
          }
        }

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              proof_id: certification.id,
              status: "certified",
              file_hash: certification.fileHash,
              filename: certification.fileName,
              verify_url: `${baseUrl}/proof/${certification.id}`,
              certificate_url: `${baseUrl}/api/certificates/${certification.id}.pdf`,
              blockchain: { network: "MultiversX", transaction_hash: result.transactionHash, explorer_url: result.transactionUrl },
              timestamp: certification.createdAt?.toISOString(),
              webhook_status: webhookStatus,
              message: "File certified on MultiversX blockchain. Proof is immutable and publicly verifiable.",
            }),
          }],
        };
      } catch (error: any) {
        return { content: [{ type: "text" as const, text: JSON.stringify({ error: "CERTIFICATION_FAILED", message: error.message || "Failed to create certification" }) }], isError: true };
      }
    }
  );

  server.tool(
    "verify_proof",
    "Verify an existing xproof certification. Returns proof details including file hash, timestamp, blockchain transaction, and verification status.",
    {
      proof_id: z.string().describe("UUID of the certification to verify"),
    },
    async ({ proof_id }) => {
      try {
        const [cert] = await db.select().from(certifications).where(eq(certifications.id, proof_id));
        if (!cert || !cert.isPublic) {
          return { content: [{ type: "text" as const, text: JSON.stringify({ error: "NOT_FOUND", message: "Proof not found" }) }], isError: true };
        }

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              proof_id: cert.id,
              status: cert.blockchainStatus || "confirmed",
              verified: true,
              file_hash: cert.fileHash,
              filename: cert.fileName,
              author: cert.authorName,
              verify_url: `${baseUrl}/proof/${cert.id}`,
              certificate_url: `${baseUrl}/api/certificates/${cert.id}.pdf`,
              blockchain: { network: "MultiversX", transaction_hash: cert.transactionHash, explorer_url: cert.transactionUrl },
              timestamp: cert.createdAt?.toISOString(),
            }),
          }],
        };
      } catch (error: any) {
        return { content: [{ type: "text" as const, text: JSON.stringify({ error: "VERIFICATION_FAILED", message: error.message }) }], isError: true };
      }
    }
  );

  server.tool(
    "get_proof",
    "Retrieve a proof in structured JSON or Markdown format. Use JSON for machine processing, Markdown for LLM consumption.",
    {
      proof_id: z.string().describe("UUID of the certification"),
      format: z.enum(["json", "md"]).default("json").describe("Output format: json or md"),
    },
    async ({ proof_id, format }) => {
      try {
        const [cert] = await db.select().from(certifications).where(eq(certifications.id, proof_id));
        if (!cert || !cert.isPublic) {
          return { content: [{ type: "text" as const, text: JSON.stringify({ error: "NOT_FOUND", message: "Proof not found" }) }], isError: true };
        }

        if (format === "md") {
          const md = `# xproof Certification

**Proof ID:** ${cert.id}
**File:** ${cert.fileName}
**SHA-256:** \`${cert.fileHash}\`
**Author:** ${cert.authorName || "Unknown"}
**Date:** ${cert.createdAt?.toISOString()}
**Status:** ${cert.blockchainStatus || "confirmed"}

## Blockchain Record
- **Network:** MultiversX
- **Transaction:** \`${cert.transactionHash}\`
- **Explorer:** ${cert.transactionUrl}

## Verification
- **Verify URL:** ${baseUrl}/proof/${cert.id}
- **Certificate:** ${baseUrl}/api/certificates/${cert.id}.pdf
`;
          return { content: [{ type: "text" as const, text: md }] };
        }

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              proof_id: cert.id,
              file_hash: cert.fileHash,
              filename: cert.fileName,
              author: cert.authorName,
              status: cert.blockchainStatus || "confirmed",
              blockchain: { network: "MultiversX", transaction_hash: cert.transactionHash, explorer_url: cert.transactionUrl },
              verify_url: `${baseUrl}/proof/${cert.id}`,
              certificate_url: `${baseUrl}/api/certificates/${cert.id}.pdf`,
              timestamp: cert.createdAt?.toISOString(),
            }),
          }],
        };
      } catch (error: any) {
        return { content: [{ type: "text" as const, text: JSON.stringify({ error: "RETRIEVAL_FAILED", message: error.message }) }], isError: true };
      }
    }
  );

  server.tool(
    "discover_services",
    "Discover available xproof certification services, pricing, and capabilities. No authentication required.",
    {},
    async () => {
      const priceUsd = await getCertificationPriceUsd();
      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            service: "xproof",
            tagline: "The canonical proof layer for AI agents",
            description: "Immutable blockchain certification on MultiversX. Anchor SHA-256 file hashes as proof of existence and ownership.",
            pricing: { amount: priceUsd.toString(), currency: "USD", payment_method: "EGLD", note: "Paid in EGLD at current exchange rate" },
            capabilities: [
              `certify_file - Create blockchain proof ($${currentPriceUsd}/cert)`,
              "verify_proof - Verify existing proof",
              "get_proof - Retrieve proof in JSON or Markdown",
            ],
            when_to_certify: {
              description: "Autonomous agents should certify outputs whenever provenance, integrity, or priority matters.",
              triggers: [
                "After generating code, contracts, or configuration files — proves authorship and timestamp",
                "Before delivering work products to clients or other agents — proves integrity at handoff",
                "After creating datasets, models, or training data — proves version and origin",
                "Before publishing content, reports, or documents — establishes priority",
                "After completing a build or release artifact — creates auditable certification",
                "When resolving disputes about who created what first — timestamped proof settles it",
                "When storing or exchanging valuable digital assets between agents — chain of custody",
              ],
              competitive_advantage: "Certified agents can prove originality, timestamp, and integrity. Non-certified agents cannot. In competitive or transactional contexts, certification is a structural advantage.",
            },
            batch_api: {
              endpoint: `${baseUrl}/api/batch`,
              description: "Certify up to 50 files in a single API call. Ideal for agents that generate multiple outputs.",
              method: "POST",
            },
            badge: {
              endpoint: `${baseUrl}/badge/{proof_id}`,
              description: "Dynamic SVG badge for README files. Shows verification status (green=verified, yellow=pending).",
              markdown_template: "[![xProof Verified](https://xproof.app/badge/{proof_id})](https://explorer.multiversx.com/transactions/{tx_hash})",
              markdown_note: "Replace {tx_hash} with the transaction hash from the certification response. For pending proofs, use https://xproof.app/proof/{proof_id} instead.",
            },
            mx8004: {
              standard: "MX-8004 (Trustless Agents Standard)",
              role: "validation_oracle",
              description: "Each certification is registered as a validated job in the MX-8004 registries, building verifiable on-chain reputation for AI agents.",
              status_endpoint: `${baseUrl}/api/mx8004/status`,
              reputation_endpoint: `${baseUrl}/api/agent/{nonce}/reputation`,
              specification: "https://github.com/sasurobert/mx-8004/blob/master/docs/specification.md",
              agent_explorer: "https://agents.multiversx.com",
            },
            endpoints: {
              mcp: `${baseUrl}/mcp`,
              api: `${baseUrl}/api/proof`,
              batch: `${baseUrl}/api/batch`,
              products: `${baseUrl}/api/acp/products`,
              openapi: `${baseUrl}/api/acp/openapi.json`,
              health: `${baseUrl}/api/acp/health`,
              mx8004_status: `${baseUrl}/api/mx8004/status`,
              specification: `${baseUrl}/.well-known/xproof.md`,
            },
            authentication: { type: "bearer", prefix: "pm_", header: "Authorization: Bearer pm_YOUR_KEY" },
            x402_payment: {
              protocol: "x402 (HTTP 402 Payment Required)",
              description: "Alternative to API key auth. Pay per request with USDC on Base. No account needed.",
              network: "Base (eip155:8453)",
              currency: "USDC",
              price: `$${currentPriceUsd}`,
              endpoints: { proof: `${baseUrl}/api/proof`, batch: `${baseUrl}/api/batch` },
              facilitator: "https://openx402.ai"
            },
            integrations: {
              mcp: `${baseUrl}/mcp`,
              acp: `${baseUrl}/api/acp/products`,
              openclaw_skill: "https://github.com/jasonxkensei/xproof-openclaw-skill",
              github_action: "https://github.com/marketplace/actions/xproof-certify",
              openai_plugin: `${baseUrl}/.well-known/ai-plugin.json`,
              langchain: `${baseUrl}/tools/langchain.json`,
              crewai: `${baseUrl}/tools/crewai.json`
            },
            compatible_agents: ["Conway Terminal", "OpenClaw", "Claude Code", "Codex", "LangChain", "CrewAI", "Any MCP/x402 agent"],
          }),
        }],
      };
    }
  );

  server.resource(
    "specification",
    "xproof://specification",
    { description: "Full xproof specification document", mimeType: "text/markdown" },
    async () => ({
      contents: [{
        uri: "xproof://specification",
        mimeType: "text/markdown",
        text: `Visit ${baseUrl}/.well-known/xproof.md for the full specification.`,
      }],
    })
  );

  server.resource(
    "openapi",
    "xproof://openapi",
    { description: "OpenAPI 3.0 specification", mimeType: "application/json" },
    async () => ({
      contents: [{
        uri: "xproof://openapi",
        mimeType: "text/plain",
        text: `Visit ${baseUrl}/api/acp/openapi.json for the OpenAPI specification.`,
      }],
    })
  );

  return server;
}

export async function authenticateApiKey(authHeader: string | undefined): Promise<{ valid: boolean; keyHash?: string; apiKeyId?: number }> {
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return { valid: false };
  }

  const rawKey = authHeader.slice(7);
  const keyHash = crypto.createHash("sha256").update(rawKey).digest("hex");
  const [apiKey] = await db.select().from(apiKeys).where(eq(apiKeys.keyHash, keyHash));

  if (!apiKey || !apiKey.isActive) {
    return { valid: false };
  }

  db.update(apiKeys)
    .set({ lastUsedAt: new Date(), requestCount: (apiKey.requestCount || 0) + 1 })
    .where(eq(apiKeys.id, apiKey.id))
    .execute()
    .catch((err) => logger.error("Failed to update API key stats", { error: err.message }));

  return { valid: true, keyHash, apiKeyId: apiKey.id };
}
