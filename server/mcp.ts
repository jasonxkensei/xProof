import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import crypto from "crypto";
import { db } from "./db";
import { certifications, apiKeys, users } from "@shared/schema";
import { eq, sql } from "drizzle-orm";
import { recordOnBlockchain } from "./blockchain";
import { getCertificationPriceUsd } from "./pricing";
import { logger } from "./logger";
import { auditLogSchema } from "./auditSchema";
import { reconstructAuditTrail } from "./audit-trail";
import { isX402Configured, verifyX402PaymentRaw, getInvestigatePaymentRequirements } from "./x402";

interface McpContext {
  baseUrl: string;
  auth: { valid: boolean; keyHash?: string; apiKeyId?: number };
  xPaymentHeader?: string;
  host: string;
}

export async function createMcpServer(ctx: McpContext) {
  const currentPriceUsd = await getCertificationPriceUsd();
  
  const server = new McpServer({
    name: "xproof",
    version: "1.3.0",
  });

  const { baseUrl, auth, xPaymentHeader, host } = ctx;

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
          authMethod: "api_key",
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
    "certify_with_confidence",
    `Create a staged blockchain certification with a confidence score. Use this when your decision builds progressively — certify at 60% (initial assessment), 80% (pre-commitment), and 100% (final decision). Each stage shares the same decision_id, creating an on-chain audit trail of the decision process. Governance: set reversibility_class='irreversible' for actions that cannot be undone — xproof will flag a policy violation if confidence_level < 0.95. Cost: $${currentPriceUsd} per certification.`,
    {
      file_hash: z.string().length(64).regex(/^[a-fA-F0-9]+$/).describe("SHA-256 hash of the decision or output file (64 hex characters)"),
      filename: z.string().min(1).describe("Original filename with extension (e.g. decision.json)"),
      decision_id: z.string().min(1).describe("Shared UUID linking all confidence stages for the same decision. Generate once and reuse across all stages."),
      confidence_level: z.number().min(0).max(1).describe("Confidence score from 0.0 to 1.0. Typical values: 0.6 (initial), 0.8 (pre-commitment), 1.0 (final)."),
      threshold_stage: z.enum(["initial", "partial", "pre-commitment", "final"]).describe("Named stage of the decision: initial (first assessment), partial (gathering info), pre-commitment (almost certain), final (committed)."),
      author_name: z.string().optional().describe("Name of the certifying agent (default: AI Agent)"),
      why: z.string().optional().describe("Reason or instruction hash driving this decision"),
      who: z.string().optional().describe("Agent identity (wallet address, name, or agent ID)"),
      reversibility_class: z.enum(["reversible", "costly", "irreversible"]).optional().describe("Governance: how reversible is this action? 'reversible' = can be undone, 'costly' = reversible but expensive, 'irreversible' = cannot be undone (on-chain settlement, data deletion, sent email). When 'irreversible', confidence_level must be >= 0.95 or xproof flags a policy violation."),
    },
    async ({ file_hash, filename, decision_id, confidence_level, threshold_stage, author_name, why, who, reversibility_class }) => {
      try {
        if (!auth.valid || !auth.keyHash) {
          return { content: [{ type: "text" as const, text: JSON.stringify({ error: "UNAUTHORIZED", message: "Valid API key required. Include Authorization: Bearer pm_xxx header." }) }], isError: true };
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

        const metadata: Record<string, unknown> = {
          confidence_level,
          threshold_stage,
          decision_id,
        };
        if (why) metadata.why = why;
        if (who) metadata.who = who;
        if (reversibility_class) metadata.reversibility_class = reversibility_class;

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
          authMethod: "api_key",
          metadata,
        }).returning();

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              proof_id: certification.id,
              decision_id,
              confidence_level,
              threshold_stage,
              ...(reversibility_class ? { reversibility_class } : {}),
              status: "certified",
              file_hash: certification.fileHash,
              filename: certification.fileName,
              verify_url: `${baseUrl}/proof/${certification.id}`,
              certificate_url: `${baseUrl}/api/certificates/${certification.id}.pdf`,
              blockchain: { network: "MultiversX", transaction_hash: result.transactionHash, explorer_url: result.transactionUrl },
              timestamp: certification.createdAt?.toISOString(),
              message: `Confidence stage '${threshold_stage}' certified at ${Math.round(confidence_level * 100)}%.${reversibility_class === "irreversible" && confidence_level < 0.95 ? " WARNING: policy_violation — irreversible action certified below 0.95 confidence threshold." : ""} Use decision_id '${decision_id}' for subsequent stages.`,
            }),
          }],
        };
      } catch (error: any) {
        return { content: [{ type: "text" as const, text: JSON.stringify({ error: "CERTIFICATION_FAILED", message: error.message || "Failed to create confidence certification" }) }], isError: true };
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
              `certify_with_confidence - Staged proof with confidence score (initial/partial/pre-commitment/final) — $${currentPriceUsd}/stage`,
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
            bazaar_discovery: {
              description: "xproof endpoints are registered in the x402 Bazaar — the canonical discovery layer for x402-compatible services. AI agents with Bazaar MCP access can find, evaluate, and call xproof without reading any documentation.",
              bazaar_mcp: "GET https://api.cdp.coinbase.com/platform/v2/x402/discovery/mcp",
              search_terms: ["proof of existence", "blockchain certification", "audit trail", "decision provenance", "agent accountability", "file hash", "SHA-256 anchor"],
              discoverable_endpoints: [
                { path: "POST /api/proof", description: "Certify any content — anchor SHA-256 hash on MultiversX with 4W provenance" },
                { path: "POST /api/batch", description: "Batch certify up to 100 files in one transaction" },
                { path: "POST /api/proof (investigate)", description: "4W incident investigation — reconstruct agent decision audit trail" },
              ],
              note: "Bazaar metadata (input/output schemas, examples) is included in every 402 response from xproof. The facilitator catalogs xproof the first time it processes a payment for each endpoint.",
            },
            compatible_agents: ["Conway Terminal", "OpenClaw", "Claude Code", "Codex", "LangChain", "CrewAI", "Any MCP/x402 agent"],
          }),
        }],
      };
    }
  );

  server.tool(
    "audit_agent_session",
    `Certify an AI agent's work session on the MultiversX blockchain BEFORE executing any critical action (trade, deploy, data access). Returns a proof_id compliance certificate. The agent MUST call this tool before acting — certification failure blocks execution. Governance: set reversibility_class='irreversible' for actions that cannot be undone — a policy violation is flagged if confidence_level < 0.95 on irreversible decisions. Schema: ${baseUrl}/.well-known/agent-audit-schema.json`,
    {
      agent_id: z.string().min(1).describe("Identifier of the agent making the decision"),
      session_id: z.string().min(1).describe("Unique session identifier (UUID or timestamp-based)"),
      action_type: z.enum(["trade_execution", "code_deploy", "data_access", "content_generation", "api_call", "other"]).describe("Category of the action being certified"),
      action_description: z.string().min(1).describe("Human-readable description of the specific action"),
      inputs_hash: z.string().length(64).regex(/^[a-fA-F0-9]+$/).describe("SHA-256 of all inputs analyzed before making the decision"),
      risk_level: z.enum(["low", "medium", "high", "critical"]).describe("Assessed risk level of the action"),
      decision: z.enum(["approved", "rejected", "deferred"]).describe("Agent's decision about whether to proceed"),
      timestamp: z.string().describe("ISO 8601 timestamp of when the decision was made"),
      risk_summary: z.string().optional().describe("Optional brief risk analysis justifying the decision"),
      context: z.record(z.unknown()).optional().describe("Optional additional context (model version, environment, tool chain, etc.)"),
      reversibility_class: z.enum(["reversible", "costly", "irreversible"]).optional().describe("Governance: how reversible is this action? 'reversible' = can be undone at low cost, 'costly' = reversible but expensive (fees, slippage, delay), 'irreversible' = cannot be undone (on-chain settlement, data deletion, email sent). When 'irreversible', a confidence_level >= 0.95 is required to be policy-compliant."),
    },
    async (params) => {
      try {
        if (!auth.valid || !auth.keyHash) {
          return {
            content: [{ type: "text" as const, text: JSON.stringify({ error: "UNAUTHORIZED", message: "Valid API key required for audit_agent_session. Include Authorization: Bearer pm_xxx header." }) }],
            isError: true,
          };
        }

        const canonicalJson = JSON.stringify(params, Object.keys(params).sort());
        const fileHash = crypto.createHash("sha256").update(canonicalJson).digest("hex");
        const fileName = `audit-log-${params.session_id}.json`;

        let [systemUser] = await db.select().from(users)
          .where(eq(users.walletAddress, "erd1acp00000000000000000000000000000000000000000000000000000agent"));
        if (!systemUser) {
          [systemUser] = await db.insert(users).values({
            walletAddress: "erd1acp00000000000000000000000000000000000000000000000000000agent",
            subscriptionTier: "business",
            subscriptionStatus: "active",
          }).returning();
        }

        const result = await recordOnBlockchain(fileHash, fileName, params.agent_id);

        const [certification] = await db.insert(certifications).values({
          userId: systemUser.id!,
          fileName,
          fileHash,
          fileType: "json",
          authorName: params.agent_id,
          transactionHash: result.transactionHash,
          transactionUrl: result.transactionUrl,
          blockchainStatus: "confirmed",
          isPublic: true,
          authMethod: "api_key",
          metadata: params,
        }).returning();

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              proof_id: certification.id,
              audit_url: `${baseUrl}/audit/${certification.id}`,
              proof_url: `${baseUrl}/proof/${certification.id}`,
              blockchain: { network: "MultiversX", transaction_hash: result.transactionHash, explorer_url: result.transactionUrl },
              decision: params.decision,
              risk_level: params.risk_level,
              inputs_hash: params.inputs_hash,
              timestamp: certification.createdAt?.toISOString(),
              message: "Agent audit session certified on MultiversX blockchain. Compliance certificate is immutable and publicly verifiable.",
            }),
          }],
        };
      } catch (error: any) {
        return {
          content: [{ type: "text" as const, text: JSON.stringify({ error: "AUDIT_CERTIFICATION_FAILED", message: error.message || "Failed to certify audit session" }) }],
          isError: true,
        };
      }
    }
  );

  server.tool(
    "check_attestations",
    "Check domain-specific attestations for an AI agent wallet on xproof. Returns active attestations issued by third-party certifying bodies (healthcare, finance, legal, security, research). Each active attestation adds +50 to the agent's trust score (max +150 from 3 attestations). Use this to verify an agent's credentials before delegating a sensitive task.",
    {
      wallet: z.string().min(3).describe("MultiversX wallet address (erd1...) of the agent to check"),
    },
    async (params) => {
      try {
        const now = new Date();
        const result = await db.execute(sql`
          SELECT id, issuer_wallet, issuer_name, domain, standard, title, description, expires_at, created_at
          FROM attestations
          WHERE subject_wallet = ${params.wallet}
            AND status = 'active'
            AND (expires_at IS NULL OR expires_at > ${now})
          ORDER BY created_at DESC
        `);
        const attestations = (result as any).rows ?? [];
        const counted = Math.min(3, attestations.length);
        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              wallet: params.wallet,
              attestation_count: attestations.length,
              trust_bonus: counted * 50,
              attestations: attestations.map((a: any) => ({
                id: a.id,
                domain: a.domain,
                standard: a.standard,
                title: a.title,
                issuer_name: a.issuer_name,
                issuer_wallet: a.issuer_wallet,
                expires_at: a.expires_at,
                issued_at: a.created_at,
                attestation_url: `${baseUrl}/attestation/${a.id}`,
              })),
              profile_url: `${baseUrl}/agent/${params.wallet}`,
              trust_url: `${baseUrl}/api/trust/${params.wallet}`,
            }),
          }],
        };
      } catch (error: any) {
        return {
          content: [{ type: "text" as const, text: JSON.stringify({ error: "CHECK_ATTESTATIONS_FAILED", message: error.message }) }],
          isError: true,
        };
      }
    }
  );

  server.tool(
    "investigate_proof",
    "Reconstruct the full 4W audit trail for a contested agent action. Returns WHO (agent identity + SIGIL), WHAT (SHA-256 hash on-chain), WHEN (MultiversX block timestamp), WHY (decision chain anchored before acting). Includes verification summary with intent_preceded_execution flag, chronological timeline of WHY/WHAT proofs, and session heartbeat anchor. Requires x402 payment ($0.05 USDC on Base via X-PAYMENT header) or API key authentication. Without payment, returns payment requirements with USDC address and amount.",
    {
      proof_id: z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i).describe("UUID of any proof in the action pair — WHY (reasoning), WHAT (action), or heartbeat session proof"),
      wallet: z.string().min(3).describe("Agent wallet address (erd1...) that owns the proof"),
    },
    async ({ proof_id, wallet }) => {
      try {
        if (!auth.valid) {
          if (isX402Configured()) {
            if (xPaymentHeader) {
              const x402Result = await verifyX402PaymentRaw(xPaymentHeader, host, "investigate");
              if (!x402Result.valid) {
                return {
                  content: [{ type: "text" as const, text: JSON.stringify({ error: "PAYMENT_FAILED", message: x402Result.error, incident_report_url: `${baseUrl}/incident/${wallet}/${proof_id}` }) }],
                  isError: true,
                };
              }
            } else {
              const paymentInfo = await getInvestigatePaymentRequirements(host);
              return {
                content: [{ type: "text" as const, text: JSON.stringify({
                  error: "PAYMENT_REQUIRED",
                  message: "x402 payment required for investigate_proof. Include X-PAYMENT header with USDC payment on Base.",
                  payment_requirements: paymentInfo,
                  incident_report_url: `${baseUrl}/incident/${wallet}/${proof_id}`,
                  hint: "Include the x-payment header in your MCP POST request to /mcp. Payment is $0.05 USDC on Base (EIP-155:8453).",
                }) }],
                isError: true,
              };
            }
          } else {
            return {
              content: [{ type: "text" as const, text: JSON.stringify({ error: "UNAUTHORIZED", message: "API key required. Include Authorization: Bearer pm_xxx header.", incident_report_url: `${baseUrl}/incident/${wallet}/${proof_id}` }) }],
              isError: true,
            };
          }
        }

        const result = await reconstructAuditTrail(wallet, proof_id);

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify(result),
          }],
        };
      } catch (error: any) {
        const message = error.error || error.message || "Failed to reconstruct audit trail";
        return {
          content: [{ type: "text" as const, text: JSON.stringify({ error: "INVESTIGATION_FAILED", message, incident_report_url: `${baseUrl}/incident/${wallet}/${proof_id}` }) }],
          isError: true,
        };
      }
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
