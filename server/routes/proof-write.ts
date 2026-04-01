import { type Express } from "express";
import crypto from "crypto";
import { db, pool } from "../db";
import { logger } from "../logger";
import { certifications, users, apiKeys } from "@shared/schema";
import { eq, desc, sql, and, count, type SQL } from "drizzle-orm";
import { z } from "zod";
import { paymentRateLimiter, publicSearchRateLimiter } from "../reliability";
import { isX402Configured, verifyX402Payment, send402Response } from "../x402";
import { recordOnBlockchain, isMultiversXConfigured } from "../blockchain";
import { getCertificationPriceEgld, getCertificationPriceUsd } from "../pricing";
import { auditLogSchema, AUDIT_LOG_JSON_SCHEMA, type AgentAuditLog } from "../auditSchema";
import { isMX8004Configured, recordCertificationAsJob } from "../mx8004";
import { checkRateLimit, isAdminWallet, getTrialUser, consumeTrialCredit, getUserCreditBalance, consumeCredit, getApiKeyOwnerWallet, TRIAL_QUOTA, RATE_LIMIT_MAX_VALUE, buildCanonicalId } from "./helpers";

export function registerProofWriteRoutes(app: Express) {
  // ============================================
  // Metadata search endpoint
  // Search certifications by metadata fields (model_hash, strategy_hash, version_number, etc.)
  // ============================================
  app.get("/api/proofs/search", publicSearchRateLimiter, async (req, res) => {
    try {
      const { model_hash, strategy_hash, version_number, key, value, wallet, limit: limitStr, offset: offsetStr } = req.query;
      const limit = Math.min(parseInt(limitStr as string) || 20, 100);
      const offset = Math.max(parseInt(offsetStr as string) || 0, 0);

      const sqlConditions: SQL[] = [];

      if (model_hash) {
        sqlConditions.push(sql`${certifications.metadata}->>'model_hash' = ${String(model_hash)}`);
      }
      if (strategy_hash) {
        sqlConditions.push(sql`${certifications.metadata}->>'strategy_hash' = ${String(strategy_hash)}`);
      }
      if (version_number) {
        sqlConditions.push(sql`${certifications.metadata}->>'version_number' = ${String(version_number)}`);
      }
      if (key && value) {
        sqlConditions.push(sql`${certifications.metadata}->>${ String(key)} = ${String(value)}`);
      }
      if (wallet) {
        sqlConditions.push(eq(users.walletAddress, String(wallet)));
      }

      const hasMetadataFilter = !!(model_hash || strategy_hash || version_number || (key && value));

      if (sqlConditions.length === 0) {
        return res.status(400).json({
          error: "MISSING_FILTER",
          message: "Provide at least one search parameter: model_hash, strategy_hash, version_number, key+value, or wallet",
        });
      }

      if (hasMetadataFilter) {
        sqlConditions.push(sql`${certifications.metadata} IS NOT NULL`);
      }

      const whereClause = and(...sqlConditions);

      const countResult = await db
        .select({ total: sql<number>`count(*)::int` })
        .from(certifications)
        .leftJoin(users, eq(certifications.userId, users.id))
        .where(whereClause!);

      const total = countResult[0]?.total || 0;

      const rows = await db
        .select({
          id: certifications.id,
          fileName: certifications.fileName,
          fileHash: certifications.fileHash,
          metadata: certifications.metadata,
          blockchainStatus: certifications.blockchainStatus,
          transactionHash: certifications.transactionHash,
          createdAt: certifications.createdAt,
          walletAddress: users.walletAddress,
        })
        .from(certifications)
        .leftJoin(users, eq(certifications.userId, users.id))
        .where(whereClause!)
        .orderBy(sql`${certifications.createdAt} DESC`)
        .limit(limit)
        .offset(offset);

      const baseUrl = `https://${req.get("host")}`;

      return res.json({
        results: rows.map((r: any) => ({
          proof_id: r.id,
          file_hash: r.file_hash || r.fileHash,
          filename: r.file_name || r.fileName,
          metadata: r.metadata,
          blockchain_status: r.blockchain_status || r.blockchainStatus,
          transaction_hash: r.transaction_hash || r.transactionHash,
          wallet_address: r.wallet_address || null,
          verify_url: `${baseUrl}/proof/${r.id}`,
          created_at: r.created_at || r.createdAt,
        })),
        total,
        limit,
        offset,
      });
    } catch (error) {
      logger.error("Proof search failed", { error: (error as Error).message });
      return res.status(500).json({ error: "INTERNAL_ERROR", message: "Search failed" });
    }
  });

  // ============================================
  // Simplified POST /api/proof endpoint for AI agents
  // Single-call certification: validate API key, record on blockchain, return proof
  // ============================================
  const VALID_THRESHOLD_STAGES = ["initial", "partial", "pre-commitment", "final"] as const;

  const proofRequestSchema = z.object({
    file_hash: z.string().length(64, "SHA-256 hash must be exactly 64 hex characters").regex(/^[a-fA-F0-9]+$/, "Must be a valid hex string"),
    filename: z.string().min(1, "Filename is required"),
    author_name: z.string().optional(),
    webhook_url: z.string().url("Must be a valid URL").refine((url) => !url || url.startsWith("https://"), { message: "Webhook URL must use HTTPS" }).optional(),
    metadata: z.record(z.any()).optional(),
  }).refine((data) => {
    if (!data.metadata) return true;
    const m = data.metadata;
    if (m.confidence_level !== undefined) {
      const cl = Number(m.confidence_level);
      if (isNaN(cl) || cl < 0 || cl > 1) return false;
    }
    return true;
  }, { message: "metadata.confidence_level must be a number between 0.0 and 1.0", path: ["metadata", "confidence_level"] })
  .refine((data) => {
    if (!data.metadata) return true;
    const m = data.metadata;
    if (m.threshold_stage !== undefined) {
      if (typeof m.threshold_stage !== "string" || !VALID_THRESHOLD_STAGES.includes(m.threshold_stage as any)) return false;
    }
    return true;
  }, { message: `metadata.threshold_stage must be one of: ${VALID_THRESHOLD_STAGES.join(", ")}`, path: ["metadata", "threshold_stage"] })
  .refine((data) => {
    if (!data.metadata) return true;
    const m = data.metadata;
    if (m.decision_id !== undefined) {
      if (typeof m.decision_id !== "string" || m.decision_id.trim().length === 0) return false;
    }
    return true;
  }, { message: "metadata.decision_id must be a non-empty string", path: ["metadata", "decision_id"] })
  .refine((data) => {
    if (!data.metadata) return true;
    const m = data.metadata;
    if (m.confidence_level !== undefined && m.decision_id === undefined) return false;
    return true;
  }, { message: "metadata.decision_id is required when using confidence_level anchoring", path: ["metadata", "decision_id"] })
  .refine((data) => {
    if (!data.metadata) return true;
    const m = data.metadata;
    if (m.confidence_level !== undefined && m.threshold_stage === undefined) return false;
    return true;
  }, { message: "metadata.threshold_stage is required when using confidence_level anchoring", path: ["metadata", "threshold_stage"] });

  app.post("/api/proof", paymentRateLimiter, async (req, res) => {
    try {
      let authMethod: "api_key" | "x402" = "api_key";
      let isAdminExempt = false;
      const authHeader = req.headers.authorization;
      const hasBearerToken = authHeader && authHeader.startsWith("Bearer ");
      const hasX402Payment = !!req.headers["x-payment"];

      let trialInfo: { isTrial: boolean; remaining: number; userId: string } | null = null;
      let creditInfo: { userId: string; balance: number } | null = null;
      let apiKeyUserId: string | null = null;

      if (hasBearerToken) {
        const rawKey = authHeader!.slice(7);

        if (!rawKey.startsWith("pm_")) {
          return res.status(401).json({
            error: "INVALID_API_KEY",
            message: "API key must start with 'pm_' prefix",
          });
        }

        const keyHash = crypto.createHash("sha256").update(rawKey).digest("hex");

        const [apiKey] = await db.select().from(apiKeys).where(eq(apiKeys.keyHash, keyHash));

        if (!apiKey) {
          return res.status(401).json({
            error: "INVALID_API_KEY",
            message: "Invalid or expired API key",
          });
        }

        if (!apiKey.isActive) {
          return res.status(403).json({
            error: "API_KEY_DISABLED",
            message: "This API key has been disabled",
          });
        }

        apiKeyUserId = apiKey.userId || null;

        const rateLimit = checkRateLimit(apiKey.id);
        res.setHeader("X-RateLimit-Limit", RATE_LIMIT_MAX_VALUE.toString());
        res.setHeader("X-RateLimit-Remaining", rateLimit.remaining.toString());
        res.setHeader("X-RateLimit-Reset", Math.floor(rateLimit.resetAt / 1000).toString());

        if (!rateLimit.allowed) {
          return res.status(429).json({
            error: "RATE_LIMIT_EXCEEDED",
            message: "Too many requests. Please slow down.",
            retry_after: Math.ceil((rateLimit.resetAt - Date.now()) / 1000),
          });
        }

        db.update(apiKeys)
          .set({
            lastUsedAt: new Date(),
            requestCount: (apiKey.requestCount || 0) + 1,
          })
          .where(eq(apiKeys.id, apiKey.id))
          .execute()
          .catch((err) => logger.error("Failed to update API key stats", { error: err.message }));

        authMethod = "api_key";

        trialInfo = await getTrialUser(apiKey);
        if (trialInfo) {
          if (trialInfo.remaining <= 0) {
            // Trial exhausted — check if user has prepaid credits
            const balance = apiKey.userId ? await getUserCreditBalance(apiKey.userId) : 0;
            if (balance > 0 && apiKey.userId) {
              creditInfo = { userId: apiKey.userId, balance };
              trialInfo = null; // Use credits instead of trial
            } else {
              const baseUrl = `https://${req.get("host")}`;
              return res.status(402).json({
                error: "TRIAL_EXHAUSTED",
                message: `Trial quota exhausted (${TRIAL_QUOTA}/${TRIAL_QUOTA} used). Purchase prepaid credits or pay per request via x402.`,
                trial: { quota: TRIAL_QUOTA, used: TRIAL_QUOTA, remaining: 0 },
                upgrade: {
                  credits: `POST ${baseUrl}/api/credits/purchase — prepaid packs (100/$5, 1000/$40, 10k/$300 USDC on Base)`,
                  x402: "Send POST /api/proof without auth header to pay per request via x402 (USDC on Base)",
                  acp: "Use POST /api/acp/checkout for EGLD payment on MultiversX",
                },
              });
            }
          }
        } else {
          const ownerWallet = await getApiKeyOwnerWallet(apiKey);
          if (ownerWallet && isAdminWallet(ownerWallet)) {
            isAdminExempt = true;
            logger.withRequest(req).info("Admin wallet exempt from payment", { walletAddress: ownerWallet });
          }
        }
      } else if (hasX402Payment && isX402Configured()) {
        const x402Result = await verifyX402Payment(req, "proof");
        if (!x402Result.valid) {
          return res.status(402).json({
            error: "PAYMENT_FAILED",
            message: x402Result.error || "x402 payment verification failed",
          });
        }
        authMethod = "x402";
        res.setHeader("X-Payment-Method", "x402");
      } else if (isX402Configured()) {
        return await send402Response(res, req, "proof");
      } else {
        const baseUrl = `https://${req.get('host')}`;
        return res.status(401).json({
          error: "AUTH_REQUIRED",
          message: "Authentication required to certify files.",
          options: [
            { type: "free_trial", method: "POST", url: `${baseUrl}/api/agent/register`, body: { agent_name: "your-agent-name" }, free_certifications: TRIAL_QUOTA, description: `${TRIAL_QUOTA} free certifications, no wallet needed` },
            { type: "api_key", header: "Authorization: Bearer pm_xxx", description: "Use an existing API key" },
            { type: "x402", price: "$0.05", network: "Base (USDC)", description: "Pay per use, no account needed" },
          ],
        });
      }

      const data = proofRequestSchema.parse(req.body);
      const baseUrl = `https://${req.get('host')}`;

      const [existing] = await db
        .select()
        .from(certifications)
        .where(eq(certifications.fileHash, data.file_hash));

      if (existing) {
        logger.withRequest(req).info("File already certified", { fileHash: data.file_hash, certificationId: existing.id });
        return res.status(200).json({
          proof_id: existing.id,
          status: "certified",
          file_hash: existing.fileHash,
          filename: existing.fileName,
          metadata: existing.metadata || null,
          verify_url: `${baseUrl}/proof/${existing.id}`,
          certificate_url: `${baseUrl}/api/certificates/${existing.id}.pdf`,
          proof_json_url: `${baseUrl}/proof/${existing.id}.json`,
          blockchain: {
            network: "MultiversX",
            transaction_hash: existing.transactionHash,
            explorer_url: existing.transactionUrl,
          },
          timestamp: existing.createdAt?.toISOString() || new Date().toISOString(),
          webhook_status: "not_applicable",
          message: "File already certified on MultiversX blockchain. Proof is immutable and publicly verifiable.",
        });
      }

      const result = await recordOnBlockchain(data.file_hash, data.filename, data.author_name || "AI Agent");

      const certUserId = trialInfo ? trialInfo.userId : (creditInfo ? creditInfo.userId : apiKeyUserId);
      let ownerUserId = certUserId;

      if (!ownerUserId) {
        let [systemUser] = await db
          .select()
          .from(users)
          .where(eq(users.walletAddress, "erd1acp00000000000000000000000000000000000000000000000000000agent"));

        if (!systemUser) {
          [systemUser] = await db
            .insert(users)
            .values({
              walletAddress: "erd1acp00000000000000000000000000000000000000000000000000000agent",
              subscriptionTier: "business",
              subscriptionStatus: "active",
            })
            .returning();
        }
        ownerUserId = systemUser.id!;
      }

      if (trialInfo) {
        await consumeTrialCredit(trialInfo.userId);
      } else if (creditInfo) {
        await consumeCredit(creditInfo.userId);
      }

      const [certification] = await db
        .insert(certifications)
        .values({
          userId: ownerUserId,
          fileName: data.filename,
          fileHash: data.file_hash,
          fileType: data.filename.split(".").pop() || "unknown",
          authorName: data.author_name || "AI Agent",
          transactionHash: result.transactionHash,
          transactionUrl: result.transactionUrl,
          blockchainStatus: "confirmed",
          isPublic: true,
          authMethod,
          ...(result.latencyMs != null ? { blockchainLatencyMs: result.latencyMs } : {}),
          ...(data.metadata ? { metadata: data.metadata } : {}),
        })
        .returning();

      logger.withRequest(req).info("File certified", { fileHash: data.file_hash, certificationId: certification.id, txHash: result.transactionHash, authMethod, adminExempt: isAdminExempt });

      recordCertificationAsJob(
        certification.id.toString(),
        data.file_hash,
        result.transactionHash
      ).catch((err) => logger.error("Background job registration failed", { component: "mx8004", error: err.message }));

      let webhookStatus: string = data.webhook_url ? "pending" : "not_requested";
      
      if (data.webhook_url) {
        const { scheduleWebhookDelivery, isValidWebhookUrl } = await import("../webhook");
        if (isValidWebhookUrl(data.webhook_url)) {
          await db.update(certifications)
            .set({ webhookUrl: data.webhook_url, webhookStatus: "pending" })
            .where(eq(certifications.id, certification.id));
          
          const webhookSecret = authMethod === "api_key" ? authHeader!.slice(7) : (process.env.SESSION_SECRET || "xproof-x402");
          scheduleWebhookDelivery(certification.id, data.webhook_url, baseUrl, webhookSecret);
        } else {
          webhookStatus = "failed";
          await db.update(certifications)
            .set({ webhookUrl: data.webhook_url, webhookStatus: "failed" })
            .where(eq(certifications.id, certification.id));
        }
      }

      if (trialInfo) {
        res.setHeader("X-Trial-Remaining", Math.max(0, trialInfo.remaining - 1).toString());
      }
      if (creditInfo) {
        const newBalance = Math.max(0, creditInfo.balance - 1);
        res.setHeader("X-Credits-Remaining", newBalance.toString());
      }

      return res.status(201).json({
        proof_id: certification.id,
        status: "certified",
        file_hash: certification.fileHash,
        filename: certification.fileName,
        metadata: certification.metadata || null,
        verify_url: `${baseUrl}/proof/${certification.id}`,
        certificate_url: `${baseUrl}/api/certificates/${certification.id}.pdf`,
        proof_json_url: `${baseUrl}/proof/${certification.id}.json`,
        blockchain: {
          network: "MultiversX",
          transaction_hash: result.transactionHash,
          explorer_url: result.transactionUrl,
        },
        timestamp: certification.createdAt?.toISOString() || new Date().toISOString(),
        webhook_status: webhookStatus,
        ...(trialInfo ? { trial: { remaining: Math.max(0, trialInfo.remaining - 1) } } : {}),
        ...(creditInfo ? { credits: { remaining: Math.max(0, creditInfo.balance - 1) } } : {}),
        message: "File certified on MultiversX blockchain. Proof is immutable and publicly verifiable.",
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({
          error: "VALIDATION_ERROR",
          message: "Invalid request data",
          details: error.errors,
        });
      }
      logger.withRequest(req).error("Proof creation failed");
      return res.status(500).json({
        error: "INTERNAL_ERROR",
        message: "Failed to create certification. Please try again.",
      });
    }
  });

  // ============================================
  // Agent Audit Log Endpoint
  // Certify an agent's session of work before
  // executing a critical action (trade, deploy, etc.)
  // ============================================
  app.post("/api/audit", paymentRateLimiter, async (req, res) => {
    try {
      const baseUrl = `https://${req.get("host")}`;
      let authMethod: "api_key" | "x402" = "api_key";
      let isAdminExempt = false;
      const authHeader = req.headers.authorization;
      const hasBearerToken = authHeader && authHeader.startsWith("Bearer ");
      const hasX402Payment = !!req.headers["x-payment"];

      let trialInfo: { isTrial: boolean; remaining: number; userId: string } | null = null;
      let creditInfo: { userId: string; balance: number } | null = null;
      let ownerUserId: string | null = null;

      if (hasBearerToken) {
        const rawKey = authHeader!.slice(7);
        if (!rawKey.startsWith("pm_")) {
          return res.status(401).json({ error: "INVALID_API_KEY", message: "API key must start with 'pm_'" });
        }
        const keyHash = crypto.createHash("sha256").update(rawKey).digest("hex");
        const [apiKey] = await db.select().from(apiKeys).where(eq(apiKeys.keyHash, keyHash));
        if (!apiKey) return res.status(401).json({ error: "INVALID_API_KEY", message: "Invalid or expired API key" });
        if (!apiKey.isActive) return res.status(403).json({ error: "API_KEY_DISABLED", message: "This API key has been disabled" });

        const rateLimit = checkRateLimit(apiKey.id);
        res.setHeader("X-RateLimit-Limit", RATE_LIMIT_MAX_VALUE.toString());
        res.setHeader("X-RateLimit-Remaining", rateLimit.remaining.toString());
        res.setHeader("X-RateLimit-Reset", Math.floor(rateLimit.resetAt / 1000).toString());
        if (!rateLimit.allowed) {
          return res.status(429).json({ error: "RATE_LIMIT_EXCEEDED", message: "Too many requests.", retry_after: Math.ceil((rateLimit.resetAt - Date.now()) / 1000) });
        }

        db.update(apiKeys).set({ lastUsedAt: new Date(), requestCount: (apiKey.requestCount || 0) + 1 }).where(eq(apiKeys.id, apiKey.id)).execute().catch(() => {});
        authMethod = "api_key";

        trialInfo = await getTrialUser(apiKey);
        if (trialInfo) {
          if (trialInfo.remaining <= 0) {
            const balance = apiKey.userId ? await getUserCreditBalance(apiKey.userId) : 0;
            if (balance > 0 && apiKey.userId) {
              creditInfo = { userId: apiKey.userId, balance };
              trialInfo = null;
            } else {
              return res.status(402).json({
                error: "TRIAL_EXHAUSTED",
                message: `Trial quota exhausted (${TRIAL_QUOTA}/${TRIAL_QUOTA} used). Purchase prepaid credits or pay per request via x402.`,
                trial: { quota: TRIAL_QUOTA, used: TRIAL_QUOTA, remaining: 0 },
                upgrade: {
                  credits: `POST ${baseUrl}/api/credits/purchase — prepaid packs (100/$5, 1000/$40, 10k/$300 USDC on Base)`,
                  x402: "Send POST /api/audit without auth header to pay per request via x402 (USDC on Base)",
                },
              });
            }
          }
        } else {
          const ownerWallet = await getApiKeyOwnerWallet(apiKey);
          if (ownerWallet && isAdminWallet(ownerWallet)) {
            isAdminExempt = true;
          }
        }
        if (apiKey.userId) ownerUserId = apiKey.userId;
      } else if (hasX402Payment && isX402Configured()) {
        const x402Result = await verifyX402Payment(req, "proof");
        if (!x402Result.valid) {
          return res.status(402).json({ error: "PAYMENT_FAILED", message: x402Result.error || "Payment verification failed" });
        }
        authMethod = "x402";
      } else if (!isAdminExempt) {
        if (isX402Configured()) {
          return send402Response(res, req, "proof");
        }
        return res.status(402).json({
          error: "PAYMENT_REQUIRED",
          message: "Provide Authorization: Bearer pm_xxx (API key) or x402 payment header",
          options: [
            { method: "api_key", description: "Bearer token", how: "POST /api/agent/register for a free trial key" },
            { method: "x402", description: "Per-request USDC payment on Base", how: "Include x-payment header" },
          ],
        });
      }

      // Parse + validate audit log
      const data = auditLogSchema.parse(req.body);

      // Compute canonical hash (sorted keys, deterministic)
      const canonicalJson = JSON.stringify(data, Object.keys(data).sort());
      const fileHash = crypto.createHash("sha256").update(canonicalJson).digest("hex");
      const fileName = `audit-log-${data.session_id}.json`;

      // Check duplicate (same audit log already certified)
      const [existing] = await db.select().from(certifications).where(eq(certifications.fileHash, fileHash));
      if (existing) {
        return res.status(200).json({
          status: "already_certified",
          proof_id: existing.id,
          audit_url: `${baseUrl}/audit/${existing.id}`,
          proof_url: `${baseUrl}/proof/${existing.id}`,
          file_hash: fileHash,
          message: "This exact audit log was already certified. Returning existing proof.",
        });
      }

      if (!isMultiversXConfigured()) {
        return res.status(503).json({ error: "BLOCKCHAIN_UNAVAILABLE", message: "MultiversX is not configured on this server." });
      }

      // Record on blockchain
      const result = await recordOnBlockchain(fileHash, fileName);
      if (!result.success) {
        return res.status(502).json({ error: "BLOCKCHAIN_ERROR", message: result.error || "Failed to record on blockchain" });
      }

      // Consume auth credit
      if (trialInfo) {
        await consumeTrialCredit(trialInfo.userId);
      } else if (creditInfo) {
        await consumeCredit(creditInfo.userId);
      }

      if (!ownerUserId) {
        let [systemUser] = await db
          .select()
          .from(users)
          .where(eq(users.walletAddress, "erd1acp00000000000000000000000000000000000000000000000000000agent"));
        if (!systemUser) {
          [systemUser] = await db
            .insert(users)
            .values({
              walletAddress: "erd1acp00000000000000000000000000000000000000000000000000000agent",
              subscriptionTier: "business",
              subscriptionStatus: "active",
            })
            .returning();
        }
        ownerUserId = systemUser.id!;
      }

      // Store certification with full audit log in metadata
      const [certification] = await db
        .insert(certifications)
        .values({
          userId: ownerUserId,
          fileName,
          fileHash,
          fileType: "json",
          authorName: data.agent_id,
          transactionHash: result.transactionHash,
          transactionUrl: result.transactionUrl,
          blockchainStatus: "confirmed",
          isPublic: true,
          authMethod,
          metadata: data as Record<string, any>,
          ...(result.latencyMs != null ? { blockchainLatencyMs: result.latencyMs } : {}),
        })
        .returning();

      logger.withRequest(req).info("Agent audit log certified", {
        certificationId: certification.id,
        agentId: data.agent_id,
        sessionId: data.session_id,
        actionType: data.action_type,
        decision: data.decision,
        riskLevel: data.risk_level,
        txHash: result.transactionHash,
        authMethod,
      });

      if (trialInfo) res.setHeader("X-Trial-Remaining", Math.max(0, trialInfo.remaining - 1).toString());
      if (creditInfo) res.setHeader("X-Credits-Remaining", Math.max(0, creditInfo.balance - 1).toString());

      return res.status(201).json({
        proof_id: certification.id,
        audit_url: `${baseUrl}/audit/${certification.id}`,
        proof_url: `${baseUrl}/proof/${certification.id}`,
        status: "certified",
        decision: data.decision,
        risk_level: data.risk_level,
        action_type: data.action_type,
        agent_id: data.agent_id,
        session_id: data.session_id,
        inputs_hash: data.inputs_hash,
        ...(data.inputs_manifest ? { inputs_manifest: data.inputs_manifest } : {}),
        file_hash: fileHash,
        blockchain: {
          network: "MultiversX",
          transaction_hash: result.transactionHash,
          explorer_url: result.transactionUrl,
        },
        timestamp: certification.createdAt?.toISOString() || new Date().toISOString(),
        ...(trialInfo ? { trial: { remaining: Math.max(0, trialInfo.remaining - 1) } } : {}),
        ...(creditInfo ? { credits: { remaining: Math.max(0, creditInfo.balance - 1) } } : {}),
        message: `Agent audit log certified on MultiversX. The proof_id is your compliance certificate — the agent was authorized to ${data.action_type} with decision: ${data.decision}.`,
        schema: `${baseUrl}/.well-known/agent-audit-schema.json`,
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({
          error: "VALIDATION_ERROR",
          message: "Invalid audit log data",
          details: error.errors,
          schema: `https://${req.get("host")}/.well-known/agent-audit-schema.json`,
        });
      }
      logger.withRequest(req).error("Audit log certification failed");
      return res.status(500).json({ error: "INTERNAL_ERROR", message: "Failed to certify audit log." });
    }
  });

  // ============================================
  // Batch Certification Endpoint
  // Certify multiple files in a single API call
  // ============================================
  const batchRequestSchema = z.object({
    files: z.array(z.object({
      file_hash: z.string().length(64, "SHA-256 hash must be exactly 64 hex characters").regex(/^[a-fA-F0-9]+$/, "Must be a valid hex string"),
      filename: z.string().min(1, "Filename is required"),
      metadata: z.record(z.any()).optional(),
    })).min(1, "At least one file is required").max(50, "Maximum 50 files per batch"),
    author_name: z.string().optional(),
    webhook_url: z.string().url("Must be a valid URL").refine((url) => !url || url.startsWith("https://"), { message: "Webhook URL must use HTTPS" }).optional(),
  });

  app.post("/api/batch", paymentRateLimiter, async (req, res) => {
    try {
      let authMethod: "api_key" | "x402" = "api_key";
      let isAdminExempt = false;
      const authHeader = req.headers.authorization;
      const hasBearerToken = authHeader && authHeader.startsWith("Bearer ");
      const hasX402Payment = !!req.headers["x-payment"];

      let trialInfo: { isTrial: boolean; remaining: number; userId: string } | null = null;
      let creditInfo: { userId: string; balance: number } | null = null;
      let apiKeyUserId: string | null = null;

      if (hasBearerToken) {
        const rawKey = authHeader!.slice(7);

        if (!rawKey.startsWith("pm_")) {
          return res.status(401).json({
            error: "INVALID_API_KEY",
            message: "API key must start with 'pm_' prefix",
          });
        }

        const keyHash = crypto.createHash("sha256").update(rawKey).digest("hex");

        const [apiKey] = await db.select().from(apiKeys).where(eq(apiKeys.keyHash, keyHash));

        if (!apiKey) {
          return res.status(401).json({
            error: "INVALID_API_KEY",
            message: "Invalid or expired API key",
          });
        }

        if (!apiKey.isActive) {
          return res.status(403).json({
            error: "API_KEY_DISABLED",
            message: "This API key has been disabled",
          });
        }

        apiKeyUserId = apiKey.userId || null;

        const rateLimit = checkRateLimit(apiKey.id);
        res.setHeader("X-RateLimit-Limit", RATE_LIMIT_MAX_VALUE.toString());
        res.setHeader("X-RateLimit-Remaining", rateLimit.remaining.toString());
        res.setHeader("X-RateLimit-Reset", Math.floor(rateLimit.resetAt / 1000).toString());

        if (!rateLimit.allowed) {
          return res.status(429).json({
            error: "RATE_LIMIT_EXCEEDED",
            message: "Too many requests. Please slow down.",
            retry_after: Math.ceil((rateLimit.resetAt - Date.now()) / 1000),
          });
        }

        db.update(apiKeys)
          .set({
            lastUsedAt: new Date(),
            requestCount: (apiKey.requestCount || 0) + 1,
          })
          .where(eq(apiKeys.id, apiKey.id))
          .execute()
          .catch((err) => logger.error("Failed to update API key stats", { error: err.message }));

        authMethod = "api_key";

        trialInfo = await getTrialUser(apiKey);
        if (trialInfo) {
          if (trialInfo.remaining <= 0) {
            // Trial exhausted — check if user has prepaid credits
            const balance = apiKey.userId ? await getUserCreditBalance(apiKey.userId) : 0;
            if (balance > 0 && apiKey.userId) {
              creditInfo = { userId: apiKey.userId, balance };
              trialInfo = null; // Use credits instead of trial
            } else {
              const baseUrl = `https://${req.get("host")}`;
              return res.status(402).json({
                error: "TRIAL_EXHAUSTED",
                message: `Trial quota exhausted (${TRIAL_QUOTA}/${TRIAL_QUOTA} used). Purchase prepaid credits or pay per request via x402.`,
                trial: { quota: TRIAL_QUOTA, used: TRIAL_QUOTA, remaining: 0 },
                upgrade: {
                  credits: `POST ${baseUrl}/api/credits/purchase — prepaid packs (100/$5, 1000/$40, 10k/$300 USDC on Base)`,
                  x402: "Send POST /api/batch without auth header to pay per request via x402 (USDC on Base)",
                  acp: "Use POST /api/acp/checkout for EGLD payment on MultiversX",
                },
              });
            }
          }
        } else {
          const ownerWallet = await getApiKeyOwnerWallet(apiKey);
          if (ownerWallet && isAdminWallet(ownerWallet)) {
            isAdminExempt = true;
            logger.withRequest(req).info("Admin wallet exempt from payment (batch)", { walletAddress: ownerWallet });
          }
        }
      } else if (hasX402Payment && isX402Configured()) {
        const x402Result = await verifyX402Payment(req, "batch");
        if (!x402Result.valid) {
          return res.status(402).json({
            error: "PAYMENT_FAILED",
            message: x402Result.error || "x402 payment verification failed",
          });
        }
        authMethod = "x402";
        res.setHeader("X-Payment-Method", "x402");
      } else if (isX402Configured()) {
        return await send402Response(res, req, "batch");
      } else {
        const baseUrl = `https://${req.get('host')}`;
        return res.status(401).json({
          error: "AUTH_REQUIRED",
          message: "Authentication required to certify files.",
          options: [
            { type: "free_trial", method: "POST", url: `${baseUrl}/api/agent/register`, body: { agent_name: "your-agent-name" }, free_certifications: TRIAL_QUOTA, description: `${TRIAL_QUOTA} free certifications, no wallet needed` },
            { type: "api_key", header: "Authorization: Bearer pm_xxx", description: "Use an existing API key" },
            { type: "x402", price: "$0.05", network: "Base (USDC)", description: "Pay per use, no account needed" },
          ],
        });
      }

      const data = batchRequestSchema.parse(req.body);
      const baseUrl = `https://${req.get('host')}`;
      const batchId = crypto.randomUUID();

      const certUserId = trialInfo ? trialInfo.userId : (creditInfo ? creditInfo.userId : apiKeyUserId);
      let ownerUserId = certUserId;

      if (!ownerUserId) {
        let [systemUser] = await db
          .select()
          .from(users)
          .where(eq(users.walletAddress, "erd1acp00000000000000000000000000000000000000000000000000000agent"));

        if (!systemUser) {
          [systemUser] = await db
            .insert(users)
            .values({
              walletAddress: "erd1acp00000000000000000000000000000000000000000000000000000agent",
              subscriptionTier: "business",
              subscriptionStatus: "active",
            })
            .returning();
        }
        ownerUserId = systemUser.id!;
      }

      const results: any[] = [];
      let createdCount = 0;
      let existingCount = 0;

      for (const file of data.files) {
        if (trialInfo && trialInfo.remaining - createdCount <= 0) {
          results.push({
            file_hash: file.file_hash,
            filename: file.filename,
            status: "skipped",
            reason: "Trial quota exhausted",
          });
          continue;
        }

        const [existing] = await db
          .select()
          .from(certifications)
          .where(eq(certifications.fileHash, file.file_hash));

        if (existing) {
          existingCount++;
          results.push({
            file_hash: existing.fileHash,
            filename: existing.fileName,
            proof_id: existing.id,
            verify_url: `${baseUrl}/proof/${existing.id}`,
            badge_url: `${baseUrl}/badge/${existing.id}`,
            status: "existing",
          });
          continue;
        }

        const result = await recordOnBlockchain(file.file_hash, file.filename, data.author_name || "AI Agent");

        const [certification] = await db
          .insert(certifications)
          .values({
            userId: ownerUserId!,
            fileName: file.filename,
            fileHash: file.file_hash,
            fileType: file.filename.split(".").pop() || "unknown",
            authorName: data.author_name || "AI Agent",
            transactionHash: result.transactionHash,
            transactionUrl: result.transactionUrl,
            blockchainStatus: "confirmed",
            isPublic: true,
            authMethod,
            ...(result.latencyMs != null ? { blockchainLatencyMs: result.latencyMs } : {}),
            ...(file.metadata ? { metadata: file.metadata } : {}),
          })
          .returning();

        createdCount++;
        results.push({
          file_hash: certification.fileHash,
          filename: certification.fileName,
          metadata: certification.metadata || null,
          proof_id: certification.id,
          verify_url: `${baseUrl}/proof/${certification.id}`,
          badge_url: `${baseUrl}/badge/${certification.id}`,
          status: "created",
        });

        recordCertificationAsJob(
          certification.id.toString(),
          file.file_hash,
          result.transactionHash
        ).catch((err) => logger.error("Background job registration failed", { component: "mx8004", error: err.message }));

        if (data.webhook_url) {
          const { scheduleWebhookDelivery, isValidWebhookUrl } = await import("../webhook");
          if (isValidWebhookUrl(data.webhook_url)) {
            await db.update(certifications)
              .set({ webhookUrl: data.webhook_url, webhookStatus: "pending" })
              .where(eq(certifications.id, certification.id));
            const batchWebhookSecret = authMethod === "api_key" ? authHeader!.slice(7) : (process.env.SESSION_SECRET || "xproof-x402");
            scheduleWebhookDelivery(certification.id, data.webhook_url, baseUrl, batchWebhookSecret);
          }
        }
      }

      if (trialInfo && createdCount > 0) {
        await consumeTrialCredit(trialInfo.userId, createdCount);
      } else if (creditInfo && createdCount > 0) {
        await consumeCredit(creditInfo.userId, createdCount);
      }

      logger.withRequest(req).info("Batch certification completed", { batchId, created: createdCount, existing: existingCount, total: data.files.length, authMethod, adminExempt: isAdminExempt, trial: !!trialInfo, credits: !!creditInfo });

      if (trialInfo) {
        res.setHeader("X-Trial-Remaining", Math.max(0, trialInfo.remaining - createdCount).toString());
      }
      if (creditInfo) {
        const newBalance = Math.max(0, creditInfo.balance - createdCount);
        res.setHeader("X-Credits-Remaining", newBalance.toString());
      }

      return res.status(201).json({
        batch_id: batchId,
        total: data.files.length,
        created: createdCount,
        existing: existingCount,
        results,
        ...(trialInfo ? { trial: { remaining: Math.max(0, trialInfo.remaining - createdCount) } } : {}),
        ...(creditInfo ? { credits: { remaining: Math.max(0, creditInfo.balance - createdCount) } } : {}),
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({
          error: "VALIDATION_ERROR",
          message: "Invalid request data",
          details: error.errors,
        });
      }
      logger.withRequest(req).error("Batch certification failed");
      return res.status(500).json({
        error: "INTERNAL_ERROR",
        message: "Failed to process batch certification. Please try again.",
      });
    }
  });
}
