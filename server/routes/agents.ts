import { type Express } from "express";
import crypto from "crypto";
import { db, pool } from "../db";
import { logger } from "../logger";
import { certifications, users, apiKeys } from "@shared/schema";
import { eq, and, sql } from "drizzle-orm";
import { z } from "zod";
import { isWalletAuthenticated } from "../walletAuth";
import { paymentRateLimiter } from "../reliability";
import { computeTrustScoreByWallet } from "../trust";
import { TRIAL_QUOTA, registerRateLimitMap, REGISTER_RATE_LIMIT_MAX, REGISTER_RATE_LIMIT_WINDOW_MS } from "./helpers";

export function registerAgentsRoutes(app: Express) {
  const trialInfoHandler = (_req: any, res: any) => {
    const baseUrl = `https://${_req.get('host')}`;
    res.json({
      name: "xproof Agent Trial",
      description: `Get ${TRIAL_QUOTA} free certifications instantly. No wallet, no payment, no browser needed.`,
      register: {
        method: "POST",
        url: `${baseUrl}/api/agent/register`,
        body: { agent_name: "your-agent-name" },
        content_type: "application/json",
      },
      free_certifications: TRIAL_QUOTA,
      example: `curl -X POST ${baseUrl}/api/agent/register -H "Content-Type: application/json" -d '{"agent_name": "my-agent"}'`,
      after_registration: `Use the returned API key (pm_xxx) as Bearer token: Authorization: Bearer pm_xxx`,
      certify_endpoint: `POST ${baseUrl}/api/proof`,
      batch_endpoint: `POST ${baseUrl}/api/batch`,
      docs: `${baseUrl}/llms.txt`,
    });
  };
  app.get("/api/trial", trialInfoHandler);
  app.get("/api/agent", trialInfoHandler);

  const agentRegisterSchema = z.object({
    agent_name: z.string().min(1, "Agent name is required").max(100),
    description: z.string().max(500).optional(),
  });

  app.post("/api/agent/register", paymentRateLimiter, async (req, res) => {
    try {
      const ip = req.headers["x-forwarded-for"]?.toString().split(",")[0]?.trim() || req.ip || "unknown";
      const ipHash = crypto.createHash("sha256").update(ip).digest("hex").slice(0, 16);

      const now = Date.now();
      const entry = registerRateLimitMap.get(ipHash);
      if (entry && now < entry.resetAt && entry.count >= REGISTER_RATE_LIMIT_MAX) {
        return res.status(429).json({
          error: "RATE_LIMIT_EXCEEDED",
          message: `Maximum ${REGISTER_RATE_LIMIT_MAX} trial registrations per hour per IP. Try again later.`,
          retry_after: Math.ceil((entry.resetAt - now) / 1000),
        });
      }
      if (!entry || now >= entry.resetAt) {
        registerRateLimitMap.set(ipHash, { count: 1, resetAt: now + REGISTER_RATE_LIMIT_WINDOW_MS });
      } else {
        entry.count++;
      }

      const data = agentRegisterSchema.parse(req.body);

      const nameLower = data.agent_name.toLowerCase();
      const existingByUser = await db.select({ id: users.id })
        .from(users)
        .where(and(
          sql`(LOWER(${users.companyName}) = ${nameLower} OR LOWER(${users.agentName}) = ${nameLower})`,
          eq(users.isTrial, false),
        ))
        .limit(1);
      const existingByKey = existingByUser.length === 0
        ? await db.select({ id: apiKeys.id })
            .from(apiKeys)
            .innerJoin(users, eq(apiKeys.userId, users.id))
            .where(and(
              sql`LOWER(${apiKeys.name}) = ${nameLower}`,
              eq(users.isTrial, false),
              eq(apiKeys.isActive, true),
            ))
            .limit(1)
        : [];
      const hasDuplicate = existingByUser.length > 0 || existingByKey.length > 0;

      if (hasDuplicate) {
        const baseUrl = `https://${req.get('host')}`;
        return res.status(409).json({
          error: "DUPLICATE_AGENT_NAME",
          message: `An agent named "${data.agent_name}" already exists on a real wallet. Registration blocked to prevent duplicates.`,
          resolution: `If this is your agent, connect your wallet at ${baseUrl} and use your existing API key. If you need a new trial key for a different agent, choose a unique name.`,
          claim_endpoint: `POST ${baseUrl}/api/trial/claim`,
        });
      }

      const trialWallet = `erd1trial${crypto.randomBytes(24).toString("hex")}`;

      const registrationIpFull = req.headers["x-forwarded-for"]?.toString().split(",")[0]?.trim() || req.ip || "unknown";
      const registrationIpHash = crypto.createHash("sha256").update(registrationIpFull).digest("hex");

      const [trialUser] = await db.insert(users).values({
        walletAddress: trialWallet,
        subscriptionTier: "free",
        subscriptionStatus: "active",
        isTrial: true,
        trialQuota: TRIAL_QUOTA,
        trialUsed: 0,
        companyName: data.agent_name,
        registrationIpHash,
      }).returning();

      const rawKey = `pm_${crypto.randomBytes(32).toString("hex")}`;
      const keyHash = crypto.createHash("sha256").update(rawKey).digest("hex");
      const keyPrefix = rawKey.slice(0, 10);

      await db.insert(apiKeys).values({
        keyHash,
        keyPrefix,
        userId: trialUser.id,
        name: `Trial: ${data.agent_name}`,
        isActive: true,
      });

      logger.withRequest(req).info("Agent trial registered", {
        agentName: data.agent_name,
        userId: trialUser.id,
        ipHash,
      });

      const baseUrl = `https://${req.get('host')}`;

      return res.status(201).json({
        api_key: rawKey,
        agent_name: data.agent_name,
        trial: {
          quota: TRIAL_QUOTA,
          used: 0,
          remaining: TRIAL_QUOTA,
        },
        endpoints: {
          certify: `POST ${baseUrl}/api/proof`,
          batch: `POST ${baseUrl}/api/batch`,
          verify: `GET ${baseUrl}/proof/{proof_id}`,
        },
        usage: `Include header: Authorization: Bearer ${rawKey}`,
        message: `Trial account created with ${TRIAL_QUOTA} free certifications. No wallet or payment needed. After trial, pay per certification via x402 (USDC on Base) or EGLD (ACP).`,
        warning: `This trial account is NOT linked to a MultiversX wallet. Certifications made with this key will NOT appear on your public agent profile or trust leaderboard. To link this key to your real wallet, authenticate at ${baseUrl} and call POST ${baseUrl}/api/trial/claim with this API key.`,
        claim_endpoint: `POST ${baseUrl}/api/trial/claim`,
        claim_usage: `After connecting your real wallet at ${baseUrl}, call: curl -X POST ${baseUrl}/api/trial/claim -H "Cookie: <your-session>" -H "Content-Type: application/json" -d '{"trial_api_key":"${rawKey}"}'`,
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({
          error: "VALIDATION_ERROR",
          message: "Invalid request data",
          details: error.errors,
        });
      }
      logger.withRequest(req).error("Agent registration failed", { error: (error as Error).message });
      return res.status(500).json({ error: "INTERNAL_ERROR", message: "Failed to create trial account" });
    }
  });

  // ============================================
  // Trial Claim endpoint
  // Transfers all certifications and API key from a trial account to the authenticated real wallet
  // POST /api/trial/claim — requires wallet session auth
  // Body: { trial_api_key: "pm_xxx..." }
  // ============================================
  app.post("/api/trial/claim", isWalletAuthenticated, async (req: any, res) => {
    try {
      const rawKey = typeof req.body?.trial_api_key === "string" ? req.body.trial_api_key.trim() : "";
      if (!rawKey || !rawKey.startsWith("pm_")) {
        return res.status(400).json({
          error: "INVALID_INPUT",
          message: "trial_api_key is required and must be a valid trial API key (starts with pm_)",
        });
      }

      const realWallet = req.walletAddress as string;
      const [realUser] = await db.select().from(users).where(eq(users.walletAddress, realWallet));
      if (!realUser) {
        return res.status(404).json({ error: "USER_NOT_FOUND", message: "Authenticated user not found" });
      }

      const keyHash = crypto.createHash("sha256").update(rawKey).digest("hex");
      const [trialApiKey] = await db.select().from(apiKeys).where(eq(apiKeys.keyHash, keyHash));
      if (!trialApiKey) {
        return res.status(404).json({ error: "KEY_NOT_FOUND", message: "Trial API key not found" });
      }

      const [trialUser] = await db.select().from(users).where(eq(users.id, trialApiKey.userId));
      if (!trialUser) {
        return res.status(404).json({ error: "TRIAL_USER_NOT_FOUND", message: "Trial user not found" });
      }
      if (!trialUser.isTrial) {
        return res.status(400).json({
          error: "NOT_A_TRIAL_KEY",
          message: "This API key is already linked to a real wallet account. Only trial keys can be claimed.",
        });
      }
      if (trialUser.id === realUser.id) {
        return res.status(400).json({
          error: "SAME_ACCOUNT",
          message: "This trial key already belongs to your account.",
        });
      }

      // Atomic transfer inside a transaction to prevent double-claim race conditions
      const result = await db.transaction(async (tx) => {
        // Atomically claim the API key — if userId already changed, this returns 0 rows
        const claimedKeys = await tx.update(apiKeys)
          .set({
            userId: realUser.id,
            name: trialApiKey.name?.replace(/^Trial: /, "") || "Claimed from trial",
          })
          .where(and(eq(apiKeys.id, trialApiKey.id), eq(apiKeys.userId, trialUser.id)))
          .returning({ id: apiKeys.id });

        if (claimedKeys.length === 0) {
          throw new Error("ALREADY_CLAIMED");
        }

        // Transfer all certifications
        const trialCerts = await tx.select({ id: certifications.id })
          .from(certifications)
          .where(eq(certifications.userId, trialUser.id));

        if (trialCerts.length > 0) {
          await tx.update(certifications)
            .set({ userId: realUser.id })
            .where(eq(certifications.userId, trialUser.id));
        }

        return { transferredCerts: trialCerts.length };
      });

      // Recalculate trust score outside transaction (non-critical — retry-safe)
      let updatedScore: any = null;
      try {
        const trust = await computeTrustScoreByWallet(realWallet);
        if (trust) {
          updatedScore = { score: trust.score, level: trust.level };
          await pool.query(
            `INSERT INTO trust_score_snapshots (wallet_address, score, level, cert_total, active_attestations, rank, snapshot_date)
             VALUES ($1, $2, $3, $4, $5, 0, CURRENT_DATE)
             ON CONFLICT (wallet_address, snapshot_date) DO UPDATE SET
               score = EXCLUDED.score, level = EXCLUDED.level,
               cert_total = EXCLUDED.cert_total, active_attestations = EXCLUDED.active_attestations`,
            [realWallet, trust.score, trust.level, trust.certTotal, trust.activeAttestations ?? 0]
          );
        }
      } catch (e) {
        logger.withRequest(req).warn("Trust score recalculation after claim failed", { error: (e as Error).message });
      }

      logger.withRequest(req).info("Trial account claimed", {
        realWallet,
        realUserId: realUser.id,
        trialUserId: trialUser.id,
        transferredCerts: result.transferredCerts,
        apiKeyId: trialApiKey.id,
        updatedScore,
      });

      return res.status(200).json({
        success: true,
        message: `Trial account successfully claimed. ${result.transferredCerts} certification(s) and 1 API key transferred to your wallet.`,
        transferred: {
          certifications: result.transferredCerts,
          api_keys: 1,
        },
        api_key_prefix: trialApiKey.keyPrefix,
        wallet: realWallet,
        trust_score: updatedScore,
      });
    } catch (error: any) {
      if (error?.message === "ALREADY_CLAIMED") {
        return res.status(409).json({
          error: "ALREADY_CLAIMED",
          message: "This trial key has already been claimed by another account.",
        });
      }
      logger.withRequest(req).error("Trial claim failed", { error: (error as Error).message });
      return res.status(500).json({ error: "INTERNAL_ERROR", message: "Failed to claim trial account" });
    }
  });
}
