import { type Express } from "express";
import crypto from "crypto";
import { db, pool } from "../db";
import { logger } from "../logger";
import { certifications, users, apiKeys } from "@shared/schema";
import { eq, and, sql, desc } from "drizzle-orm";
import { z } from "zod";
import { isWalletAuthenticated } from "../walletAuth";
import { paymentRateLimiter } from "../reliability";
import { computeTrustScoreByWallet } from "../trust";
import { TRIAL_QUOTA, registerRateLimitMap, REGISTER_RATE_LIMIT_MAX, REGISTER_RATE_LIMIT_WINDOW_MS } from "./helpers";

// ============================================
// Builds the machine-actionable quick_start guide
// Pre-fills the API key into every request so the agent can execute immediately
// ============================================
function buildQuickStart(apiKey: string, agentName: string, baseUrl: string) {
  return {
    workflow: [
      {
        step: 1,
        name: "verify_key",
        description: "Confirm your API key is active and check your credit balance",
        request: {
          method: "GET",
          url: `${baseUrl}/api/agent/status`,
          headers: { Authorization: `Bearer ${apiKey}` },
        },
        curl: `curl "${baseUrl}/api/agent/status" -H "Authorization: Bearer ${apiKey}"`,
      },
      {
        step: 2,
        name: "anchor_proof",
        description: "Certify a file or AI decision on-chain. Replace file_hash with SHA-256(your_content).",
        request: {
          method: "POST",
          url: `${baseUrl}/api/proof`,
          headers: {
            Authorization: `Bearer ${apiKey}`,
            "Content-Type": "application/json",
          },
          body: {
            file_hash: "<sha256-hex-64-chars>",
            filename: "decision.json",
            author_name: agentName,
            metadata: {
              action_type: "decision",
              agent: agentName,
            },
          },
        },
        curl: `curl -X POST "${baseUrl}/api/proof" \\
  -H "Authorization: Bearer ${apiKey}" \\
  -H "Content-Type: application/json" \\
  -d '{"file_hash":"<sha256-hex>","filename":"decision.json","author_name":"${agentName}","metadata":{"action_type":"decision"}}'`,
        note: "The response contains proof_id and verify_url. Save proof_id for step 3.",
      },
      {
        step: 3,
        name: "view_proof",
        description: "Retrieve the immutable on-chain proof record",
        request: {
          method: "GET",
          url: `${baseUrl}/proof/{proof_id}`,
          note: "Replace {proof_id} with the id returned in step 2",
        },
        curl: `curl "${baseUrl}/proof/{proof_id}"`,
      },
    ],
    sdk: {
      python: {
        install: "pip install xproof",
        usage: `from xproof import XProofClient\nimport hashlib\nclient = XProofClient("${apiKey}")\ncontent = b"my decision"\nproof = client.certify(hashlib.sha256(content).hexdigest(), "decision.json")\nprint(proof["proof_id"])`,
      },
      npm: {
        install: "npm install @xproof/sdk",
        usage: `import { XProofClient } from "@xproof/sdk";\nimport { createHash } from "crypto";\nconst client = new XProofClient({ apiKey: "${apiKey}" });\nconst hash = createHash("sha256").update("my decision").digest("hex");\nconst proof = await client.certify({ fileHash: hash, filename: "decision.json" });\nconsole.log(proof.proof_id);`,
      },
    },
    status_endpoint: `${baseUrl}/api/agent/status`,
    docs: `${baseUrl}/llms.txt`,
    openapi: `${baseUrl}/api/acp/openapi.json`,
  };
}

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
        optional_fields: {
          webhook_url: "https://your-server.com/webhook — called when each proof is confirmed on-chain",
          description: "Short description of your agent (max 500 chars)",
        },
      },
      free_certifications: TRIAL_QUOTA,
      example: `curl -X POST ${baseUrl}/api/agent/register -H "Content-Type: application/json" -d '{"agent_name": "my-agent"}'`,
      after_registration: `Use returned api_key as Bearer token. Call GET ${baseUrl}/api/agent/status to verify.`,
      certify_endpoint: `POST ${baseUrl}/api/proof`,
      status_endpoint: `GET ${baseUrl}/api/agent/status`,
      batch_endpoint: `POST ${baseUrl}/api/batch`,
      docs: `${baseUrl}/llms.txt`,
    });
  };
  app.get("/api/trial", trialInfoHandler);
  app.get("/api/agent", trialInfoHandler);

  // ============================================
  // POST /api/agent/register — Free trial registration
  // Creates a trial account with 10 free certifications.
  // Optionally accepts a webhook_url so the agent receives callbacks
  // for every proof it anchors, without specifying it per-proof.
  // ============================================
  const agentRegisterSchema = z.object({
    agent_name: z.string().min(1, "Agent name is required").max(100),
    description: z.string().max(500).optional(),
    webhook_url: z
      .string()
      .url("Must be a valid URL")
      .refine((url) => url.startsWith("https://"), { message: "Webhook URL must use HTTPS" })
      .optional(),
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

      // Generate a per-account webhook secret derived from the key — stable and unique
      const webhookSecretSeed = crypto.randomBytes(16).toString("hex");

      const [trialUser] = await db.insert(users).values({
        walletAddress: trialWallet,
        subscriptionTier: "free",
        subscriptionStatus: "active",
        isTrial: true,
        trialQuota: TRIAL_QUOTA,
        trialUsed: 0,
        companyName: data.agent_name,
        registrationIpHash,
        ...(data.webhook_url ? { webhookUrl: data.webhook_url, webhookSecret: webhookSecretSeed } : {}),
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
        hasWebhook: !!data.webhook_url,
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
        // Machine-actionable guide: every request pre-filled, ready to execute
        quick_start: buildQuickStart(rawKey, data.agent_name, baseUrl),
        // Account-level webhook (fires for every proof, no need to repeat per-proof)
        webhook: data.webhook_url
          ? {
              url: data.webhook_url,
              secret: webhookSecretSeed,
              status: "registered",
              note: "All your proofs will POST to this URL automatically. Verify signature with X-xProof-Signature header.",
              verify_signature: `HMAC-SHA256(secret="${webhookSecretSeed}", message=timestamp + "." + raw_body)`,
            }
          : {
              status: "not_configured",
              note: `To receive callbacks, include webhook_url in your registration body or add it per-proof in POST ${baseUrl}/api/proof.`,
            },
        // Legacy fields kept for backward compatibility
        endpoints: {
          status: `GET ${baseUrl}/api/agent/status`,
          certify: `POST ${baseUrl}/api/proof`,
          batch: `POST ${baseUrl}/api/batch`,
          verify: `GET ${baseUrl}/proof/{proof_id}`,
          claim: `POST ${baseUrl}/api/trial/claim`,
        },
        message: `Trial account created with ${TRIAL_QUOTA} free certifications. No wallet or payment needed. Call GET /api/agent/status to verify your key is active.`,
        warning: `Trial certifications are NOT linked to a MultiversX wallet. To link to your real identity, authenticate at ${baseUrl} and call POST ${baseUrl}/api/trial/claim.`,
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
  // GET /api/agent/status — Agent health & state check
  // Auth: Authorization: Bearer pm_xxx
  // Returns current credits, last proof, and next recommended action.
  // This is the single endpoint an agent can poll to know where it stands.
  // ============================================
  app.get("/api/agent/status", async (req, res) => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({
          error: "UNAUTHORIZED",
          message: "API key required. Include 'Authorization: Bearer pm_xxx' header.",
          register: `POST https://${req.get('host')}/api/agent/register`,
        });
      }

      const rawKey = authHeader.slice(7);
      if (!rawKey.startsWith("pm_")) {
        return res.status(401).json({
          error: "INVALID_API_KEY",
          message: "API key must start with 'pm_' prefix.",
        });
      }

      const keyHash = crypto.createHash("sha256").update(rawKey).digest("hex");
      const [apiKey] = await db.select().from(apiKeys).where(eq(apiKeys.keyHash, keyHash));

      if (!apiKey || !apiKey.isActive) {
        return res.status(401).json({
          error: "INVALID_API_KEY",
          message: "Invalid or revoked API key.",
        });
      }

      const [user] = await db.select().from(users).where(eq(users.id, apiKey.userId!));
      if (!user) {
        return res.status(404).json({ error: "USER_NOT_FOUND", message: "Account not found." });
      }

      const baseUrl = `https://${req.get('host')}`;

      // Fetch last proof anchored by this agent
      const [lastProof] = await db
        .select({
          id: certifications.id,
          fileName: certifications.fileName,
          fileHash: certifications.fileHash,
          blockchainStatus: certifications.blockchainStatus,
          transactionHash: certifications.transactionHash,
          createdAt: certifications.createdAt,
        })
        .from(certifications)
        .where(eq(certifications.userId, user.id))
        .orderBy(desc(certifications.createdAt))
        .limit(1);

      const trialRemaining = user.isTrial
        ? Math.max(0, (user.trialQuota ?? TRIAL_QUOTA) - (user.trialUsed ?? 0))
        : null;
      const creditBalance = user.creditBalance ?? 0;
      const totalRemaining = (trialRemaining ?? 0) + creditBalance;
      const isExhausted = user.isTrial ? trialRemaining === 0 && creditBalance === 0 : false;

      // Compute next recommended action
      let next_action: Record<string, any>;
      if (isExhausted) {
        next_action = {
          action: "purchase_credits",
          description: "Trial exhausted. Purchase prepaid credits to continue.",
          options: {
            credits: {
              method: "POST",
              url: `${baseUrl}/api/credits/purchase`,
              note: "100 proofs / $5 USDC on Base",
            },
            x402: {
              method: "POST",
              url: `${baseUrl}/api/proof`,
              note: "Pay per proof via x402 (no account needed)",
            },
            acp: {
              method: "POST",
              url: `${baseUrl}/api/acp/checkout`,
              note: "Pay with EGLD on MultiversX",
            },
          },
        };
      } else if (!lastProof) {
        next_action = {
          action: "anchor_first_proof",
          description: `You have ${totalRemaining} certification${totalRemaining !== 1 ? "s" : ""} available. Anchor your first proof now.`,
          request: {
            method: "POST",
            url: `${baseUrl}/api/proof`,
            headers: { Authorization: `Bearer ${rawKey}`, "Content-Type": "application/json" },
            body: {
              file_hash: "<sha256-hex-64-chars>",
              filename: "decision.json",
              author_name: user.companyName || "agent",
              metadata: { action_type: "decision" },
            },
          },
          curl: `curl -X POST "${baseUrl}/api/proof" -H "Authorization: Bearer ${rawKey}" -H "Content-Type: application/json" -d '{"file_hash":"<sha256-hex>","filename":"decision.json","metadata":{"action_type":"decision"}}'`,
        };
      } else {
        next_action = {
          action: "anchor_proof",
          description: `${totalRemaining} certification${totalRemaining !== 1 ? "s" : ""} remaining. Continue anchoring proofs.`,
          request: {
            method: "POST",
            url: `${baseUrl}/api/proof`,
            headers: { Authorization: `Bearer ${rawKey}`, "Content-Type": "application/json" },
            body: {
              file_hash: "<sha256-hex-64-chars>",
              filename: "decision.json",
              metadata: { action_type: "decision" },
            },
          },
        };
      }

      return res.json({
        status: "active",
        agent: {
          name: user.companyName || user.agentName || apiKey.name || "unknown",
          api_key_prefix: apiKey.keyPrefix,
          account_type: user.isTrial ? "trial" : "full",
          wallet: user.isTrial ? null : user.walletAddress,
        },
        credits: {
          ...(user.isTrial
            ? {
                trial: {
                  quota: user.trialQuota ?? TRIAL_QUOTA,
                  used: user.trialUsed ?? 0,
                  remaining: trialRemaining,
                },
              }
            : {}),
          paid: creditBalance,
          total_remaining: totalRemaining,
        },
        proofs: {
          total: (await db.select({ count: sql<number>`count(*)` }).from(certifications).where(eq(certifications.userId, user.id)))[0]?.count ?? 0,
          last_proof: lastProof
            ? {
                id: lastProof.id,
                filename: lastProof.fileName,
                file_hash: lastProof.fileHash,
                blockchain_status: lastProof.blockchainStatus,
                transaction_hash: lastProof.transactionHash,
                anchored_at: lastProof.createdAt?.toISOString(),
                verify_url: `${baseUrl}/proof/${lastProof.id}`,
              }
            : null,
        },
        webhook: user.webhookUrl
          ? {
              url: user.webhookUrl,
              status: "configured",
              note: "All your proofs fire a POST to this URL on confirmation.",
            }
          : {
              status: "not_configured",
              note: `Add webhook_url to POST ${baseUrl}/api/proof body to receive per-proof callbacks.`,
            },
        next_action,
        links: {
          anchor: `POST ${baseUrl}/api/proof`,
          batch: `POST ${baseUrl}/api/batch`,
          docs: `${baseUrl}/llms.txt`,
          openapi: `${baseUrl}/api/acp/openapi.json`,
          claim_trial: user.isTrial ? `POST ${baseUrl}/api/trial/claim` : null,
        },
      });
    } catch (error) {
      logger.withRequest(req).error("Agent status check failed", { error: (error as Error).message });
      return res.status(500).json({ error: "INTERNAL_ERROR", message: "Failed to retrieve agent status." });
    }
  });

  // ============================================
  // POST /api/trial/claim
  // Transfers all certifications and API key from a trial account to the authenticated real wallet
  // Requires wallet session auth
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
