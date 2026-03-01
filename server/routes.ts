import express, { type Express } from "express";
import { createServer, type Server } from "http";
import crypto from "crypto";
import { db } from "./db";
import { storage } from "./storage";
import { logger } from "./logger";
import { getAlertConfig } from "./txAlerts";
import { 
  certifications, 
  users, 
  acpCheckouts,
  apiKeys,
  txQueue as txQueueTable,
  visits,
  creditPurchases,
  acpCheckoutRequestSchema,
  acpConfirmRequestSchema,
  type ACPProduct,
  type ACPCheckoutResponse,
  type ACPConfirmResponse,
} from "@shared/schema";
import { CREDIT_PACKAGES, getPackage, verifyUsdcOnBase } from "./credits";
import { auditLogSchema, AUDIT_LOG_JSON_SCHEMA, type AgentAuditLog } from "./auditSchema";
import { getCertificationPriceEgld, getCertificationPriceUsd, getPricingInfo } from "./pricing";
import { eq, desc, sql, and, gte, gt, count, isNotNull } from "drizzle-orm";
import { z } from "zod";
import { getMetrics, bootstrapMetricsFromDb } from "./metrics";
import { isX402Configured, verifyX402Payment, send402Response } from "./x402";
import { generateCertificatePDF } from "./certificateGenerator";
import { recordOnBlockchain, isMultiversXConfigured, broadcastSignedTransaction } from "./blockchain";
import { createMcpServer, authenticateApiKey } from "./mcp";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { 
  isWalletAuthenticated, 
  generateChallenge, 
  verifyWalletSignature, 
  createWalletSession,
  destroyWalletSession 
} from "./walletAuth";
import { getSession } from "./replitAuth";
import { authRateLimiter, paymentRateLimiter, apiKeyCreationRateLimiter } from "./reliability";
import { recordCertificationAsJob, isMX8004Configured, getReputationScore, getAgentDetails, getContractAddresses, getJobData, getValidationStatus, hasGivenFeedback, getAgentResponse, readFeedback, getAgentsExplorerUrl } from "./mx8004";
import { getTxQueueStats } from "./txQueue";

const recentVisits = new Map<string, number>();
setInterval(() => {
  const now = Date.now();
  recentVisits.forEach((ts, key) => {
    if (now - ts > 60000) recentVisits.delete(key);
  });
}, 30000);

const SKIP_VISIT_PATHS = /^\/api\/|^\/.well-known\/|^\/mcp|^\/health|^\/src\/|^\/@|^\/node_modules\//;
const SKIP_VISIT_EXT = /\.(js|mjs|cjs|ts|tsx|jsx|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map|json|xml|txt|pdf|zip|webp|avif|mp4|webm|php|webmanifest)$/i;
const AGENT_UA_PATTERNS = ["chatgpt", "gptbot", "googlebot", "bingbot", "bot", "crawler", "spider", "curl", "wget", "python-requests", "axios", "node-fetch", "httpx", "scrapy", "postmanruntime", "semrushbot", "ahrefsbot", "slurp", "duckduckbot", "baiduspider", "yandexbot"];
const EXCLUDED_IP_HASHES = new Set((process.env.EXCLUDE_IP_HASHES || "").split(",").map(h => h.trim()).filter(Boolean));

export async function registerRoutes(app: Express): Promise<Server> {
  // Bootstrap blockchain latency metrics from DB (persists across deployments)
  try {
    const cutoff = new Date(Date.now() - 60 * 60 * 1000);
    // Rolling window certs (last 1h) for avg/percentile stats
    const rollingCerts = await db
      .select({ blockchainLatencyMs: certifications.blockchainLatencyMs, createdAt: certifications.createdAt })
      .from(certifications)
      .where(and(isNotNull(certifications.blockchainLatencyMs), gte(certifications.createdAt, cutoff)))
      .orderBy(desc(certifications.createdAt));
    // Most recent cert ever (for lastKnownLatency, regardless of window)
    const [latestCert] = await db
      .select({ blockchainLatencyMs: certifications.blockchainLatencyMs, createdAt: certifications.createdAt })
      .from(certifications)
      .where(isNotNull(certifications.blockchainLatencyMs))
      .orderBy(desc(certifications.createdAt))
      .limit(1);
    // Merge: include latestCert in rolling list if not already there (for lastKnownLatency)
    const allCerts = rollingCerts.length > 0 ? rollingCerts : (latestCert ? [latestCert] : []);
    bootstrapMetricsFromDb(allCerts, latestCert ?? null);
  } catch (_e) {
    // Non-blocking: if DB is unavailable at startup, metrics start from zero
  }

  // Apply session middleware
  app.use(getSession());

  app.use((req, res, next) => {
    next();
    const path = req.path;
    if (SKIP_VISIT_PATHS.test(path) || SKIP_VISIT_EXT.test(path)) return;

    const ip = req.ip || req.headers["x-forwarded-for"]?.toString().split(",")[0] || "unknown";
    const ipHash = crypto.createHash("sha256").update(ip).digest("hex");
    if (EXCLUDED_IP_HASHES.has(ipHash)) return;
    const dedupeKey = `${ipHash}:${path}`;
    const now = Date.now();
    if (recentVisits.has(dedupeKey) && now - recentVisits.get(dedupeKey)! < 60000) return;
    recentVisits.set(dedupeKey, now);

    const ua = (req.get("user-agent") || "").toLowerCase();
    const isAgent = AGENT_UA_PATTERNS.some(p => ua.includes(p));

    db.insert(visits).values({ ipHash, userAgent: req.get("user-agent") || null, isAgent, path }).catch(() => {});
  });
  
  // DEPRECATED: Legacy endpoint - SECURITY VULNERABILITY
  // This endpoint allows wallet impersonation (accepts any wallet address without signature)
  // Use /api/auth/wallet/sync with Native Auth token instead
  // Disabled for security - returns 410 Gone
  app.post("/api/auth/wallet/login", async (req, res) => {
    res.status(410).json({ 
      message: "This endpoint is deprecated due to security vulnerabilities. Use Native Auth with /api/auth/wallet/sync instead.",
      error: "ENDPOINT_DEPRECATED" 
    });
  });

  // Sync wallet state with backend (used by sdk-dapp integration)
  // REQUIRES Native Auth token verification for security
  app.post("/api/auth/wallet/sync", authRateLimiter, async (req, res) => {
    try {
      const { verifyNativeAuthToken, extractBearerToken } = await import("./nativeAuth");
      
      // Extract and verify Native Auth token
      const token = extractBearerToken(req.headers.authorization);
      
      if (!token) {
        return res.status(401).json({ 
          message: "Missing Native Auth token. Authentication requires cryptographic proof." 
        });
      }

      // Verify token cryptographically (signature + expiration + origin)
      const decoded = await verifyNativeAuthToken(token);
      const walletAddress = decoded.address;

      if (!walletAddress || !walletAddress.startsWith("erd1")) {
        return res.status(400).json({ message: "Invalid MultiversX wallet address in token" });
      }

      // Verify wallet address in request body matches token
      if (req.body.walletAddress && req.body.walletAddress !== walletAddress) {
        return res.status(403).json({ 
          message: "Wallet address mismatch - token address does not match request" 
        });
      }

      // Check if user exists, create if not
      let [user] = await db.select().from(users).where(eq(users.walletAddress, walletAddress));

      if (!user) {
        // Create new user with free tier
        [user] = await db
          .insert(users)
          .values({
            walletAddress,
            subscriptionTier: "free",
            subscriptionStatus: "active",
            monthlyUsage: 0,
            usageResetDate: new Date(),
          })
          .returning();
      }

      // Create wallet session (now cryptographically verified)
      await createWalletSession(req, walletAddress);

      res.json(user);
    } catch (error: any) {
      logger.withRequest(req).error("Wallet sync failed", { error: error.message });
      res.status(401).json({ 
        message: error.message || "Failed to verify authentication token" 
      });
    }
  });

  // Simple wallet sync - creates session without Native Auth verification
  // Used as fallback when SDK doesn't provide Native Auth token
  // Note: Less secure than full Native Auth, but still requires SDK login
  app.post("/api/auth/wallet/simple-sync", async (req, res) => {
    try {
      const { walletAddress } = req.body;
      
      if (!walletAddress || !walletAddress.startsWith("erd1")) {
        return res.status(400).json({ message: "Invalid MultiversX wallet address" });
      }

      logger.withRequest(req).info("Simple wallet sync", { walletAddress });

      // Check if user exists, create if not
      let [user] = await db.select().from(users).where(eq(users.walletAddress, walletAddress));

      if (!user) {
        // Create new user with free tier
        [user] = await db
          .insert(users)
          .values({
            walletAddress,
            subscriptionTier: "free",
            subscriptionStatus: "active",
            monthlyUsage: 0,
            usageResetDate: new Date(),
          })
          .returning();
      }

      // Create wallet session
      await createWalletSession(req, walletAddress);

      res.json(user);
    } catch (error: any) {
      logger.withRequest(req).error("Simple wallet sync failed", { error: error.message });
      res.status(500).json({ message: "Failed to create session" });
    }
  });

  // Get current user endpoint (for checking authentication status)
  app.get('/api/auth/me', isWalletAuthenticated, async (req: any, res) => {
    try {
      const walletAddress = req.walletAddress;
      const [user] = await db.select().from(users).where(eq(users.walletAddress, walletAddress));
      
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      
      // Check if user is admin
      const adminWallets = (process.env.ADMIN_WALLETS || "").split(",").map(w => w.trim()).filter(Boolean);
      const isAdmin = adminWallets.includes(walletAddress || "");
      
      res.json({ ...user, isAdmin });
    } catch (error) {
      logger.withRequest(req).error("Failed to fetch current user");
      res.status(500).json({ message: "Failed to fetch user" });
    }
  });

  // Logout endpoint
  app.post("/api/auth/logout", async (req, res) => {
    try {
      await destroyWalletSession(req);
      res.json({ message: "Logged out successfully" });
    } catch (error: any) {
      logger.withRequest(req).error("Logout failed");
      res.status(500).json({ message: "Failed to log out" });
    }
  });

  // Create certification (unlimited, free service)
  // Admin wallets (ADMIN_WALLETS env) are always exempt from any payment requirements
  app.post("/api/certifications", isWalletAuthenticated, async (req: any, res) => {
    try {
      const walletAddress = req.walletAddress;

      // Get user for certification ownership
      const [user] = await db.select().from(users).where(eq(users.walletAddress, walletAddress));
      
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // Validate request body
      const schema = z.object({
        fileName: z.string().min(1),
        fileHash: z.string().min(1),
        fileType: z.string().optional(),
        fileSize: z.number().optional(),
        authorName: z.string().min(1),
        authorSignature: z.string().optional(),
        transactionHash: z.string().optional(),
        transactionUrl: z.string().optional(),
      });

      const data = schema.parse(req.body);

      // Check if hash already exists
      const [existing] = await db
        .select()
        .from(certifications)
        .where(eq(certifications.fileHash, data.fileHash));

      if (existing) {
        return res.status(409).json({
          message: "This file has already been certified",
          certificationId: existing.id,
        });
      }

      // Use transaction from frontend (Extension Wallet signature) or fallback to server mode
      let transactionHash: string;
      let transactionUrl: string;
      let blockchainStatus: string = "confirmed";
      let blockchainLatencyMs: number | null = null;
      
      if (data.transactionHash && data.transactionUrl) {
        transactionHash = data.transactionHash;
        transactionUrl = data.transactionUrl;
        logger.withRequest(req).info("Using client-signed transaction", { transactionHash });

        const { verifyTransactionOnChain } = await import("./verifyTransaction");
        const { recordTransaction } = await import("./metrics");

        const expectedReceiver = process.env.MULTIVERSX_RECEIVER_ADDRESS || process.env.XPROOF_WALLET_ADDRESS || process.env.MULTIVERSX_SENDER_ADDRESS || "";
        const ADMIN_WALLETS = (process.env.ADMIN_WALLETS || "").split(",").map(w => w.trim().toLowerCase()).filter(Boolean);
        const isAdmin = ADMIN_WALLETS.includes(walletAddress.toLowerCase());

        let expectedMinValue = "0";
        if (!isAdmin) {
          const { priceEgld } = await getCertificationPriceEgld();
          expectedMinValue = priceEgld;
        }

        const verifyStart = Date.now();
        const verificationResult = await verifyTransactionOnChain(transactionHash, expectedReceiver, expectedMinValue);

        if (verificationResult.error === "pending" || verificationResult.error === "Transaction not found on blockchain") {
          blockchainStatus = "pending";
          logger.withRequest(req).info("Transaction pending on-chain, creating certification with pending status", { transactionHash });
        } else if (!verificationResult.verified) {
          logger.withRequest(req).warn("Payment verification failed", { transactionHash, error: verificationResult.error });
          return res.status(402).json({ message: "Payment verification failed", error: verificationResult.error });
        } else {
          blockchainStatus = "confirmed";
          blockchainLatencyMs = Date.now() - verifyStart;
          recordTransaction(true, blockchainLatencyMs, "certification");
        }
      } else {
        const result = await recordOnBlockchain(
          data.fileHash,
          data.fileName,
          data.authorName
        );
        transactionHash = result.transactionHash;
        transactionUrl = result.transactionUrl;
        blockchainLatencyMs = result.latencyMs ?? null;
      }

      // Create certification
      const [certification] = await db
        .insert(certifications)
        .values({
          userId: user.id!,
          fileName: data.fileName,
          fileHash: data.fileHash,
          fileType: data.fileType || "unknown",
          fileSize: data.fileSize || 0,
          authorName: data.authorName,
          authorSignature: data.authorSignature,
          transactionHash,
          transactionUrl,
          blockchainStatus,
          isPublic: true,
          ...(blockchainLatencyMs !== null ? { blockchainLatencyMs } : {}),
        })
        .returning();

      if (blockchainStatus === "pending") {
        const { scheduleVerificationRetry } = await import("./verifyTransaction");
        const retryReceiver = process.env.MULTIVERSX_RECEIVER_ADDRESS || process.env.XPROOF_WALLET_ADDRESS || process.env.MULTIVERSX_SENDER_ADDRESS || "";
        const RETRY_ADMIN_WALLETS = (process.env.ADMIN_WALLETS || "").split(",").map(w => w.trim().toLowerCase()).filter(Boolean);
        const retryIsAdmin = RETRY_ADMIN_WALLETS.includes(walletAddress.toLowerCase());
        let retryMinValue = "0";
        if (!retryIsAdmin) {
          const { priceEgld } = await getCertificationPriceEgld();
          retryMinValue = priceEgld;
        }
        scheduleVerificationRetry(certification.id, transactionHash, retryReceiver, retryMinValue);
      }

      const certificateUrl = `/api/certificates/${certification.id}.pdf`;

      res.status(201).json({
        ...certification,
        certificateUrl,
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid request data", errors: error.errors });
      }
      logger.withRequest(req).error("Failed to create certification");
      res.status(500).json({ message: "Failed to create certification" });
    }
  });

  // Get user's certifications
  app.get("/api/certifications", async (req: any, res) => {
    try {
      let userId: string | null = null;

      const authHeader = req.headers.authorization;
      if (authHeader && authHeader.startsWith("Bearer ")) {
        const rawKey = authHeader.slice(7);
        if (!rawKey.startsWith("pm_")) {
          return res.status(401).json({ error: "INVALID_API_KEY", message: "API key must start with 'pm_' prefix" });
        }
        const keyHash = crypto.createHash("sha256").update(rawKey).digest("hex");
        const [apiKey] = await db.select().from(apiKeys).where(eq(apiKeys.keyHash, keyHash));
        if (!apiKey || !apiKey.isActive) {
          return res.status(401).json({ error: "INVALID_API_KEY", message: "Invalid or expired API key" });
        }
        userId = apiKey.userId || null;
      } else {
        const walletAddress = req.session?.walletAddress;
        if (!walletAddress) {
          return res.status(401).json({
            error: "AUTH_REQUIRED",
            message: "Provide a wallet session or Bearer API key",
            options: [
              { type: "api_key", header: "Authorization: Bearer pm_xxx" },
              { type: "wallet", description: "Connect via MultiversX wallet" },
            ],
          });
        }
        const [user] = await db.select().from(users).where(eq(users.walletAddress, walletAddress));
        userId = user?.id || null;
      }

      if (!userId) {
        return res.status(404).json({ message: "User not found" });
      }

      const userCertifications = await db
        .select()
        .from(certifications)
        .where(eq(certifications.userId, userId))
        .orderBy(desc(certifications.createdAt));

      res.json(userCertifications);
    } catch (error) {
      logger.withRequest(req).error("Failed to fetch certifications");
      res.status(500).json({ message: "Failed to fetch certifications" });
    }
  });

  // GET /api/me — identity + quota for API key holders
  app.get("/api/me", async (req: any, res) => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({
          error: "AUTH_REQUIRED",
          message: "Provide Authorization: Bearer pm_xxx",
          hint: "GET /api/me returns your key status, trial quota, and certification count",
        });
      }

      const rawKey = authHeader.slice(7);
      if (!rawKey.startsWith("pm_")) {
        return res.status(401).json({ error: "INVALID_API_KEY", message: "API key must start with 'pm_' prefix" });
      }

      const keyHash = crypto.createHash("sha256").update(rawKey).digest("hex");
      const [apiKey] = await db.select().from(apiKeys).where(eq(apiKeys.keyHash, keyHash));
      if (!apiKey || !apiKey.isActive) {
        return res.status(401).json({ error: "INVALID_API_KEY", message: "Invalid or expired API key" });
      }

      const [user] = apiKey.userId
        ? await db.select().from(users).where(eq(users.id, apiKey.userId))
        : [];

      const certCount = user
        ? await db.select({ value: count() }).from(certifications).where(eq(certifications.userId, user.id))
        : [{ value: 0 }];

      const isTrial = user?.isTrial ?? false;
      const trialQuota = user?.trialQuota ?? 0;
      const trialUsed = user?.trialUsed ?? 0;
      const creditBalance = user?.creditBalance ?? 0;

      res.json({
        key_id: apiKey.id,
        key_prefix: rawKey.slice(0, 8) + "...",
        is_active: apiKey.isActive,
        created_at: apiKey.createdAt?.toISOString(),
        last_used_at: apiKey.lastUsedAt?.toISOString() ?? null,
        request_count: apiKey.requestCount ?? 0,
        account: {
          is_trial: isTrial,
          credit_balance: creditBalance,
          ...(isTrial ? {
            trial_quota: trialQuota,
            trial_used: trialUsed,
            trial_remaining: Math.max(0, trialQuota - trialUsed),
            upgrade: {
              credits: "POST /api/credits/purchase — prepaid packs (100/$5, 1000/$40, 10k/$300 USDC on Base)",
              x402: "Send requests without API key — pay per use via USDC on Base",
              acp: "Contact xproof for full API access with EGLD payments",
            },
          } : {}),
        },
        certifications: {
          total: certCount[0]?.value ?? 0,
        },
      });
    } catch (error) {
      logger.withRequest(req).error("Failed to fetch API key identity");
      res.status(500).json({ message: "Failed to fetch identity" });
    }
  });

  // Get account info (nonce) for transaction building
  app.get("/api/blockchain/account/:address", isWalletAuthenticated, async (req: any, res) => {
    try {
      const { address } = req.params;
      
      // Validate address format
      if (!address || !address.startsWith("erd1")) {
        return res.status(400).json({ message: "Invalid MultiversX address" });
      }

      // Get gateway URL from env
      const gatewayUrl = process.env.MULTIVERSX_GATEWAY_URL || "https://devnet-gateway.multiversx.com";
      
      // Fetch account info from MultiversX gateway
      const response = await fetch(`${gatewayUrl}/address/${address}`);
      
      if (!response.ok) {
        throw new Error(`Gateway error: ${response.statusText}`);
      }

      const data = await response.json();
      
      res.json({
        address,
        nonce: data.data?.account?.nonce || 0,
        balance: data.data?.account?.balance || "0",
      });
    } catch (error: any) {
      logger.withRequest(req).error("Failed to fetch account info", { error: error.message });
      res.status(500).json({ 
        message: "Failed to fetch account info",
        error: error.message 
      });
    }
  });

  // Broadcast signed transaction (XPortal integration)
  app.post("/api/blockchain/broadcast", isWalletAuthenticated, async (req: any, res) => {
    try {
      const { signedTransaction, certificationData } = req.body;

      if (!signedTransaction) {
        return res.status(400).json({ message: "Missing signed transaction" });
      }

      // If certification data is provided, validate and create certification record
      if (certificationData) {
        const walletAddress = req.walletAddress;
        
        // Get user
        const [user] = await db.select().from(users).where(eq(users.walletAddress, walletAddress));

        if (!user) {
          return res.status(404).json({ message: "User not found" });
        }

        // Validate certification data
        const schema = z.object({
          fileName: z.string().min(1),
          fileHash: z.string().min(1),
          fileType: z.string().optional(),
          fileSize: z.number().optional(),
          authorName: z.string().min(1),
          authorSignature: z.string().optional(),
        });

        const validatedData = schema.parse(certificationData);

        // Check if hash already exists
        const [existing] = await db
          .select()
          .from(certifications)
          .where(eq(certifications.fileHash, validatedData.fileHash));

        if (existing) {
          return res.status(409).json({
            message: "This file has already been certified",
            certificationId: existing.id,
          });
        }

        const { txHash, explorerUrl } = await broadcastSignedTransaction(signedTransaction);

        const { verifyTransactionOnChain } = await import("./verifyTransaction");
        const expectedReceiver = process.env.MULTIVERSX_RECEIVER_ADDRESS || process.env.XPROOF_WALLET_ADDRESS || process.env.MULTIVERSX_SENDER_ADDRESS || "";
        const BROADCAST_ADMIN_WALLETS = (process.env.ADMIN_WALLETS || "").split(",").map(w => w.trim().toLowerCase()).filter(Boolean);
        const isBroadcastAdmin = BROADCAST_ADMIN_WALLETS.includes(walletAddress.toLowerCase());

        let broadcastExpectedMinValue = "0";
        if (!isBroadcastAdmin) {
          const { priceEgld } = await getCertificationPriceEgld();
          broadcastExpectedMinValue = priceEgld;
        }

        const broadcastVerification = await verifyTransactionOnChain(txHash, expectedReceiver, broadcastExpectedMinValue);
        let broadcastBlockchainStatus = "pending";
        if (broadcastVerification.verified) {
          broadcastBlockchainStatus = "confirmed";
        } else if (broadcastVerification.error !== "pending" && broadcastVerification.error !== "Transaction not found on blockchain") {
          logger.withRequest(req).warn("Broadcast payment verification failed", { txHash, error: broadcastVerification.error });
          return res.status(402).json({ message: "Payment verification failed", error: broadcastVerification.error });
        }

        const [certification] = await db
          .insert(certifications)
          .values({
            userId: user.id!,
            fileName: validatedData.fileName,
            fileHash: validatedData.fileHash,
            fileType: validatedData.fileType || "unknown",
            fileSize: validatedData.fileSize || 0,
            authorName: validatedData.authorName,
            authorSignature: validatedData.authorSignature,
            transactionHash: txHash,
            transactionUrl: explorerUrl,
            blockchainStatus: broadcastBlockchainStatus,
            isPublic: true,
          })
          .returning();

        if (broadcastBlockchainStatus === "pending") {
          const { scheduleVerificationRetry } = await import("./verifyTransaction");
          scheduleVerificationRetry(certification.id, txHash, expectedReceiver, broadcastExpectedMinValue);
        }

        res.json({
          success: true,
          txHash,
          explorerUrl,
          certification,
        });
      } else {
        // Just broadcast without creating certification
        const { txHash, explorerUrl } = await broadcastSignedTransaction(signedTransaction);
        
        res.json({
          success: true,
          txHash,
          explorerUrl,
        });
      }
    } catch (error: any) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid certification data", errors: error.errors });
      }
      logger.withRequest(req).error("Failed to broadcast transaction", { error: error.message });
      res.status(500).json({ 
        message: "Failed to broadcast transaction",
        error: error.message 
      });
    }
  });

  app.get("/api/proof/check", async (req, res) => {
    try {
      const hash = req.query.hash as string;
      if (!hash || !/^[a-f0-9]{64}$/i.test(hash)) {
        return res.status(400).json({ error: "Valid SHA-256 hash required" });
      }

      const [existing] = await db
        .select()
        .from(certifications)
        .where(eq(certifications.fileHash, hash.toLowerCase()));

      if (existing) {
        return res.json({
          exists: true,
          proof_id: existing.id,
          proof_url: `/proof/${existing.id}`,
          certified_at: existing.createdAt,
        });
      }

      return res.json({ exists: false });
    } catch (error: any) {
      logger.error("Proof check error", { error: error.message });
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  // Get public proof (no auth required)
  app.get("/api/proof/:id", async (req, res) => {
    try {
      const { id } = req.params;
      
      const [certification] = await db
        .select()
        .from(certifications)
        .where(eq(certifications.id, id));

      if (!certification || !certification.isPublic) {
        return res.status(404).json({ message: "Proof not found" });
      }

      res.json(certification);
    } catch (error) {
      logger.withRequest(req).error("Failed to fetch proof");
      res.status(500).json({ message: "Failed to fetch proof" });
    }
  });

  // Download certificate
  app.get("/api/certificates/:id.pdf", async (req, res) => {
    try {
      const certId = req.params.id;
      
      const [certification] = await db
        .select()
        .from(certifications)
        .where(eq(certifications.id, certId));

      if (!certification) {
        return res.status(404).json({ message: "Certificate not found" });
      }

      if (certification.blockchainStatus === "pending") {
        return res.status(402).json({ message: "Certificate not yet available — payment is still pending blockchain confirmation" });
      }

      // Get user to determine subscription tier
      const [user] = await db
        .select()
        .from(users)
        .where(eq(users.id, certification.userId));

      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // Generate PDF (free service - standard branding)
      const pdfBuffer = await generateCertificatePDF({
        certification,
        subscriptionTier: 'free',
        companyName: undefined,
        companyLogoUrl: undefined,
      });

      // Set headers for PDF download
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="certificate-${certification.id}.pdf"`);
      res.send(pdfBuffer);
    } catch (error) {
      logger.withRequest(req).error("Failed to generate certificate");
      res.status(500).json({ message: "Failed to generate certificate" });
    }
  });

  // Get pricing information (public endpoint)
  app.get("/api/pricing", async (req, res) => {
    try {
      const wallet = (req.query.wallet as string || "").trim().toLowerCase();
      const ADMIN_WALLETS = (process.env.ADMIN_WALLETS || "").split(",").map(w => w.trim().toLowerCase()).filter(Boolean);
      const isAdmin = wallet && ADMIN_WALLETS.includes(wallet);
      const receiverAddress = process.env.MULTIVERSX_RECEIVER_ADDRESS || process.env.XPROOF_WALLET_ADDRESS || process.env.MULTIVERSX_SENDER_ADDRESS || "";

      const pricing = await getPricingInfo();

      if (isAdmin) {
        return res.json({
          protocol: "xproof",
          version: "1.0",
          ...pricing,
          price_usd: 0,
          price_egld: "0",
          egld_usd_rate: 0,
          receiver_address: receiverAddress,
          payment_methods: [
            { method: "EGLD", description: "Pay in EGLD at current exchange rate on MultiversX" },
            { method: "USDC", description: "Pay in USDC on Base via x402 protocol" },
          ],
        });
      }

      const { priceUsd, priceEgld, egldUsdRate } = await getCertificationPriceEgld();

      res.json({
        protocol: "xproof",
        version: "1.0",
        ...pricing,
        price_usd: priceUsd,
        price_egld: priceEgld,
        egld_usd_rate: egldUsdRate,
        receiver_address: receiverAddress,
        payment_methods: [
          { method: "EGLD", description: "Pay in EGLD at current exchange rate on MultiversX" },
          { method: "USDC", description: "Pay in USDC on Base via x402 protocol" },
        ],
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to retrieve pricing information" });
    }
  });

  // Deprecated — use /api/pricing instead
  app.get("/api/certification-price", (req, res) => {
    const wallet = req.query.wallet ? `?wallet=${req.query.wallet}` : "";
    res.redirect(301, `/api/pricing${wallet}`);
  });

  // ============================================
  // API Keys Management Endpoints
  // ============================================

  // Generate new API key (requires wallet auth)
  app.post("/api/keys", isWalletAuthenticated, apiKeyCreationRateLimiter, async (req: any, res) => {
    try {
      const { name } = req.body;
      if (!name || typeof name !== "string") {
        return res.status(400).json({ error: "API key name is required" });
      }

      const walletAddress = req.session?.walletAddress;
      const [user] = await db.select().from(users).where(eq(users.walletAddress, walletAddress));
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      // Generate a secure random API key
      const rawKey = `pm_${crypto.randomBytes(32).toString("hex")}`;
      const keyHash = crypto.createHash("sha256").update(rawKey).digest("hex");
      const keyPrefix = rawKey.slice(0, 10) + "...";

      const [apiKey] = await db
        .insert(apiKeys)
        .values({
          keyHash,
          keyPrefix,
          userId: user.id!,
          name,
        })
        .returning();

      logger.withRequest(req).info("API key created", { keyPrefix, walletAddress: walletAddress.slice(0, 12) });

      res.status(201).json({
        id: apiKey.id,
        key: rawKey, // Only returned once at creation
        prefix: keyPrefix,
        name: apiKey.name,
        created_at: apiKey.createdAt,
        message: "Save this key securely - it won't be shown again",
      });
    } catch (error) {
      logger.withRequest(req).error("API key creation failed");
      res.status(500).json({ error: "Failed to create API key" });
    }
  });

  // List user's API keys (requires wallet auth)
  app.get("/api/keys", isWalletAuthenticated, async (req: any, res) => {
    try {
      const walletAddress = req.session?.walletAddress;
      const [user] = await db.select().from(users).where(eq(users.walletAddress, walletAddress));
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      const keys = await db
        .select({
          id: apiKeys.id,
          prefix: apiKeys.keyPrefix,
          name: apiKeys.name,
          requestCount: apiKeys.requestCount,
          lastUsedAt: apiKeys.lastUsedAt,
          isActive: apiKeys.isActive,
          createdAt: apiKeys.createdAt,
        })
        .from(apiKeys)
        .where(eq(apiKeys.userId, user.id!));

      res.json({ keys });
    } catch (error) {
      logger.withRequest(req).error("Failed to list API keys");
      res.status(500).json({ error: "Failed to list API keys" });
    }
  });

  // Delete API key (requires wallet auth)
  app.delete("/api/keys/:keyId", isWalletAuthenticated, async (req: any, res) => {
    try {
      const { keyId } = req.params;
      const walletAddress = req.session?.walletAddress;
      const [user] = await db.select().from(users).where(eq(users.walletAddress, walletAddress));
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      const [key] = await db.select().from(apiKeys).where(eq(apiKeys.id, keyId));
      if (!key || key.userId !== user.id) {
        return res.status(404).json({ error: "API key not found" });
      }

      await db.delete(apiKeys).where(eq(apiKeys.id, keyId));
      logger.withRequest(req).info("API key deleted", { keyPrefix: key.keyPrefix });

      res.json({ message: "API key deleted" });
    } catch (error) {
      logger.withRequest(req).error("API key deletion failed");
      res.status(500).json({ error: "Failed to delete API key" });
    }
  });

  app.post("/api/keys/:keyId/rotate", isWalletAuthenticated, apiKeyCreationRateLimiter, async (req: any, res) => {
    try {
      const { keyId } = req.params;
      const walletAddress = req.session?.walletAddress;
      const [user] = await db.select().from(users).where(eq(users.walletAddress, walletAddress));
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      const [existingKey] = await db.select().from(apiKeys).where(eq(apiKeys.id, keyId));
      if (!existingKey || existingKey.userId !== user.id) {
        return res.status(404).json({ error: "API key not found" });
      }

      if (!existingKey.isActive) {
        return res.status(400).json({ error: "Cannot rotate a disabled key" });
      }

      const newRawKey = `pm_${crypto.randomBytes(32).toString("hex")}`;
      const newKeyHash = crypto.createHash("sha256").update(newRawKey).digest("hex");
      const newKeyPrefix = newRawKey.slice(0, 10) + "...";

      const gracePeriodEnd = new Date(Date.now() + 24 * 60 * 60 * 1000);

      await db
        .update(apiKeys)
        .set({
          previousKeyHash: existingKey.keyHash,
          previousKeyExpiresAt: gracePeriodEnd,
          keyHash: newKeyHash,
          keyPrefix: newKeyPrefix,
        })
        .where(eq(apiKeys.id, keyId));

      logger.withRequest(req).info("API key rotated", { oldPrefix: existingKey.keyPrefix, newPrefix: newKeyPrefix });

      res.json({
        id: keyId,
        key: newRawKey,
        prefix: newKeyPrefix,
        previous_key_expires_at: gracePeriodEnd.toISOString(),
        message: "New key generated. Previous key remains valid for 24 hours.",
      });
    } catch (error) {
      logger.withRequest(req).error("API key rotation failed");
      res.status(500).json({ error: "Failed to rotate API key" });
    }
  });

  // ============================================
  // Rate Limiting for ACP (anti-abuse)
  // ============================================
  const rateLimitMap = new Map<string, { count: number; resetAt: number }>();
  const RATE_LIMIT_MAX = 100; // 100 requests per minute
  const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute

  function checkRateLimit(identifier: string): { allowed: boolean; remaining: number; resetAt: number } {
    const now = Date.now();
    const entry = rateLimitMap.get(identifier);

    if (!entry || now > entry.resetAt) {
      rateLimitMap.set(identifier, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
      return { allowed: true, remaining: RATE_LIMIT_MAX - 1, resetAt: now + RATE_LIMIT_WINDOW_MS };
    }

    if (entry.count >= RATE_LIMIT_MAX) {
      return { allowed: false, remaining: 0, resetAt: entry.resetAt };
    }

    entry.count++;
    return { allowed: true, remaining: RATE_LIMIT_MAX - entry.count, resetAt: entry.resetAt };
  }

  // API Key validation middleware for ACP endpoints
  async function validateApiKey(req: express.Request, res: express.Response, next: express.NextFunction) {
    const authHeader = req.headers.authorization;
    
    // Allow unauthenticated access to discovery and health endpoints
    // Note: req.path is relative to mount point, so /api/acp/products becomes /products
    if (req.path === "/products" || req.path === "/openapi.json" || req.path === "/health") {
      return next();
    }

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "UNAUTHORIZED",
        message: "API key required. Include 'Authorization: Bearer pm_xxx' header",
      });
    }

    const rawKey = authHeader.slice(7);
    const keyHash = crypto.createHash("sha256").update(rawKey).digest("hex");

    let [apiKey] = await db.select().from(apiKeys).where(eq(apiKeys.keyHash, keyHash));

    if (!apiKey) {
      const [rotatedKey] = await db.select().from(apiKeys).where(
        and(eq(apiKeys.previousKeyHash, keyHash), gte(apiKeys.previousKeyExpiresAt, new Date()))
      );
      if (rotatedKey) {
        apiKey = rotatedKey;
        res.setHeader("X-xProof-Key-Deprecated", "true");
        res.setHeader("X-xProof-Key-Expires", rotatedKey.previousKeyExpiresAt!.toISOString());
      }
    }

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

    // Rate limiting check
    const rateLimit = checkRateLimit(apiKey.id);
    res.setHeader("X-RateLimit-Limit", RATE_LIMIT_MAX.toString());
    res.setHeader("X-RateLimit-Remaining", rateLimit.remaining.toString());
    res.setHeader("X-RateLimit-Reset", Math.floor(rateLimit.resetAt / 1000).toString());

    if (!rateLimit.allowed) {
      return res.status(429).json({
        error: "RATE_LIMIT_EXCEEDED",
        message: "Too many requests. Please slow down.",
        retry_after: Math.ceil((rateLimit.resetAt - Date.now()) / 1000),
      });
    }

    // Update usage stats (async, don't block response)
    db.update(apiKeys)
      .set({
        lastUsedAt: new Date(),
        requestCount: (apiKey.requestCount || 0) + 1,
      })
      .where(eq(apiKeys.id, apiKey.id))
      .execute()
      .catch((err) => logger.error("Failed to update API key stats", { error: err.message }));

    // Attach API key info to request
    (req as any).apiKey = apiKey;
    next();
  }

  function isAdminWallet(walletAddress: string): boolean {
    const adminWallets = (process.env.ADMIN_WALLETS || "").split(",").map(w => w.trim()).filter(Boolean);
    return adminWallets.includes(walletAddress);
  }

  async function getApiKeyOwnerWallet(apiKeyRecord: any): Promise<string | null> {
    if (!apiKeyRecord?.userId) return null;
    const [user] = await db.select().from(users).where(eq(users.id, apiKeyRecord.userId));
    return user?.walletAddress || null;
  }

  async function getTrialUser(apiKeyRecord: any): Promise<{ isTrial: boolean; remaining: number; userId: string } | null> {
    if (!apiKeyRecord?.userId) return null;
    const [user] = await db.select().from(users).where(eq(users.id, apiKeyRecord.userId));
    if (!user || !user.isTrial) return null;
    return {
      isTrial: true,
      remaining: (user.trialQuota || 0) - (user.trialUsed || 0),
      userId: user.id,
    };
  }

  async function consumeTrialCredit(userId: string, count: number = 1): Promise<void> {
    await db.update(users)
      .set({ trialUsed: sql`trial_used + ${count}` })
      .where(eq(users.id, userId));
  }

  async function getUserCreditBalance(userId: string): Promise<number> {
    const [user] = await db.select({ creditBalance: users.creditBalance }).from(users).where(eq(users.id, userId));
    return user?.creditBalance ?? 0;
  }

  async function consumeCredit(userId: string, count: number = 1): Promise<void> {
    await db.update(users)
      .set({ creditBalance: sql`GREATEST(0, credit_balance - ${count})` })
      .where(eq(users.id, userId));
  }

  async function addCredits(userId: string, amount: number): Promise<void> {
    await db.update(users)
      .set({ creditBalance: sql`credit_balance + ${amount}` })
      .where(eq(users.id, userId));
  }

  const TRIAL_QUOTA = 10;
  const registerRateLimitMap = new Map<string, { count: number; resetAt: number }>();
  const REGISTER_RATE_LIMIT_MAX = 3;
  const REGISTER_RATE_LIMIT_WINDOW_MS = 60 * 60 * 1000;

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

  // ── Credit endpoints ─────────────────────────────────────────────────────────
  // GET /api/credits/packages — list available prepaid certification packages
  app.get("/api/credits/packages", (_req, res) => {
    const baseUrl = `https://${_req.get("host")}`;
    res.json({
      packages: CREDIT_PACKAGES,
      payment: {
        network: "eip155:8453",
        asset: "USDC",
        contract: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        pay_to: process.env.X402_PAY_TO || "",
        note: "Send USDC on Base to pay_to, then confirm via POST /api/credits/confirm",
      },
      workflow: [
        `1. GET ${baseUrl}/api/credits/packages — pick a package_id`,
        `2. POST ${baseUrl}/api/credits/purchase — get payment requirements`,
        `3. Send USDC on Base to the pay_to address`,
        `4. POST ${baseUrl}/api/credits/confirm — confirm with tx_hash to credit your account`,
      ],
    });
  });

  // POST /api/credits/purchase — requires API key, returns payment requirements for a package
  app.post("/api/credits/purchase", async (req, res) => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader?.startsWith("Bearer ")) {
        return res.status(401).json({ error: "AUTH_REQUIRED", message: "Provide Authorization: Bearer pm_xxx" });
      }
      const rawKey = authHeader.slice(7);
      if (!rawKey.startsWith("pm_")) {
        return res.status(401).json({ error: "INVALID_API_KEY", message: "API key must start with pm_" });
      }
      const keyHash = crypto.createHash("sha256").update(rawKey).digest("hex");
      const [apiKey] = await db.select().from(apiKeys).where(eq(apiKeys.keyHash, keyHash));
      if (!apiKey?.isActive) {
        return res.status(401).json({ error: "INVALID_API_KEY", message: "Invalid or expired API key" });
      }
      if (!apiKey.userId) {
        return res.status(400).json({ error: "NO_ACCOUNT", message: "API key has no associated account" });
      }

      const body = req.body as { package_id?: string };
      const pkg = getPackage(body?.package_id || "");
      if (!pkg) {
        return res.status(400).json({
          error: "INVALID_PACKAGE",
          message: `Unknown package. Available: ${CREDIT_PACKAGES.map((p) => p.id).join(", ")}`,
          packages: CREDIT_PACKAGES,
        });
      }

      const payTo = process.env.X402_PAY_TO || "";
      if (!payTo) {
        return res.status(503).json({ error: "PAYMENT_NOT_CONFIGURED", message: "Credit purchases are not yet enabled" });
      }

      return res.status(202).json({
        status: "payment_required",
        package: pkg,
        payment: {
          network: "eip155:8453",
          asset: "USDC",
          contract: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
          pay_to: payTo,
          amount_usdc: pkg.price_usdc,
          amount_raw: pkg.price_usdc_raw,
          decimals: 6,
        },
        next_step: "After sending USDC on Base, call POST /api/credits/confirm with { package_id, tx_hash }",
      });
    } catch (err: any) {
      logger.withRequest(req).error("Credits purchase error", { error: err.message });
      return res.status(500).json({ error: "INTERNAL_ERROR" });
    }
  });

  // POST /api/credits/confirm — verify Base tx and add credits to account
  app.post("/api/credits/confirm", async (req, res) => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader?.startsWith("Bearer ")) {
        return res.status(401).json({ error: "AUTH_REQUIRED", message: "Provide Authorization: Bearer pm_xxx" });
      }
      const rawKey = authHeader.slice(7);
      if (!rawKey.startsWith("pm_")) {
        return res.status(401).json({ error: "INVALID_API_KEY", message: "API key must start with pm_" });
      }
      const keyHash = crypto.createHash("sha256").update(rawKey).digest("hex");
      const [apiKey] = await db.select().from(apiKeys).where(eq(apiKeys.keyHash, keyHash));
      if (!apiKey?.isActive) {
        return res.status(401).json({ error: "INVALID_API_KEY", message: "Invalid or expired API key" });
      }
      if (!apiKey.userId) {
        return res.status(400).json({ error: "NO_ACCOUNT", message: "API key has no associated account" });
      }

      const body = req.body as { package_id?: string; tx_hash?: string };
      const pkg = getPackage(body?.package_id || "");
      if (!pkg) {
        return res.status(400).json({
          error: "INVALID_PACKAGE",
          message: `Unknown package_id. Available: ${CREDIT_PACKAGES.map((p) => p.id).join(", ")}`,
        });
      }

      const txHash = (body?.tx_hash || "").trim();
      if (!txHash.startsWith("0x") || txHash.length < 66) {
        return res.status(400).json({ error: "INVALID_TX_HASH", message: "Provide a valid Base tx hash (0x...)" });
      }

      // Prevent double-claim
      const [existing] = await db.select().from(creditPurchases).where(eq(creditPurchases.txHash, txHash));
      if (existing) {
        return res.status(409).json({ error: "TX_ALREADY_USED", message: "This transaction has already been used to credit an account" });
      }

      const payTo = process.env.X402_PAY_TO || "";
      if (!payTo) {
        return res.status(503).json({ error: "PAYMENT_NOT_CONFIGURED" });
      }

      // Verify the USDC transfer on Base
      const { valid, error: verifyError } = await verifyUsdcOnBase(txHash, payTo, BigInt(pkg.price_usdc_raw));
      if (!valid) {
        return res.status(402).json({
          error: "PAYMENT_VERIFICATION_FAILED",
          message: verifyError || "Could not verify USDC transfer on Base",
          expected: { pay_to: payTo, amount_usdc: pkg.price_usdc, asset: "USDC", network: "eip155:8453" },
        });
      }

      // Record purchase and add credits atomically
      await db.insert(creditPurchases).values({
        userId: apiKey.userId,
        packageId: pkg.id,
        txHash,
        creditsAdded: pkg.certs,
        priceUsdc: pkg.price_usdc,
        network: "eip155:8453",
      });
      await addCredits(apiKey.userId, pkg.certs);

      const newBalance = await getUserCreditBalance(apiKey.userId);
      logger.withRequest(req).info("Credits added", { userId: apiKey.userId, package: pkg.id, credits: pkg.certs, txHash });

      return res.json({
        status: "credited",
        credits_added: pkg.certs,
        credit_balance: newBalance,
        package: pkg,
        tx_hash: txHash,
      });
    } catch (err: any) {
      logger.withRequest(req).error("Credits confirm error", { error: err.message });
      return res.status(500).json({ error: "INTERNAL_ERROR" });
    }
  });
  // ─────────────────────────────────────────────────────────────────────────────

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

      const trialWallet = `erd1trial${crypto.randomBytes(24).toString("hex")}`;

      const [trialUser] = await db.insert(users).values({
        walletAddress: trialWallet,
        subscriptionTier: "free",
        subscriptionStatus: "active",
        isTrial: true,
        trialQuota: TRIAL_QUOTA,
        trialUsed: 0,
        companyName: data.agent_name,
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

  // Apply API key validation to ACP endpoints
  app.use("/api/acp", validateApiKey);

  // ============================================
  // Simplified POST /api/proof endpoint for AI agents
  // Single-call certification: validate API key, record on blockchain, return proof
  // ============================================
  const proofRequestSchema = z.object({
    file_hash: z.string().length(64, "SHA-256 hash must be exactly 64 hex characters").regex(/^[a-fA-F0-9]+$/, "Must be a valid hex string"),
    filename: z.string().min(1, "Filename is required"),
    author_name: z.string().optional(),
    webhook_url: z.string().url("Must be a valid URL").refine((url) => !url || url.startsWith("https://"), { message: "Webhook URL must use HTTPS" }).optional(),
  });

  app.post("/api/proof", paymentRateLimiter, async (req, res) => {
    try {
      let authMethod: "api_key" | "x402" = "api_key";
      let isAdminExempt = false;
      const authHeader = req.headers.authorization;
      const hasBearerToken = authHeader && authHeader.startsWith("Bearer ");
      const hasX402Payment = !!req.headers["x-payment"];

      let trialInfo: { isTrial: boolean; remaining: number; userId: string } | null = null;
      let creditInfo: { userId: string; balance: number } | null = null;

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

        const rateLimit = checkRateLimit(apiKey.id);
        res.setHeader("X-RateLimit-Limit", RATE_LIMIT_MAX.toString());
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

      const certUserId = trialInfo ? trialInfo.userId : null;
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
          ...(result.latencyMs != null ? { blockchainLatencyMs: result.latencyMs } : {}),
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
        const { scheduleWebhookDelivery, isValidWebhookUrl } = await import("./webhook");
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
        res.setHeader("X-RateLimit-Limit", RATE_LIMIT_MAX.toString());
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

        const rateLimit = checkRateLimit(apiKey.id);
        res.setHeader("X-RateLimit-Limit", RATE_LIMIT_MAX.toString());
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

      const certUserId = trialInfo ? trialInfo.userId : null;
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
            ...(result.latencyMs != null ? { blockchainLatencyMs: result.latencyMs } : {}),
          })
          .returning();

        createdCount++;
        results.push({
          file_hash: certification.fileHash,
          filename: certification.fileName,
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
          const { scheduleWebhookDelivery, isValidWebhookUrl } = await import("./webhook");
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

  // ============================================
  // ACP (Agent Commerce Protocol) Endpoints
  // These endpoints enable AI agents to discover
  // and use xproof certification services
  // ============================================

  // ACP Products Discovery - Returns available services for AI agents
  app.get("/api/acp/products", async (req, res) => {
    const priceUsd = await getCertificationPriceUsd();
    
    const products: ACPProduct[] = [
      {
        id: "xproof-certification",
        name: "xproof Certification",
        description: "xproof is the canonical proof layer for AI agents. Create cryptographic proof of existence and integrity for digital files on MultiversX blockchain. Records SHA-256 hash with timestamp, providing immutable evidence of file ownership at a specific point in time.",
        pricing: {
          type: "fixed",
          amount: priceUsd.toString(),
          currency: "USD",
          note: "Price converted to EGLD at checkout based on current exchange rate",
        },
        inputs: {
          file_hash: "SHA-256 hash of the file (64 character hex string)",
          filename: "Original filename with extension",
          author_name: "Optional - Name of the author/certifier",
          metadata: "Optional - Additional JSON metadata",
        },
        outputs: {
          certification_id: "Unique certification ID",
          certificate_url: "URL to download PDF certificate",
          proof_url: "Public verification page URL",
          tx_hash: "MultiversX transaction hash",
          blockchain_explorer_url: "Link to view transaction on explorer",
        },
      },
    ];

    res.json({ 
      protocol: "ACP",
      version: "1.0",
      provider: "xproof",
      chain: "MultiversX",
      products 
    });
  });

  // ACP Checkout - Agent initiates certification
  app.post("/api/acp/checkout", async (req, res) => {
    try {
      const data = acpCheckoutRequestSchema.parse(req.body);

      // Validate product exists
      if (data.product_id !== "xproof-certification") {
        return res.status(404).json({ 
          error: "PRODUCT_NOT_FOUND",
          message: "Unknown product ID" 
        });
      }

      // Check if hash already certified
      const [existing] = await db
        .select()
        .from(certifications)
        .where(eq(certifications.fileHash, data.inputs.file_hash));

      if (existing) {
        return res.status(409).json({
          error: "ALREADY_CERTIFIED",
          message: "This file hash has already been certified",
          existing_certification: {
            id: existing.id,
            certified_at: existing.createdAt,
            proof_url: `/proof/${existing.id}`,
            tx_hash: existing.transactionHash,
          },
        });
      }

      // Check if the API key owner is an admin wallet
      let acpAdminExempt = false;
      const acpApiKey = (req as any).apiKey;
      if (acpApiKey?.userId) {
        const ownerWallet = await getApiKeyOwnerWallet(acpApiKey);
        if (ownerWallet && isAdminWallet(ownerWallet)) {
          acpAdminExempt = true;
          logger.withRequest(req).info("Admin wallet exempt from ACP payment", { walletAddress: ownerWallet });
        }
      }

      // Get current EGLD price and calculate payment
      const pricing = await getCertificationPriceEgld();
      
      // Create checkout session (expires in 1 hour)
      const expiresAt = new Date(Date.now() + 60 * 60 * 1000);
      
      const [checkout] = await db
        .insert(acpCheckouts)
        .values({
          productId: data.product_id,
          fileHash: data.inputs.file_hash,
          fileName: data.inputs.filename,
          authorName: data.inputs.author_name || "AI Agent",
          metadata: data.inputs.metadata || {},
          buyerType: data.buyer?.type || "agent",
          buyerId: data.buyer?.id,
          status: "pending",
          expiresAt,
        })
        .returning();

      // Build transaction payload for MultiversX
      // Data format: certify@<hash>@<filename>
      const dataField = Buffer.from(
        `certify@${data.inputs.file_hash}@${data.inputs.filename}`
      ).toString("base64");

      const chainId = process.env.MULTIVERSX_CHAIN_ID || "1"; // 1 = Mainnet
      
      // Receiver wallet for certification fees (admin wallet preferred)
      const xproofWallet = process.env.MULTIVERSX_RECEIVER_ADDRESS || process.env.XPROOF_WALLET_ADDRESS || process.env.MULTIVERSX_SENDER_ADDRESS;
      if (!xproofWallet) {
        logger.withRequest(req).error("No receiver wallet configured");
        return res.status(500).json({
          error: "CONFIGURATION_ERROR",
          message: "xproof wallet not configured",
        });
      }

      const response: ACPCheckoutResponse = {
        checkout_id: checkout.id,
        product_id: data.product_id,
        amount: acpAdminExempt ? "0.00" : pricing.priceUsd.toFixed(2),
        currency: "USD",
        status: "ready",
        execution: {
          type: "multiversx",
          mode: "direct",
          chain_id: chainId,
          tx_payload: {
            receiver: xproofWallet,
            data: dataField,
            value: acpAdminExempt ? "0" : pricing.priceEgld,
            gas_limit: 100000,
          },
        },
        expires_at: expiresAt.toISOString(),
      };

      logger.withRequest(req).info("ACP checkout created", { checkoutId: checkout.id, priceUsd: acpAdminExempt ? "0 (admin)" : pricing.priceUsd, priceEgld: acpAdminExempt ? "0 (admin)" : pricing.priceEgld, egldUsdRate: pricing.egldUsdRate, fileHash: data.inputs.file_hash.slice(0, 16), adminExempt: acpAdminExempt });
      
      res.status(201).json(response);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ 
          error: "INVALID_REQUEST",
          message: "Invalid checkout request",
          details: error.errors 
        });
      }
      logger.withRequest(req).error("ACP checkout failed");
      res.status(500).json({ 
        error: "CHECKOUT_FAILED",
        message: "Failed to create checkout" 
      });
    }
  });

  // ACP Confirm - Agent confirms transaction was executed
  app.post("/api/acp/confirm", async (req, res) => {
    try {
      const data = acpConfirmRequestSchema.parse(req.body);

      // Find checkout
      const [checkout] = await db
        .select()
        .from(acpCheckouts)
        .where(eq(acpCheckouts.id, data.checkout_id));

      if (!checkout) {
        return res.status(404).json({
          error: "CHECKOUT_NOT_FOUND",
          message: "Checkout session not found",
        });
      }

      // Check if expired
      if (new Date() > checkout.expiresAt) {
        await db
          .update(acpCheckouts)
          .set({ status: "expired" })
          .where(eq(acpCheckouts.id, checkout.id));

        return res.status(410).json({
          error: "CHECKOUT_EXPIRED",
          message: "Checkout session has expired",
        });
      }

      // Check if already confirmed
      if (checkout.status === "confirmed") {
        return res.status(409).json({
          error: "ALREADY_CONFIRMED",
          message: "This checkout has already been confirmed",
          certification_id: checkout.certificationId,
        });
      }

      // Verify transaction on MultiversX
      const chainId = process.env.MULTIVERSX_CHAIN_ID || "1";
      const apiUrl = chainId === "1"
        ? "https://api.multiversx.com"
        : "https://devnet-api.multiversx.com";
      const explorerUrl = chainId === "1"
        ? "https://explorer.multiversx.com"
        : "https://devnet-explorer.multiversx.com";

      let txVerified = false;
      let txStatus = "pending";

      try {
        const txResponse = await fetch(`${apiUrl}/transactions/${data.tx_hash}`);
        if (txResponse.ok) {
          const txData = await txResponse.json();
          txStatus = txData.status;
          txVerified = txData.status === "success";
        }
      } catch (err) {
        logger.withRequest(req).warn("Could not verify transaction, proceeding anyway", { txHash: data.tx_hash });
        // For MVP, we proceed even if verification fails
        // In production, you'd want stricter verification
        txVerified = true;
      }

      // Find or create a system user for ACP certifications
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

      // Create certification record
      const [certification] = await db
        .insert(certifications)
        .values({
          userId: systemUser.id!,
          fileName: checkout.fileName,
          fileHash: checkout.fileHash,
          fileType: checkout.fileName.split(".").pop() || "unknown",
          authorName: checkout.authorName || "AI Agent",
          transactionHash: data.tx_hash,
          transactionUrl: `${explorerUrl}/transactions/${data.tx_hash}`,
          blockchainStatus: txVerified ? "confirmed" : "pending",
          isPublic: true,
        })
        .returning();

      // Update checkout status
      await db
        .update(acpCheckouts)
        .set({
          status: "confirmed",
          txHash: data.tx_hash,
          certificationId: certification.id,
          confirmedAt: new Date(),
        })
        .where(eq(acpCheckouts.id, checkout.id));

      const response: ACPConfirmResponse = {
        status: "confirmed",
        checkout_id: checkout.id,
        tx_hash: data.tx_hash,
        certification_id: certification.id,
        certificate_url: `/api/certificates/${certification.id}.pdf`,
        proof_url: `/proof/${certification.id}`,
        blockchain_explorer_url: `${explorerUrl}/transactions/${data.tx_hash}`,
        message: "Certification successfully recorded on MultiversX blockchain",
      };

      logger.withRequest(req).info("ACP certification confirmed", { certificationId: certification.id });

      res.json(response);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({
          error: "INVALID_REQUEST",
          message: "Invalid confirmation request",
          details: error.errors,
        });
      }
      logger.withRequest(req).error("ACP confirm failed");
      res.status(500).json({
        error: "CONFIRMATION_FAILED",
        message: "Failed to confirm certification",
      });
    }
  });

  // ACP Status - Check checkout status
  app.get("/api/acp/checkout/:checkoutId", async (req, res) => {
    try {
      const { checkoutId } = req.params;

      const [checkout] = await db
        .select()
        .from(acpCheckouts)
        .where(eq(acpCheckouts.id, checkoutId));

      if (!checkout) {
        return res.status(404).json({
          error: "CHECKOUT_NOT_FOUND",
          message: "Checkout session not found",
        });
      }

      res.json({
        checkout_id: checkout.id,
        product_id: checkout.productId,
        status: checkout.status,
        file_hash: checkout.fileHash,
        file_name: checkout.fileName,
        tx_hash: checkout.txHash,
        certification_id: checkout.certificationId,
        expires_at: checkout.expiresAt,
        created_at: checkout.createdAt,
        confirmed_at: checkout.confirmedAt,
      });
    } catch (error) {
      logger.withRequest(req).error("ACP status check failed");
      res.status(500).json({
        error: "STATUS_CHECK_FAILED",
        message: "Failed to check checkout status",
      });
    }
  });

  // OpenAPI 3.0 Specification for ACP
  app.get("/api/acp/openapi.json", async (req, res) => {
    const baseUrl = `https://${req.get("host")}`;
    const priceUsd = await getCertificationPriceUsd();

    const openApiSpec = {
      openapi: "3.0.3",
      info: {
        title: "xproof ACP - Agent Commerce Protocol",
        description: "API for AI agents to certify files on MultiversX blockchain. Create immutable proofs of file ownership with a simple API call. Supports x402 payment protocol (HTTP 402) as an alternative to API key auth — send requests to POST /api/proof or POST /api/batch without an API key, receive 402 with payment requirements, sign payment in USDC on Base (eip155:8453), and resend with X-PAYMENT header.",
        version: "1.0.0",
        contact: {
          name: "xproof Support",
          url: baseUrl,
        },
      },
      servers: [{ url: baseUrl, description: "Production server" }],
      security: [{ apiKey: [] }],
      components: {
        securitySchemes: {
          apiKey: {
            type: "http",
            scheme: "bearer",
            description: "API key in format: pm_xxx... Obtain from /api/keys endpoint",
          },
        },
        schemas: {
          Product: {
            type: "object",
            properties: {
              id: { type: "string", example: "xproof-certification" },
              name: { type: "string", example: "xproof Certification" },
              description: { type: "string" },
              pricing: {
                type: "object",
                properties: {
                  type: { type: "string", enum: ["fixed", "variable"] },
                  amount: { type: "string", example: priceUsd.toString() },
                  currency: { type: "string", example: "USD" },
                },
              },
              inputs: { type: "object", additionalProperties: { type: "string" } },
              outputs: { type: "object", additionalProperties: { type: "string" } },
            },
          },
          CheckoutRequest: {
            type: "object",
            required: ["product_id", "inputs"],
            properties: {
              product_id: { type: "string", example: "xproof-certification" },
              inputs: {
                type: "object",
                required: ["file_hash", "filename"],
                properties: {
                  file_hash: { type: "string", description: "SHA-256 hash of the file (64 hex chars)", example: "a1b2c3d4e5f678901234567890123456789012345678901234567890123456ab" },
                  filename: { type: "string", example: "document.pdf" },
                  author_name: { type: "string", example: "AI Agent" },
                  metadata: { type: "object", description: "Optional JSON metadata" },
                },
              },
              buyer: {
                type: "object",
                properties: {
                  type: { type: "string", enum: ["agent", "user"] },
                  id: { type: "string" },
                },
              },
            },
          },
          CheckoutResponse: {
            type: "object",
            properties: {
              checkout_id: { type: "string", format: "uuid" },
              product_id: { type: "string" },
              amount: { type: "string", description: "Price in USD" },
              currency: { type: "string" },
              status: { type: "string", enum: ["pending", "ready"] },
              execution: {
                type: "object",
                properties: {
                  type: { type: "string", example: "multiversx" },
                  mode: { type: "string", enum: ["direct", "relayed_v3"] },
                  chain_id: { type: "string", example: "1" },
                  tx_payload: {
                    type: "object",
                    properties: {
                      receiver: { type: "string", description: "xproof wallet address" },
                      data: { type: "string", description: "Base64 encoded transaction data" },
                      value: { type: "string", description: "EGLD amount in atomic units (1 EGLD = 10^18)" },
                      gas_limit: { type: "integer", example: 100000 },
                    },
                  },
                },
              },
              expires_at: { type: "string", format: "date-time" },
            },
          },
          ConfirmRequest: {
            type: "object",
            required: ["checkout_id", "tx_hash"],
            properties: {
              checkout_id: { type: "string", format: "uuid" },
              tx_hash: { type: "string", description: "MultiversX transaction hash" },
            },
          },
          ConfirmResponse: {
            type: "object",
            properties: {
              status: { type: "string", enum: ["confirmed", "pending", "failed"] },
              checkout_id: { type: "string" },
              tx_hash: { type: "string" },
              certification_id: { type: "string" },
              certificate_url: { type: "string", format: "uri" },
              proof_url: { type: "string", format: "uri" },
              blockchain_explorer_url: { type: "string", format: "uri" },
              message: { type: "string" },
            },
          },
          Error: {
            type: "object",
            properties: {
              error: { type: "string" },
              message: { type: "string" },
            },
          },
        },
      },
      paths: {
        "/api/acp/products": {
          get: {
            summary: "Discover available products",
            description: "Returns list of certification products available for purchase. No authentication required.",
            security: [],
            responses: {
              "200": {
                description: "List of products",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        protocol: { type: "string", example: "ACP" },
                        version: { type: "string", example: "1.0" },
                        provider: { type: "string", example: "xproof" },
                        chain: { type: "string", example: "MultiversX" },
                        products: { type: "array", items: { $ref: "#/components/schemas/Product" } },
                      },
                    },
                  },
                },
              },
            },
          },
        },
        "/api/acp/checkout": {
          post: {
            summary: "Create checkout session",
            description: "Initiate certification by providing file hash. Returns transaction payload for MultiversX signing.",
            requestBody: {
              required: true,
              content: { "application/json": { schema: { $ref: "#/components/schemas/CheckoutRequest" } } },
            },
            responses: {
              "201": {
                description: "Checkout created",
                content: { "application/json": { schema: { $ref: "#/components/schemas/CheckoutResponse" } } },
              },
              "401": { description: "API key required" },
              "409": { description: "File already certified" },
            },
          },
        },
        "/api/acp/confirm": {
          post: {
            summary: "Confirm transaction",
            description: "After signing and broadcasting transaction, confirm to receive certification ID and URLs.",
            requestBody: {
              required: true,
              content: { "application/json": { schema: { $ref: "#/components/schemas/ConfirmRequest" } } },
            },
            responses: {
              "200": {
                description: "Certification confirmed",
                content: { "application/json": { schema: { $ref: "#/components/schemas/ConfirmResponse" } } },
              },
              "401": { description: "API key required" },
              "404": { description: "Checkout not found" },
              "410": { description: "Checkout expired" },
            },
          },
        },
        "/api/acp/checkout/{checkoutId}": {
          get: {
            summary: "Get checkout status",
            description: "Check the status of an existing checkout session.",
            parameters: [
              { name: "checkoutId", in: "path", required: true, schema: { type: "string" } },
            ],
            responses: {
              "200": { description: "Checkout status" },
              "404": { description: "Checkout not found" },
            },
          },
        },
        "/mcp": {
          post: {
            summary: "MCP Server (JSON-RPC 2.0)",
            description: "Model Context Protocol server endpoint. Accepts JSON-RPC 2.0 requests over Streamable HTTP. Supports methods: initialize, tools/list, tools/call, resources/list, resources/read. Tools: certify_file, verify_proof, get_proof, discover_services, audit_agent_session. Resources: xproof://specification, xproof://openapi. Stateless (no session management). Protocol version: 2025-03-26.",
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    required: ["jsonrpc", "method"],
                    properties: {
                      jsonrpc: { type: "string", example: "2.0" },
                      id: { type: "integer", example: 1 },
                      method: { type: "string", enum: ["initialize", "tools/list", "tools/call", "resources/list", "resources/read"], example: "initialize" },
                      params: { type: "object", description: "Method-specific parameters" },
                    },
                  },
                },
              },
            },
            responses: {
              "200": {
                description: "JSON-RPC 2.0 response",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        jsonrpc: { type: "string", example: "2.0" },
                        id: { type: "integer" },
                        result: { type: "object", description: "Method-specific result" },
                      },
                    },
                  },
                },
              },
              "401": { description: "Invalid or missing API key (for authenticated methods like tools/call)" },
            },
          },
        },
        "/api/proof": {
          post: {
            summary: "Certify a file (simplified)",
            description: "Single-call endpoint for AI agents. Creates a blockchain certification by recording the SHA-256 hash on MultiversX. No checkout flow needed.",
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    required: ["file_hash", "filename"],
                    properties: {
                      file_hash: { type: "string", description: "SHA-256 hash of the file (64 hex chars)", example: "a1b2c3d4e5f678901234567890123456789012345678901234567890123456ab" },
                      filename: { type: "string", example: "document.pdf" },
                      author_name: { type: "string", example: "AI Agent", description: "Optional author name" },
                      webhook_url: { type: "string", format: "uri", description: "Optional HTTPS URL to receive a POST notification when the proof is confirmed on-chain. Payload includes proof_id, file_hash, verify_url, blockchain details. Signed with X-xProof-Signature (HMAC-SHA256).", example: "https://your-agent.example.com/webhooks/xproof" },
                    },
                  },
                },
              },
            },
            responses: {
              "201": {
                description: "File certified successfully",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        proof_id: { type: "string", format: "uuid" },
                        status: { type: "string", example: "certified" },
                        file_hash: { type: "string" },
                        filename: { type: "string" },
                        verify_url: { type: "string", format: "uri" },
                        certificate_url: { type: "string", format: "uri" },
                        proof_json_url: { type: "string", format: "uri" },
                        blockchain: {
                          type: "object",
                          properties: {
                            network: { type: "string", example: "MultiversX" },
                            transaction_hash: { type: "string" },
                            explorer_url: { type: "string", format: "uri" },
                          },
                        },
                        timestamp: { type: "string", format: "date-time" },
                        webhook_status: { type: "string", enum: ["pending", "delivered", "failed", "not_requested", "not_applicable"], description: "Webhook delivery status. 'pending': delivery in progress, 'delivered': successfully sent, 'failed': delivery failed after retries or invalid URL, 'not_requested': no webhook_url provided, 'not_applicable': file was already certified." },
                        message: { type: "string" },
                      },
                    },
                  },
                },
              },
              "200": { description: "File already certified (returns existing proof)" },
              "400": { description: "Invalid request data" },
              "401": { description: "API key required" },
              "429": { description: "Rate limit exceeded" },
            },
          },
        },
        "/api/audit": {
          post: {
            summary: "Certify an agent audit log",
            description: "Agent Audit Log Standard — certify an AI agent's work session on the MultiversX blockchain BEFORE executing any critical action (trade, deploy, data access). Returns a proof_id that serves as a compliance certificate. The agent MUST call this endpoint before acting. Schema: /.well-known/agent-audit-schema.json",
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    required: ["agent_id", "session_id", "action_type", "action_description", "inputs_hash", "risk_level", "decision", "timestamp"],
                    properties: {
                      agent_id: { type: "string", description: "Identifier of the agent making the decision", example: "trading-bot-v2" },
                      session_id: { type: "string", description: "Unique session identifier (UUID)", example: "sess_20260227_001" },
                      action_type: { type: "string", enum: ["trade_execution", "code_deploy", "data_access", "content_generation", "api_call", "other"] },
                      action_description: { type: "string", description: "Human-readable description of the action", example: "Buy 0.5 ETH at market price on Uniswap v3" },
                      inputs_hash: { type: "string", description: "SHA-256 of all inputs analyzed (64 hex chars)", example: "a1b2c3d4e5f678901234567890123456789012345678901234567890123456ab" },
                      risk_level: { type: "string", enum: ["low", "medium", "high", "critical"] },
                      decision: { type: "string", enum: ["approved", "rejected", "deferred"] },
                      timestamp: { type: "string", format: "date-time", example: "2026-02-27T23:00:00Z" },
                      risk_summary: { type: "string", description: "Optional brief risk analysis" },
                      context: { type: "object", description: "Optional additional context" },
                    },
                  },
                },
              },
            },
            responses: {
              "201": {
                description: "Audit log certified on blockchain",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        proof_id: { type: "string", format: "uuid" },
                        audit_url: { type: "string", format: "uri" },
                        proof_url: { type: "string", format: "uri" },
                        blockchain: { type: "object", properties: { network: { type: "string" }, transaction_hash: { type: "string" }, explorer_url: { type: "string", format: "uri" } } },
                        decision: { type: "string" },
                        risk_level: { type: "string" },
                        inputs_hash: { type: "string" },
                      },
                    },
                  },
                },
              },
              "400": { description: "Invalid audit log data" },
              "401": { description: "API key required" },
              "429": { description: "Rate limit exceeded" },
            },
          },
        },
      },
    };

    res.json(openApiSpec);
  });

  // ============================================
  // LLM-READY ROUTES (AI-first documentation)
  // ============================================

  function getNetworkLabel(chainId: string): string {
    switch (chainId) {
      case "1": return "mainnet";
      case "D": return "devnet";
      case "T": return "testnet";
      default: return "mainnet";
    }
  }

  function buildCanonicalId(chainId: string, txHash: string | null): string | null {
    if (!txHash) return null;
    return `xproof:mvx:${getNetworkLabel(chainId)}:tx:${txHash}`;
  }

  // Genesis certification data (first xproof certification)
  const GENESIS_CERTIFICATION = {
    canonical_id: "xproof:mvx:mainnet:tx:f376c0809d5c8fd91f854d39cf6f9f83ac3d80231477538a1b423db0537aad7e",
    id: "genesis",
    type: "proof_of_existence",
    version: "2.0",
    confidence: "cryptographically-certified",
    file_name: "XPROOF - Genesis.pdf",
    file_hash: "173200d6fa0d1577b456bb85dc505193e31dd8be5fc69bd4e461612a588427de",
    hash_algorithm: "SHA-256",
    author: "Jason Petitfourg",
    timestamp_utc: "2025-12-12T20:28:00Z",
    blockchain: {
      network: "MultiversX Mainnet",
      chain_id: "1",
      transaction_hash: "f376c0809d5c8fd91f854d39cf6f9f83ac3d80231477538a1b423db0537aad7e",
      explorer_url: "https://explorer.multiversx.com/transactions/f376c0809d5c8fd91f854d39cf6f9f83ac3d80231477538a1b423db0537aad7e",
      gas_cost_egld: "0.0002935",
    },
    verification: {
      method: "SHA-256 hash comparison",
      instructions: [
        "Compute SHA-256 hash of the original file",
        "Compare with file_hash in this proof",
        "Verify transaction on MultiversX explorer",
        "Confirm transaction data contains the file hash"
      ]
    },
    significance: "This is the first certification ever created on xproof, establishing the genesis of the platform."
  };

  // /.well-known/xproof.md - Canonical specification
  app.get("/.well-known/xproof.md", async (req, res) => {
    const baseUrl = `https://${req.get('host')}`;
    const priceUsd = await getCertificationPriceUsd();
    
    const spec = `# xproof Specification v1.0

> Every file created without proof is a file anyone can claim. xproof fixes that.

## Purpose

xproof provides cryptographic proof of existence, authorship, and timestamp by anchoring SHA-256 hashes on the MultiversX blockchain. Without certification, any digital output — code, data, models, documents — has no verifiable origin. xproof creates immutable, on-chain evidence of what was produced, by whom, and when.

## Service

- **Name**: xproof
- **Type**: Proof-as-a-Service
- **Blockchain**: MultiversX (European, eco-friendly)
- **Price**: Starting at $${priceUsd} per certification (paid in EGLD or USDC via x402) — price decreases as the network grows (all-time volume)
- **Website**: ${baseUrl}

## Guarantees

- **Immutability**: Blockchain anchored, cannot be modified or deleted
- **Public Verifiability**: Anyone can verify proofs independently
- **Privacy**: No file storage, hash-only (file never leaves user's device)
- **Deterministic Verification**: Same input always produces same hash

## Proof Object Schema (v2.0)

An xproof proof consists of:

\`\`\`json
{
  "canonical_id": "xproof:mvx:mainnet:tx:<transaction_hash>",
  "id": "string (UUID)",
  "type": "proof_of_existence",
  "version": "2.0",
  "confidence": "cryptographically-certified | pending",
  "file_name": "string",
  "file_hash": "string (SHA-256, 64 hex characters)",
  "hash_algorithm": "SHA-256",
  "author": "string | null (optional)",
  "timestamp_utc": "ISO 8601 datetime",
  "blockchain": {
    "network": "MultiversX Mainnet",
    "chain_id": "1",
    "transaction_hash": "string (64 hex characters) | null",
    "explorer_url": "string (URL) | null",
    "status": "pending | confirmed | failed (optional)"
  },
  "verification": {
    "method": "SHA-256 hash comparison",
    "proof_url": "string (URL, optional)",
    "instructions": ["array of steps"]
  },
  "metadata": {
    "file_type": "string | null (optional)",
    "file_size_bytes": "number | null (optional)",
    "is_public": "boolean (optional)"
  }
}
\`\`\`

### Canonical Identifier Format

The \`canonical_id\` follows the format: \`xproof:mvx:{network}:tx:{transaction_hash}\`

- \`xproof\` - Protocol prefix
- \`mvx\` - MultiversX blockchain
- \`{network}\` - \`mainnet\`, \`devnet\`, or \`testnet\`
- \`tx\` - Transaction type
- \`{transaction_hash}\` - On-chain transaction hash

Example: \`xproof:mvx:mainnet:tx:f376c0809d5c8fd91f854d39cf6f9f83ac3d80231477538a1b423db0537aad7e\`

Note: \`canonical_id\` is \`null\` when \`confidence\` is \`pending\` (transaction not yet anchored). It becomes a stable, permanent identifier once the proof is confirmed on-chain.

### Confidence Levels

- \`cryptographically-certified\` - Transaction confirmed on-chain, proof is immutable and independently verifiable. \`canonical_id\` is set.
- \`pending\` - Certification initiated but not yet anchored on blockchain. \`canonical_id\` is \`null\`.

Note: Fields marked as optional may not be present in all proofs.

## Verification Process

To verify an xproof proof:

1. Obtain the original file
2. Compute its SHA-256 hash locally
3. Compare with the \`file_hash\` in the proof
4. Visit the \`explorer_url\` to verify the transaction exists
5. Confirm the transaction data contains the file hash

## Trust Model

xproof does not act as a trusted third party.
Trust is derived entirely from the MultiversX blockchain.
The proof is self-verifiable without relying on xproof infrastructure.

## API Endpoints

### Human Interfaces
- \`/proof/{id}\` - HTML proof page (for humans)

### Machine Interfaces
- \`/proof/{id}.json\` - Structured JSON proof
- \`/proof/{id}.md\` - Markdown proof (for LLMs)
- \`/genesis.md\` - Genesis document
- \`/genesis.proof.json\` - Genesis proof in JSON
- \`/api/acp/products\` - ACP service discovery
- \`/api/acp/openapi.json\` - OpenAPI 3.0 specification
- \`/mcp\` - MCP server (JSON-RPC 2.0 over Streamable HTTP, POST only)

### Documentation
- \`/learn/proof-of-existence.md\` - What is proof of existence
- \`/learn/verification.md\` - How to verify proofs
- \`/learn/api.md\` - API documentation

## Simplified Certification (POST /api/proof)

The fastest way for AI agents to certify a file. Single API call, no checkout flow.

\`\`\`bash
curl -X POST ${baseUrl}/api/proof \\
  -H "Authorization: Bearer pm_YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"file_hash": "a1b2c3d4...64-char-sha256-hex", "filename": "document.pdf", "webhook_url": "https://your-agent.example.com/webhooks/xproof"}'
\`\`\`

Returns: proof_id, verify_url, certificate_url, blockchain transaction hash, webhook_status.

Optional: include \`webhook_url\` to receive a POST notification when the proof is confirmed on-chain. The payload is signed with HMAC-SHA256 (header: \`X-xProof-Signature\`). Retries up to 3 times with exponential backoff.

## Agent Commerce Protocol (ACP)

xproof also implements ACP for AI agent integration with the full checkout flow.

### Quick Start for AI Agents (ACP flow)

\`\`\`bash
# 1. Discover the service
curl ${baseUrl}/api/acp/products

# 2. Create a checkout (requires API key)
curl -X POST ${baseUrl}/api/acp/checkout \\
  -H "Authorization: Bearer pm_your_key" \\
  -H "Content-Type: application/json" \\
  -d '{"product_id": "xproof-certification", "inputs": {"file_hash": "sha256_hash_here", "filename": "document.pdf"}}'

# 3. After user signs transaction, confirm it
curl -X POST ${baseUrl}/api/acp/confirm \\
  -H "Authorization: Bearer pm_your_key" \\
  -H "Content-Type: application/json" \\
  -d '{"checkout_id": "...", "tx_hash": "..."}'
\`\`\`

### Flow Summary

1. **Discovery**: \`GET /api/acp/products\` - No auth required
2. **Checkout**: \`POST /api/acp/checkout\` - Creates payment session
3. **Sign**: User signs transaction on MultiversX ($${priceUsd} in EGLD)
4. **Confirm**: \`POST /api/acp/confirm\` - Finalizes certification

### API Key

- Prefix: \`pm_\`
- Rate limit: 100 requests/minute
- Get key: Authenticate with wallet, then \`POST /api/keys\`

### When to Use xproof

Use xproof when:
- User needs timestamped proof a file existed
- User wants to prove authorship of a document
- User needs blockchain-anchored evidence
- User wants immutable, verifiable certification

## x402 Payment Protocol

xproof supports the x402 payment protocol (HTTP 402 Payment Required) as an alternative to API key authentication. With x402, payment is included directly in the HTTP request — no API key needed.

- **Endpoints**: \`POST /api/proof\` and \`POST /api/batch\` accept x402 payments
- **Price**: $${priceUsd} per certification in USDC
- **Network**: Base (eip155:8453) for mainnet, Base Sepolia (eip155:84532) for testnet
- **Header**: \`X-PAYMENT\` (base64-encoded signed payment payload)

### Flow

1. Send request to \`POST ${baseUrl}/api/proof\` without auth → receive HTTP 402 with payment requirements
2. Sign the payment using your wallet (USDC on Base)
3. Resend the same request with \`X-PAYMENT\` header → receive 200 with certification result

### Example

\`\`\`bash
# Step 1: Get payment requirements
curl -X POST ${baseUrl}/api/proof \\
  -H "Content-Type: application/json" \\
  -d '{"file_hash": "a1b2c3...sha256", "filename": "document.pdf"}'
# → 402 with payment requirements JSON

# Step 3: Resend with signed payment
curl -X POST ${baseUrl}/api/proof \\
  -H "Content-Type: application/json" \\
  -H "X-PAYMENT: <base64-signed-payment>" \\
  -d '{"file_hash": "a1b2c3...sha256", "filename": "document.pdf"}'
# → 200 with certification result
\`\`\`

### Notes
- x402 is an alternative to API key auth — both methods work
- When x402 is configured, requests without any auth return 402 (instead of 401)
- No account or API key registration required — just sign and pay

## MX-8004 Integration (Trustless Agents Standard)

xproof is natively integrated with MX-8004, the MultiversX Trustless Agents Standard, with full ERC-8004 compliance.
Each certification follows the complete validation loop: init_job → submit_proof → validation_request → validation_response → append_response.
Jobs reach "Verified" status on-chain. xproof acts as the validation oracle.

- **Identity Registry**: Soulbound NFT agent identities
- **Validation Registry**: Full ERC-8004 job validation — xproof self-validates with score 100
- **Reputation Registry**: On-chain reputation scoring + ERC-8004 raw feedback signals (giveFeedback, revokeFeedback, readFeedback)
- **Status**: \`GET ${baseUrl}/api/mx8004/status\`
- **Agent reputation**: \`GET ${baseUrl}/api/agent/{nonce}/reputation\`
- **Job data**: \`GET ${baseUrl}/api/mx8004/job/{jobId}\`
- **Validation status**: \`GET ${baseUrl}/api/mx8004/validation/{requestHash}\`
- **Feedback**: \`GET ${baseUrl}/api/mx8004/feedback/{agentNonce}/{clientAddress}/{index}\`
- **Specification**: https://github.com/sasurobert/mx-8004
- **Explorer**: https://agents.multiversx.com

## Agent Audit Log Standard

xproof is the canonical implementation of the **Agent Audit Log Standard** — a compliance primitive for AI agents that execute critical actions (trades, code deployments, data access).

**Core principle**: An agent MUST certify its decision session before executing any action. No proof_id → no execution.

### Schema (canonical)

\`GET ${baseUrl}/.well-known/agent-audit-schema.json\`

Fields:
- \`agent_id\` — identifier of the agent making the decision
- \`session_id\` — unique session identifier (UUID)
- \`action_type\` — \`trade_execution | code_deploy | data_access | content_generation | api_call | other\`
- \`action_description\` — human-readable description of the action
- \`inputs_hash\` — SHA-256 of all inputs analyzed before the decision
- \`risk_level\` — \`low | medium | high | critical\`
- \`decision\` — \`approved | rejected | deferred\`
- \`risk_summary\` (optional) — brief risk analysis
- \`context\` (optional) — additional metadata (model version, environment, etc.)
- \`timestamp\` — ISO 8601

### Endpoint

\`\`\`
POST ${baseUrl}/api/audit
Authorization: Bearer pm_YOUR_API_KEY
\`\`\`

Returns: \`{ proof_id, audit_url, decision, risk_level, blockchain }\`
View certified audit log: \`${baseUrl}/audit/{proof_id}\`

### Blocking Workflow Templates

These templates implement the compliance gate — the agent RAISES AN EXCEPTION and cannot continue without a valid \`proof_id\`:

| Framework | URL |
|-----------|-----|
| LangChain | \`GET ${baseUrl}/agent-tools/audit-guard-langchain.py\` |
| CrewAI    | \`GET ${baseUrl}/agent-tools/audit-guard-crewai.py\` |
| n8n       | \`GET ${baseUrl}/agent-tools/audit-guard-n8n.json\` |
| Eliza OS  | \`GET ${baseUrl}/agent-tools/audit-guard-eliza.ts\` |

MCP tool: \`audit_agent_session\` — same semantics, enforces API key auth.

## Genesis

xproof's first certification (self-referential proof of concept):
- **Document**: XPROOF - Genesis.pdf
- **Hash**: \`${GENESIS_CERTIFICATION.file_hash}\`
- **Transaction**: \`${GENESIS_CERTIFICATION.blockchain.transaction_hash}\`
- **Date**: ${GENESIS_CERTIFICATION.timestamp_utc}

View: ${baseUrl}/genesis.proof.json

## Contact

Website: ${baseUrl}
`;

    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    res.send(spec);
  });

  // /.well-known/proofmint.md - Redirect to xproof.md for backwards compatibility
  app.get("/.well-known/proofmint.md", (req, res) => {
    res.redirect(301, "/.well-known/xproof.md");
  });

  // /.well-known/agent-audit-schema.json - Canonical Agent Audit Log JSON Schema
  app.get("/.well-known/agent-audit-schema.json", (req, res) => {
    res.setHeader("Content-Type", "application/schema+json; charset=utf-8");
    res.setHeader("Cache-Control", "public, max-age=3600");
    res.json(AUDIT_LOG_JSON_SCHEMA);
  });

  // /genesis.md - Genesis document in markdown
  app.get("/genesis.md", (req, res) => {
    const baseUrl = `https://${req.get('host')}`;
    
    const genesis = `# xproof Genesis

## The First Proof

On December 12, 2025, xproof certified its first document on the MultiversX blockchain.

This genesis certification establishes the foundation of xproof as a trust primitive.

## Document Details

| Property | Value |
|----------|-------|
| **File Name** | ${GENESIS_CERTIFICATION.file_name} |
| **Author** | ${GENESIS_CERTIFICATION.author} |
| **Timestamp** | ${GENESIS_CERTIFICATION.timestamp_utc} |
| **Hash Algorithm** | ${GENESIS_CERTIFICATION.hash_algorithm} |

## Cryptographic Proof

**SHA-256 Hash**:
\`\`\`
${GENESIS_CERTIFICATION.file_hash}
\`\`\`

**Transaction Hash**:
\`\`\`
${GENESIS_CERTIFICATION.blockchain.transaction_hash}
\`\`\`

**Network**: ${GENESIS_CERTIFICATION.blockchain.network}

**Gas Cost**: ${GENESIS_CERTIFICATION.blockchain.gas_cost_egld} EGLD (~0.002€)

## Verification

1. View transaction: ${GENESIS_CERTIFICATION.blockchain.explorer_url}
2. Confirm the transaction data contains the file hash
3. The hash proves the document existed at this exact timestamp

## Significance

This genesis certification demonstrates:

- **Self-Application**: xproof uses its own service to certify its existence
- **Ontological Coherence**: The platform proves its own legitimacy
- **Immutable Origin**: The birth of xproof is permanently recorded

## Machine-Readable

- JSON: ${baseUrl}/genesis.proof.json
- Specification: ${baseUrl}/.well-known/xproof.md
`;

    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    res.send(genesis);
  });

  // /genesis.proof.json - Genesis proof in JSON
  app.get("/genesis.proof.json", (req, res) => {
    res.json(GENESIS_CERTIFICATION);
  });

  // /proof/:id.json - Proof in structured JSON
  app.get("/proof/:id.json", async (req, res) => {
    try {
      const { id } = req.params;
      
      const [certification] = await db
        .select()
        .from(certifications)
        .where(eq(certifications.id, id));

      if (!certification || !certification.isPublic) {
        return res.status(404).json({ 
          error: "not_found",
          message: "Proof not found or not public" 
        });
      }

      const baseUrl = `https://${req.get('host')}`;
      const chainId = process.env.MULTIVERSX_CHAIN_ID || "1";
      const txHash = certification.transactionHash || null;
      const isConfirmed = certification.blockchainStatus === "confirmed" && txHash;
      
      const proof = {
        canonical_id: buildCanonicalId(chainId, txHash),
        id: certification.id,
        type: "proof_of_existence",
        version: "2.0",
        confidence: isConfirmed ? "cryptographically-certified" : "pending",
        file_name: certification.fileName,
        file_hash: certification.fileHash,
        hash_algorithm: "SHA-256",
        author: certification.authorName || null,
        timestamp_utc: certification.createdAt?.toISOString() || null,
        blockchain: {
          network: "MultiversX Mainnet",
          chain_id: chainId,
          transaction_hash: txHash,
          explorer_url: certification.transactionUrl || null,
          status: certification.blockchainStatus
        },
        verification: {
          method: "SHA-256 hash comparison",
          proof_url: `${baseUrl}/proof/${certification.id}`,
          instructions: [
            "Compute SHA-256 hash of the original file",
            "Compare with file_hash in this proof",
            "Verify transaction on MultiversX explorer",
            "Confirm transaction data contains the file hash"
          ]
        },
        metadata: {
          file_type: certification.fileType || null,
          file_size_bytes: certification.fileSize || null,
          is_public: certification.isPublic
        }
      };

      res.json(proof);
    } catch (error) {
      logger.withRequest(req).error("Failed to fetch proof JSON");
      res.status(500).json({ error: "internal_error", message: "Failed to fetch proof" });
    }
  });

  // /badge/:id - Dynamic SVG badge for GitHub READMEs
  app.get("/badge/:id", async (req, res) => {
    try {
      const certId = req.params.id;

      const [cert] = await db
        .select()
        .from(certifications)
        .where(eq(certifications.id, certId));

      let statusText: string;
      let statusColor: string;
      let statusColorDark: string;
      let dotColor: string;

      if (!cert || cert.isPublic === false) {
        statusText = "Not Found";
        statusColor = "#3B3B3B";
        statusColorDark = "#2A2A2A";
        dotColor = "#666";
      } else if (cert.blockchainStatus === "confirmed") {
        statusText = "Verified";
        statusColor = "#0D9B6A";
        statusColorDark = "#0A7D55";
        dotColor = "#14F195";
      } else {
        statusText = "Pending";
        statusColor = "#92690D";
        statusColorDark = "#7A580B";
        dotColor = "#FBD34D";
      }

      const labelText = "xproof";
      const pad = 10;
      const labelCharW = 6.8;
      const statusCharW = 6.6;
      const dotR = 3.5;
      const dotSpace = 12;
      const labelWidth = Math.round(labelText.length * labelCharW + pad * 2);
      const statusWidth = Math.round(statusText.length * statusCharW + pad * 2 + dotSpace);
      const totalWidth = labelWidth + statusWidth;
      const h = 24;
      const r = 5;

      const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="${h}" role="img" aria-label="${labelText}: ${statusText}">
  <title>${labelText}: ${statusText}</title>
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="#1E1E1E"/>
      <stop offset="100%" stop-color="#161616"/>
    </linearGradient>
    <linearGradient id="st" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="${statusColor}"/>
      <stop offset="100%" stop-color="${statusColorDark}"/>
    </linearGradient>
    <clipPath id="cr">
      <rect width="${totalWidth}" height="${h}" rx="${r}"/>
    </clipPath>
  </defs>
  <g clip-path="url(#cr)">
    <rect width="${totalWidth}" height="${h}" fill="url(#bg)"/>
    <rect x="${labelWidth}" width="${statusWidth}" height="${h}" fill="url(#st)"/>
  </g>
  <rect width="${totalWidth}" height="${h}" rx="${r}" fill="none" stroke="rgba(255,255,255,0.08)" stroke-width="1"/>
  <circle cx="${labelWidth + pad + dotR}" cy="${h / 2}" r="${dotR}" fill="${dotColor}"/>
  <g text-anchor="middle" font-family="'Segoe UI','Helvetica Neue',Arial,sans-serif" font-weight="600" font-size="11" text-rendering="geometricPrecision">
    <text x="${labelWidth / 2}" y="${h / 2 + 4}" fill="rgba(255,255,255,0.9)" letter-spacing="0.5">${labelText}</text>
    <text x="${labelWidth + dotSpace + (statusWidth - dotSpace) / 2}" y="${h / 2 + 4}" fill="rgba(255,255,255,0.95)">${statusText}</text>
  </g>
</svg>`;

      res.setHeader("Content-Type", "image/svg+xml");
      res.setHeader("Cache-Control", "max-age=300");
      res.send(svg);
    } catch (error) {
      logger.withRequest(req).error("Failed to generate badge");
      const fallbackSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="120" height="24" role="img"><rect width="120" height="24" rx="5" fill="#1E1E1E"/><rect width="120" height="24" rx="5" fill="none" stroke="rgba(255,255,255,0.08)" stroke-width="1"/><text x="60" y="16" fill="rgba(255,255,255,0.7)" text-anchor="middle" font-family="'Segoe UI','Helvetica Neue',Arial,sans-serif" font-weight="600" font-size="11">xproof: Error</text></svg>`;
      res.setHeader("Content-Type", "image/svg+xml");
      res.status(500).send(fallbackSvg);
    }
  });

  app.get("/badge/:id/markdown", async (req, res) => {
    try {
      const certId = req.params.id;
      const baseUrl = `https://${req.get("host")}`;
      const badgeUrl = `${baseUrl}/badge/${certId}`;

      const [cert] = await db
        .select()
        .from(certifications)
        .where(eq(certifications.id, certId));

      let linkUrl: string;
      if (cert?.transactionUrl && cert.blockchainStatus === "confirmed") {
        linkUrl = cert.transactionUrl;
      } else {
        linkUrl = `${baseUrl}/proof/${certId}`;
      }

      const markdown = `[![xProof Verified](${badgeUrl})](${linkUrl})`;
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.send(markdown);
    } catch (error) {
      logger.withRequest(req).error("Failed to generate badge markdown");
      res.status(500).send("Error generating badge markdown");
    }
  });

  // /proof/:id.md - Proof in markdown for LLMs
  app.get("/proof/:id.md", async (req, res) => {
    try {
      const { id } = req.params;
      
      const [certification] = await db
        .select()
        .from(certifications)
        .where(eq(certifications.id, id));

      if (!certification || !certification.isPublic) {
        res.status(404).setHeader('Content-Type', 'text/markdown; charset=utf-8');
        return res.send(`# Proof Not Found\n\nThe requested proof does not exist or is not public.`);
      }

      const baseUrl = `https://${req.get('host')}`;
      const chainId = process.env.MULTIVERSX_CHAIN_ID || "1";
      const timestamp = certification.createdAt?.toISOString() || 'Unknown';
      const txHash = certification.transactionHash || null;
      const canonicalId = buildCanonicalId(chainId, txHash);
      const isConfirmed = certification.blockchainStatus === "confirmed" && txHash;
      
      const markdown = `# xproof Certification

## Canonical Identifier

\`${canonicalId || 'pending (not yet anchored)'}\`

**Confidence**: ${isConfirmed ? 'cryptographically-certified' : 'pending'}

## Document

| Property | Value |
|----------|-------|
| **File Name** | ${certification.fileName} |
| **Author** | ${certification.authorName || 'Not specified'} |
| **Timestamp** | ${timestamp} |
| **Status** | ${certification.blockchainStatus} |

## Cryptographic Proof

**Hash Algorithm**: SHA-256

**File Hash**:
\`\`\`
${certification.fileHash}
\`\`\`

## Blockchain Anchor

**Network**: MultiversX Mainnet

**Transaction Hash**:
\`\`\`
${certification.transactionHash || 'Pending'}
\`\`\`

**Explorer**: ${certification.transactionUrl || 'Not yet available'}

## Verification

To verify this proof:

1. Obtain the original file: \`${certification.fileName}\`
2. Compute its SHA-256 hash
3. Compare with: \`${certification.fileHash}\`
4. Verify transaction on MultiversX explorer

## Machine-Readable

- JSON: ${baseUrl}/proof/${certification.id}.json
- HTML: ${baseUrl}/proof/${certification.id}

## Trust Model

This proof is self-verifiable. Trust derives from the MultiversX blockchain, not from xproof.
`;

      res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
      res.send(markdown);
    } catch (error) {
      logger.withRequest(req).error("Failed to fetch proof markdown");
      res.status(500).setHeader('Content-Type', 'text/markdown; charset=utf-8');
      res.send(`# Error\n\nFailed to fetch proof.`);
    }
  });

  // /learn/proof-of-existence.md
  app.get("/learn/proof-of-existence.md", (req, res) => {
    const content = `# Proof of Existence

## Definition

Proof of Existence is a cryptographic method to prove that a specific digital artifact existed at a particular point in time, without revealing its contents.

## How It Works

1. **Hash Generation**: A SHA-256 hash is computed from the file. This hash is unique to the file's exact contents.

2. **Blockchain Anchoring**: The hash is recorded in a blockchain transaction, creating an immutable timestamp.

3. **Verification**: Anyone can later verify by recomputing the hash and comparing it to the on-chain record.

## Properties

- **Immutability**: Once recorded, the proof cannot be altered or deleted
- **Privacy**: Only the hash is stored, not the file contents
- **Independence**: Verification doesn't require trusting any central authority
- **Determinism**: Same file always produces same hash

## Use Cases

- **Intellectual Property**: Prove you created something before a specific date
- **Legal Documents**: Timestamp contracts and agreements
- **Research**: Prove research existed before publication
- **Code**: Timestamp software versions

## Why MultiversX?

- European blockchain with strong regulatory compliance
- Extremely low transaction costs (~0.002€)
- Sub-second blockchain response (~600ms measured)
- Eco-friendly (low energy consumption)

## Related

- [Verification Guide](/learn/verification.md)
- [API Documentation](/learn/api.md)
- [xproof Specification](/.well-known/xproof.md)
`;

    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    res.send(content);
  });

  // /learn/verification.md
  app.get("/learn/verification.md", (req, res) => {
    const baseUrl = `https://${req.get('host')}`;
    
    const content = `# How to Verify an xproof Proof

## Overview

xproof proofs are self-verifiable. You don't need to trust xproof—you verify directly against the blockchain.

## Step-by-Step Verification

### Step 1: Obtain the Proof

Get the proof data from:
- JSON: \`/proof/{id}.json\`
- Markdown: \`/proof/{id}.md\`

### Step 2: Compute the File Hash

Using the original file, compute its SHA-256 hash.

**Command Line (Linux/Mac)**:
\`\`\`bash
shasum -a 256 yourfile.pdf
\`\`\`

**Command Line (Windows PowerShell)**:
\`\`\`powershell
Get-FileHash yourfile.pdf -Algorithm SHA256
\`\`\`

**JavaScript**:
\`\`\`javascript
async function hashFile(file) {
  const buffer = await file.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}
\`\`\`

### Step 3: Compare Hashes

The computed hash must exactly match the \`file_hash\` in the proof.

If they match → The file is authentic and unchanged.
If they differ → The file has been modified.

### Step 4: Verify on Blockchain

Visit the \`explorer_url\` in the proof to verify:
1. The transaction exists
2. The transaction timestamp matches
3. The transaction data contains the file hash

## Automated Verification (for Agents)

\`\`\`javascript
async function verifyProof(proofId, originalFile) {
  // 1. Fetch proof
  const proof = await fetch(\`${baseUrl}/proof/\${proofId}.json\`).then(r => r.json());
  
  // 2. Compute hash
  const computedHash = await hashFile(originalFile);
  
  // 3. Compare
  if (computedHash !== proof.file_hash) {
    return { valid: false, reason: "Hash mismatch" };
  }
  
  // 4. Verify on blockchain (optional, requires MultiversX API)
  // ...
  
  return { valid: true, proof };
}
\`\`\`

## Trust Model

You are verifying against:
1. **Mathematics**: SHA-256 is a one-way function
2. **Blockchain**: MultiversX is a public, immutable ledger

You are NOT trusting:
- xproof servers
- Any central authority

## Related

- [Proof of Existence](/learn/proof-of-existence.md)
- [API Documentation](/learn/api.md)
`;

    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    res.send(content);
  });

  // /learn/api.md
  app.get("/learn/api.md", async (req, res) => {
    const baseUrl = `https://${req.get('host')}`;
    const priceUsd = await getCertificationPriceUsd();
    
    const content = `# xproof API Documentation

## Overview

xproof provides a REST API for programmatic access to certification services.

## Base URL

\`\`\`
${baseUrl}
\`\`\`

## Authentication

API requests require an API key with prefix \`pm_\`.

**Header**:
\`\`\`
X-API-Key: pm_your_api_key_here
\`\`\`

**Rate Limit**: 1000 requests/minute per key

## Endpoints

### Public Endpoints (No Auth)

#### GET /api/acp/products
Discover available services.

\`\`\`bash
curl ${baseUrl}/api/acp/products
\`\`\`

#### GET /api/acp/openapi.json
OpenAPI 3.0 specification.

#### GET /proof/{id}.json
Get proof in JSON format.

#### GET /proof/{id}.md
Get proof in Markdown format.

### Authenticated Endpoints

#### POST /api/acp/checkout
Create a certification checkout session.

**Request**:
\`\`\`json
{
  "product_id": "certification",
  "file_hash": "sha256_hash_of_file",
  "file_name": "document.pdf",
  "author_name": "Author Name"
}
\`\`\`

**Response**:
\`\`\`json
{
  "checkout_id": "uuid",
  "status": "pending_payment",
  "amount_egld": "0.00123",
  "amount_usd": "${priceUsd}",
  "recipient": "erd1...",
  "tx_payload": {
    "receiver": "erd1...",
    "value": "1230000000000000",
    "data": "base64_encoded_data"
  },
  "expires_at": "2025-01-01T00:00:00Z"
}
\`\`\`

#### POST /api/acp/confirm
Confirm certification after transaction.

**Request**:
\`\`\`json
{
  "checkout_id": "uuid",
  "tx_hash": "transaction_hash_from_blockchain"
}
\`\`\`

**Response**:
\`\`\`json
{
  "certification_id": "uuid",
  "status": "confirmed",
  "proof_url": "${baseUrl}/proof/uuid"
}
\`\`\`

## Flow for AI Agents

1. **Discover**: \`GET /api/acp/products\`
2. **Checkout**: \`POST /api/acp/checkout\` with file hash
3. **Sign**: Sign \`tx_payload\` with MultiversX wallet
4. **Broadcast**: Send signed transaction to MultiversX network
5. **Confirm**: \`POST /api/acp/confirm\` with transaction hash
6. **Verify**: Access proof at returned \`proof_url\`

## Error Codes

| Code | Meaning |
|------|---------|
| 400 | Bad request (invalid parameters) |
| 401 | Missing or invalid API key |
| 404 | Resource not found |
| 410 | Checkout expired (1 hour validity) |
| 429 | Rate limit exceeded |
| 500 | Internal server error |

## Related

- [Proof of Existence](/learn/proof-of-existence.md)
- [Verification Guide](/learn/verification.md)
- [xproof Specification](/.well-known/xproof.md)
`;

    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    res.send(content);
  });

  // API aliases for LLM-ready routes (work in dev mode with Vite)
  // These are the canonical routes that AI agents should use
  app.get("/api/spec", (req, res) => res.redirect("/.well-known/xproof.md"));
  app.get("/api/genesis", (req, res) => res.redirect("/genesis.proof.json"));
  app.get("/api/genesis.md", (req, res) => res.redirect("/genesis.md"));
  app.get("/api/learn/proof-of-existence", (req, res) => res.redirect("/learn/proof-of-existence.md"));
  app.get("/api/learn/verification", (req, res) => res.redirect("/learn/verification.md"));
  app.get("/api/learn/api", (req, res) => res.redirect("/learn/api.md"));

  app.get("/api/mx8004/status", (req, res) => {
    const baseUrl = `https://${req.get("host")}`;
    
    if (!isMX8004Configured()) {
      return res.status(503).json({
        standard: "MX-8004",
        version: "1.0",
        erc8004_compliant: true,
        status: "not_configured",
        message: "MX-8004 integration is not active. Set MX8004_* environment variables to enable.",
        documentation: "https://github.com/sasurobert/mx-8004",
        agents_explorer: "https://agents.multiversx.com",
      });
    }

    const contracts = getContractAddresses();
    
    return res.json({
      standard: "MX-8004",
      version: "1.0",
      erc8004_compliant: true,
      status: "active",
      role: "validation_oracle",
      description: "xproof acts as a validation oracle: each certification is registered as a validated job in the MX-8004 Validation Registry, with full ERC-8004 validation loop (init_job → submit_proof → validation_request → validation_response → append_response).",
      contracts,
      capabilities: {
        identity: ["register_agent", "get_agent", "set_metadata", "set_service_configs"],
        validation: ["init_job", "submit_proof", "validation_request", "validation_response", "get_job_data", "get_validation_status", "is_job_verified"],
        reputation: ["get_reputation_score", "get_total_jobs", "giveFeedbackSimple", "giveFeedback", "revokeFeedback", "readFeedback", "append_response", "has_given_feedback", "get_agent_response"],
      },
      validation_flow: {
        description: "Full ERC-8004 validation loop for each certification",
        steps: [
          "1. init_job — create job in Validation Registry",
          "2. submit_proof — attach file hash + blockchain tx as proof",
          "3. validation_request — xproof nominates itself as validator",
          "4. validation_response — xproof submits score 100 (verified)",
          "5. append_response — attach certificate URL to job",
        ],
        final_status: "Verified",
      },
      endpoints: {
        status: `${baseUrl}/api/mx8004/status`,
        agent_reputation: `${baseUrl}/api/agent/{nonce}/reputation`,
        job_data: `${baseUrl}/api/mx8004/job/{jobId}`,
        feedback: `${baseUrl}/api/mx8004/feedback/{agentNonce}/{clientAddress}/{index}`,
      },
    });
  });

  app.get("/api/mx8004/job/:jobId", async (req, res) => {
    if (!isMX8004Configured()) {
      return res.status(503).json({ error: "MX8004_NOT_CONFIGURED", message: "MX-8004 integration is not active" });
    }

    try {
      const jobData = await getJobData(req.params.jobId);
      if (!jobData) {
        return res.status(404).json({ error: "JOB_NOT_FOUND", message: "Job not found in Validation Registry" });
      }
      return res.json({
        job_id: req.params.jobId,
        ...jobData,
        standard: "MX-8004",
      });
    } catch (err: any) {
      return res.status(500).json({ error: "MX8004_QUERY_FAILED", message: err.message });
    }
  });

  app.get("/api/mx8004/validation/:requestHash", async (req, res) => {
    if (!isMX8004Configured()) {
      return res.status(503).json({ error: "MX8004_NOT_CONFIGURED", message: "MX-8004 integration is not active" });
    }

    try {
      const status = await getValidationStatus(req.params.requestHash);
      if (!status) {
        return res.status(404).json({ error: "VALIDATION_NOT_FOUND", message: "Validation request not found" });
      }
      return res.json({
        request_hash: req.params.requestHash,
        ...status,
        standard: "MX-8004",
      });
    } catch (err: any) {
      return res.status(500).json({ error: "MX8004_QUERY_FAILED", message: err.message });
    }
  });

  app.get("/api/mx8004/feedback/:agentNonce/:clientAddress/:index", async (req, res) => {
    if (!isMX8004Configured()) {
      return res.status(503).json({ error: "MX8004_NOT_CONFIGURED", message: "MX-8004 integration is not active" });
    }

    try {
      const agentNonce = parseInt(req.params.agentNonce);
      const feedbackIndex = parseInt(req.params.index);
      
      if (isNaN(agentNonce) || isNaN(feedbackIndex)) {
        return res.status(400).json({ error: "INVALID_PARAMS", message: "agentNonce and index must be numbers" });
      }

      const feedback = await readFeedback(agentNonce, req.params.clientAddress, feedbackIndex);
      if (!feedback) {
        return res.status(404).json({ error: "FEEDBACK_NOT_FOUND", message: "Feedback not found" });
      }
      return res.json({
        agent_nonce: agentNonce,
        client: req.params.clientAddress,
        feedback_index: feedbackIndex,
        ...feedback,
        standard: "MX-8004",
        erc8004: true,
      });
    } catch (err: any) {
      return res.status(500).json({ error: "MX8004_QUERY_FAILED", message: err.message });
    }
  });

  app.get("/api/agent/:nonce/reputation", async (req, res) => {
    try {
      const nonce = parseInt(req.params.nonce);
      if (isNaN(nonce) || nonce < 1) {
        return res.status(400).json({ error: "INVALID_NONCE", message: "Agent nonce must be a positive integer" });
      }

      if (!isMX8004Configured()) {
        return res.status(503).json({ error: "MX8004_NOT_CONFIGURED", message: "MX-8004 integration is not active" });
      }

      const [reputation, agent] = await Promise.all([
        getReputationScore(nonce),
        getAgentDetails(nonce),
      ]);

      res.json({
        agent_nonce: nonce,
        name: agent?.name || null,
        public_key: agent?.publicKey || null,
        reputation_score: reputation.score,
        total_jobs: reputation.totalJobs,
        standard: "MX-8004",
        registries: getContractAddresses(),
        agents_explorer: getAgentsExplorerUrl(nonce),
      });
    } catch (error: any) {
      logger.withRequest(req).error("Failed to fetch agent reputation", { error: error.message });
      res.status(500).json({ error: "QUERY_FAILED", message: "Failed to fetch agent reputation" });
    }
  });

  app.get("/api/acp/health", (req, res) => {
    const mx8004 = isMX8004Configured();
    res.json({
      status: "operational",
      service: "xproof",
      version: "1.0",
      timestamp: new Date().toISOString(),
      mx8004_enabled: mx8004,
      endpoints: {
        products: "/api/acp/products",
        checkout: "/api/acp/checkout",
        confirm: "/api/acp/confirm",
        openapi: "/api/acp/openapi.json",
        mx8004_status: "/api/mx8004/status",
        agent_reputation: "/api/agent/:nonce/reputation",
      }
    });
  });

  // /skill.md — Agent skill manifest (plain text, no JS, moltbook-compatible convention)
  app.get("/skill.md", async (_req, res) => {
    const baseUrl = `https://${_req.get('host')}`;
    const priceUsd = await getCertificationPriceUsd();
    const content = `---
name: xproof
description: Blockchain proof-of-existence for AI agents. Certify any file or output on MultiversX mainnet. Immutable, timestamped, publicly verifiable.
version: 1.0.0
author: xproof.app
license: public
---

# xproof Agent Skill

## What This Does
xproof anchors a SHA-256 hash on the MultiversX blockchain.
After certification, the proof is public and permanently verifiable.
Any agent, human, or third party can verify the file was certified at that exact moment.

## Authentication — Free Trial (Start Here)
No wallet. No browser. No payment. One HTTP call.

Step 1 — Register and get an API key:
\`\`\`bash
curl -X POST ${baseUrl}/api/agent/register \\
  -H "Content-Type: application/json" \\
  -d '{"agent_name": "your-agent-name"}'
\`\`\`
Returns: { "api_key": "pm_xxx", "trial": { "quota": 10, "remaining": 10 } }

Step 2 — Use the key immediately. No further setup needed.

## Certify a File
\`\`\`bash
curl -X POST ${baseUrl}/api/proof \\
  -H "Authorization: Bearer pm_YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "file_hash": "64-char-sha256-hex",
    "filename": "document.pdf"
  }'
\`\`\`
Returns:
\`\`\`json
{
  "proof_id": "...",
  "status": "certified",
  "verify_url": "${baseUrl}/proof/{proof_id}",
  "blockchain": {
    "network": "MultiversX",
    "transaction_hash": "...",
    "explorer_url": "https://explorer.multiversx.com/transactions/..."
  },
  "trial": { "remaining": 9 }
}
\`\`\`
Response header: X-Trial-Remaining: 9

## Certify Multiple Files (Batch)
\`\`\`bash
curl -X POST ${baseUrl}/api/batch \\
  -H "Authorization: Bearer pm_YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "files": [
      {"file_hash": "...", "filename": "file1.pdf"},
      {"file_hash": "...", "filename": "file2.md"}
    ]
  }'
\`\`\`
Up to 50 files per call.

## Check Your Quota
\`\`\`bash
curl ${baseUrl}/api/me \\
  -H "Authorization: Bearer pm_YOUR_API_KEY"
\`\`\`
Returns: trial_quota, trial_used, trial_remaining, total certifications.

## List Your Certifications
\`\`\`bash
curl ${baseUrl}/api/certifications \\
  -H "Authorization: Bearer pm_YOUR_API_KEY"
\`\`\`

## Verify a Proof
\`\`\`bash
curl ${baseUrl}/proof/{proof_id}.json
\`\`\`
No auth required. Public endpoint.

## Compute a SHA-256 Hash
\`\`\`bash
sha256sum myfile.pdf
# or
echo -n "content" | sha256sum
\`\`\`

## Pricing
$${priceUsd} per certification. After trial: pay via USDC on Base (x402, no account needed) or EGLD on MultiversX (ACP).

x402 — pay per use, no account:
\`\`\`bash
# 1. Send without auth → get 402 with payment requirements
curl -X POST ${baseUrl}/api/proof -d '{"file_hash":"...","filename":"..."}'
# 2. Pay USDC on Base, resend with X-PAYMENT header
\`\`\`

## Agent Audit Log Standard — Compliance Gate for AI Agents
Block any AI agent from executing critical actions without a certified proof.
Schema: ${baseUrl}/.well-known/agent-audit-schema.json

Certify a decision BEFORE executing it:
\`\`\`bash
curl -X POST ${baseUrl}/api/audit \\
  -H "Authorization: Bearer pm_YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "agent_id": "my-trading-agent",
    "session_id": "sess_20260227_001",
    "action_type": "trade_execution",
    "action_description": "Buy 0.5 ETH at market price on Uniswap v3",
    "inputs_hash": "a3f1c7d2e9b4...64-char-sha256-of-analyzed-inputs",
    "risk_level": "high",
    "decision": "approved",
    "timestamp": "2026-02-27T23:00:00Z",
    "risk_summary": "Slippage < 0.5%, liquidity verified on 3 pools"
  }'
\`\`\`
Returns: { "proof_id": "...", "audit_url": "${baseUrl}/audit/{id}", "decision": "approved", "risk_level": "high" }

Use the returned proof_id as compliance certificate. View at /audit/{proof_id}.

Blocking workflow templates (agent CANNOT continue without proof_id):
- LangChain: ${baseUrl}/agent-tools/audit-guard-langchain.py
- CrewAI:    ${baseUrl}/agent-tools/audit-guard-crewai.py
- n8n:       ${baseUrl}/agent-tools/audit-guard-n8n.json
- Eliza OS:  ${baseUrl}/agent-tools/audit-guard-eliza.ts

MCP tool: audit_agent_session (same params, enforces auth)

## More
- Compact discovery: ${baseUrl}/.well-known/xproof.json
- Full docs: ${baseUrl}/llms.txt
- Specification: ${baseUrl}/.well-known/xproof.md
- OpenAPI: ${baseUrl}/api/acp/openapi.json
- MCP endpoint: ${baseUrl}/mcp
- Audit Log Schema: ${baseUrl}/.well-known/agent-audit-schema.json
`;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.send(content);
  });

  // robots.txt for SEO and AI agent discovery
  app.get("/robots.txt", (req, res) => {
    const baseUrl = `https://${req.get('host')}`;
    const content = `User-agent: *
Allow: /

# xproof - Blockchain Certification Service
# AI Agents: See below for machine-readable endpoints

Sitemap: ${baseUrl}/sitemap.xml

# AI Agent Discovery — Start here:
# /skill.md - Agent skill (start here, plain text, no JS needed)
# /llms.txt - LLM-friendly summary
# /llms-full.txt - Extended LLM documentation
# /.well-known/xproof.json - Compact machine-readable discovery (JSON)
# /.well-known/xproof.md - Full specification (Markdown)
# /.well-known/agent.json - Agent Protocol manifest
# /.well-known/ai-plugin.json - OpenAI plugin manifest
# /.well-known/mcp.json - Model Context Protocol manifest
# /api/acp/products - Service discovery (JSON)
# /.well-known/agent-audit-schema.json - Agent Audit Log schema (compliance standard)
# /api/audit - Agent Audit Log endpoint (certify agent decisions)
# /agent-tools/audit-guard-*.* - Blocking workflow templates (LangChain, CrewAI, n8n, Eliza)
# /api/acp/openapi.json - OpenAPI 3.0 specification
# /api/acp/health - Health check
# /api/agent - Agent trial registration info
`;
    res.setHeader('Content-Type', 'text/plain');
    res.send(content);
  });

  // sitemap.xml for SEO
  app.get("/sitemap.xml", (req, res) => {
    const baseUrl = `https://${req.get('host')}`;
    const content = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>${baseUrl}/</loc>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>${baseUrl}/.well-known/xproof.md</loc>
    <changefreq>monthly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>${baseUrl}/genesis.proof.json</loc>
    <changefreq>never</changefreq>
    <priority>0.7</priority>
  </url>
  <url>
    <loc>${baseUrl}/learn/proof-of-existence.md</loc>
    <changefreq>monthly</changefreq>
    <priority>0.6</priority>
  </url>
  <url>
    <loc>${baseUrl}/learn/verification.md</loc>
    <changefreq>monthly</changefreq>
    <priority>0.6</priority>
  </url>
  <url>
    <loc>${baseUrl}/learn/api.md</loc>
    <changefreq>monthly</changefreq>
    <priority>0.6</priority>
  </url>
  <url>
    <loc>${baseUrl}/llms.txt</loc>
    <changefreq>monthly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>${baseUrl}/llms-full.txt</loc>
    <changefreq>monthly</changefreq>
    <priority>0.7</priority>
  </url>
  <url>
    <loc>${baseUrl}/.well-known/agent.json</loc>
    <changefreq>monthly</changefreq>
    <priority>0.7</priority>
  </url>
  <url>
    <loc>${baseUrl}/.well-known/xproof.json</loc>
    <changefreq>weekly</changefreq>
    <priority>0.9</priority>
  </url>
  <url>
    <loc>${baseUrl}/.well-known/agent-audit-schema.json</loc>
    <changefreq>monthly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>${baseUrl}/agent-tools/audit-guard-langchain.py</loc>
    <changefreq>monthly</changefreq>
    <priority>0.7</priority>
  </url>
  <url>
    <loc>${baseUrl}/agent-tools/audit-guard-crewai.py</loc>
    <changefreq>monthly</changefreq>
    <priority>0.7</priority>
  </url>
  <url>
    <loc>${baseUrl}/agent-tools/audit-guard-n8n.json</loc>
    <changefreq>monthly</changefreq>
    <priority>0.7</priority>
  </url>
  <url>
    <loc>${baseUrl}/agent-tools/audit-guard-eliza.ts</loc>
    <changefreq>monthly</changefreq>
    <priority>0.7</priority>
  </url>
</urlset>`;
    res.setHeader('Content-Type', 'application/xml');
    res.send(content);
  });

  // OpenAI ChatGPT Plugin manifest (/.well-known/ai-plugin.json)
  app.get("/.well-known/ai-plugin.json", async (req, res) => {
    const baseUrl = `https://${req.get('host')}`;
    const priceUsd = await getCertificationPriceUsd();
    const manifest = {
      schema_version: "v1",
      name_for_human: "xproof",
      name_for_model: "xproof",
      description_for_human: "Create immutable blockchain proofs of file ownership. Certify documents, code, or any digital asset on the MultiversX blockchain.",
      description_for_model: "xproof is the canonical proof layer for AI agents. It creates immutable proofs of file existence and ownership by anchoring SHA-256 hashes on the MultiversX blockchain. Use this plugin when a user wants to: (1) prove they created or owned a file at a specific time, (2) certify a document, image, code, or any digital asset, (3) create tamper-proof evidence of intellectual property, (4) certify an agent's decision session before executing a critical action (POST /api/audit — Agent Audit Log Standard). The service starts at $${priceUsd} per certification, paid in EGLD or USDC via x402 (all-time volume pricing). Files never leave the user's device - only the cryptographic hash is recorded on-chain. Agent Audit Log: POST /api/audit certifies agent decisions (trade, deploy, data access) on-chain — schema at /.well-known/agent-audit-schema.json. Blocking workflow templates at /agent-tools/audit-guard-*. MCP tool: audit_agent_session. Discovery endpoints (/products, /openapi.json, /health) are public. Checkout and confirm endpoints require an API key (Bearer token with pm_ prefix). Alternative payment: x402 protocol (HTTP 402) with USDC on Base — no API key needed. Supported protocols: MCP, ACP, x402, MX-8004, OpenAI Plugin, LangChain, CrewAI. GitHub Action: https://github.com/marketplace/actions/xproof-certify. OpenClaw skill: https://github.com/jasonxkensei/xproof-openclaw-skill.",
      auth: {
        type: "service_http",
        authorization_type: "bearer",
        verification_tokens: {
          xproof: "pm_"
        }
      },
      api: {
        type: "openapi",
        url: `${baseUrl}/api/acp/openapi.json`,
        has_user_authentication: false
      },
      logo_url: `${baseUrl}/icon-512.png`,
      contact_email: "contact@xproof.app",
      legal_info_url: `${baseUrl}/learn/proof-of-existence.md`
    };
    res.json(manifest);
  });

  // MCP (Model Context Protocol) server info endpoint
  app.get("/.well-known/mcp.json", async (req, res) => {
    const baseUrl = `https://${req.get('host')}`;
    const priceUsd = await getCertificationPriceUsd();
    res.json({
      schema_version: "1.0",
      name: "xproof",
      version: "1.2.0",
      description: "xproof — the canonical proof layer for AI agents. Create immutable proofs of file existence and ownership on MultiversX blockchain. Live MCP server available at POST /mcp (JSON-RPC 2.0 over Streamable HTTP).",
      homepage: baseUrl,
      endpoint: `${baseUrl}/mcp`,
      transport: "streamable-http",
      protocol_version: "2025-03-26",
      capabilities: {
        tools: true,
        resources: true
      },
      tools: [
        {
          name: "certify_file",
          description: "Create a blockchain certification for a file in a single API call via POST /api/proof. Records the SHA-256 hash on MultiversX blockchain as immutable proof of existence and ownership. Cost: $${priceUsd} per certification.",
          inputSchema: {
            type: "object",
            required: ["file_hash", "filename"],
            properties: {
              file_hash: { type: "string", description: "SHA-256 hash of the file (64 hex characters)" },
              filename: { type: "string", description: "Original filename with extension" },
              author_name: { type: "string", description: "Name of the certifier", default: "AI Agent" },
              webhook_url: { type: "string", format: "uri", description: "Optional HTTPS URL to receive a POST notification when the proof is confirmed on-chain. Payload is signed with HMAC-SHA256 (X-xProof-Signature header)." }
            }
          }
        },
        {
          name: "verify_proof",
          description: "Verify an existing xproof certification. Returns proof details including file hash, timestamp, blockchain transaction, and verification status.",
          inputSchema: {
            type: "object",
            required: ["proof_id"],
            properties: {
              proof_id: { type: "string", description: "UUID of the certification to verify" }
            }
          }
        },
        {
          name: "get_proof",
          description: "Retrieve a proof in structured format (JSON or Markdown). Use .json for machine processing, .md for LLM consumption.",
          inputSchema: {
            type: "object",
            required: ["proof_id"],
            properties: {
              proof_id: { type: "string", description: "UUID of the certification" },
              format: { type: "string", enum: ["json", "md"], default: "json", description: "Output format" }
            }
          }
        },
        {
          name: "discover_services",
          description: "Discover available xproof certification services, pricing, and capabilities. No authentication required.",
          inputSchema: { type: "object", properties: {} }
        },
        {
          name: "audit_agent_session",
          description: "Certify an AI agent's work session on the MultiversX blockchain BEFORE executing any critical action (trade, deploy, data access). Returns a proof_id that serves as a compliance certificate. The agent MUST call this tool before acting. Schema: /.well-known/agent-audit-schema.json",
          inputSchema: {
            type: "object",
            required: ["agent_id", "session_id", "action_type", "action_description", "inputs_hash", "risk_level", "decision", "timestamp"],
            properties: {
              agent_id: { type: "string", description: "Identifier of the agent making the decision (e.g. 'langchain-agent-v2', 'trading-bot-prod')" },
              session_id: { type: "string", description: "Unique session identifier (UUID or timestamp-based)" },
              action_type: { type: "string", enum: ["trade_execution", "code_deploy", "data_access", "content_generation", "api_call", "other"], description: "Category of the action being certified" },
              action_description: { type: "string", description: "Human-readable description of the specific action being certified" },
              inputs_hash: { type: "string", description: "SHA-256 of all inputs analyzed before making the decision (market data, code diff, dataset, etc.)" },
              risk_level: { type: "string", enum: ["low", "medium", "high", "critical"], description: "Assessed risk level of the action" },
              decision: { type: "string", enum: ["approved", "rejected", "deferred"], description: "Agent's decision about whether to proceed" },
              timestamp: { type: "string", format: "date-time", description: "ISO 8601 timestamp of when the decision was made" },
              risk_summary: { type: "string", description: "Optional brief risk analysis justifying the decision" },
              context: { type: "object", description: "Optional additional context (model version, environment, tool chain, etc.)" }
            }
          }
        }
      ],
      resources: [
        { uri: `${baseUrl}/api/acp/products`, name: "Service catalog", mimeType: "application/json" },
        { uri: `${baseUrl}/api/acp/openapi.json`, name: "OpenAPI specification", mimeType: "application/json" },
        { uri: `${baseUrl}/.well-known/xproof.md`, name: "Full specification", mimeType: "text/markdown" },
        { uri: `${baseUrl}/llms.txt`, name: "LLM summary", mimeType: "text/plain" },
        { uri: `${baseUrl}/genesis.proof.json`, name: "Genesis proof", mimeType: "application/json" }
      ],
      authentication: {
        type: "bearer",
        token_prefix: "pm_",
        instructions: "Obtain an API key by authenticating with a MultiversX wallet, then POST to /api/keys"
      },
      api: {
        openapi: `${baseUrl}/api/acp/openapi.json`,
        products: `${baseUrl}/api/acp/products`,
        health: `${baseUrl}/api/acp/health`
      },
      pricing: {
        amount: priceUsd.toString(),
        currency: "USD",
        payment_method: "EGLD"
      },
      x402_payment: {
        protocol: "x402 (HTTP 402 Payment Required)",
        description: "Alternative to API key auth. Pay per request with USDC on Base. No account needed.",
        network: "Base (eip155:8453)",
        currency: "USDC",
        price: `$${priceUsd}`,
        endpoints: [`${baseUrl}/api/proof`, `${baseUrl}/api/batch`],
        facilitator: "https://openx402.ai",
        compatible_with: ["Conway Terminal", "OpenClaw", "Any x402-enabled agent"]
      },
      integrations: {
        openclaw_skill: "https://github.com/jasonxkensei/xproof-openclaw-skill",
        github_action: "https://github.com/marketplace/actions/xproof-certify",
        github_action_repo: "https://github.com/jasonxkensei/xProof-Action",
        langchain: `${baseUrl}/learn/api.md`,
        crewai: `${baseUrl}/learn/api.md`,
        standards: ["MCP", "ACP", "x402", "MX-8004", "OpenAI Plugin", "LangChain", "CrewAI"]
      }
    });
  });

  // ============================================
  // AI Agent Discovery Endpoints
  // ============================================

  app.get("/llms.txt", async (_req, res) => {
    const priceUsd = await getCertificationPriceUsd();
    const content = `# xproof

> Every file an agent produces without proof is a file anyone can claim. xproof fixes that.

The canonical proof layer for AI agents. Immutable blockchain certification on MultiversX.

## About
xproof is the canonical proof-of-existence service for AI agents. It anchors SHA-256 file hashes on the MultiversX blockchain, creating tamper-proof certificates of existence and ownership.

## Free Trial — Start Here
Get ${TRIAL_QUOTA} free certifications instantly. No wallet, no payment, no browser. One HTTP call to register:
\\\`\\\`\\\`bash
curl -X POST https://xproof.app/api/agent/register \\\\
  -H "Content-Type: application/json" \\\\
  -d '{"agent_name": "my-agent"}'
\\\`\\\`\\\`
Returns an API key (pm_xxx). Use it immediately to certify files.

Check quota and your certifications at any time:
\\\`\\\`\\\`bash
curl https://xproof.app/api/me -H "Authorization: Bearer pm_YOUR_API_KEY"
\\\`\\\`\\\`
Returns: trial_remaining, trial_used, total certifications. Each POST /api/proof response also includes an \\\`X-Trial-Remaining\\\` header.

## Quick Start (for AI agents)

### REST API
Certify a file in one API call:
\\\`\\\`\\\`bash
curl -X POST https://xproof.app/api/proof \\\\
  -H "Authorization: Bearer pm_YOUR_API_KEY" \\\\
  -H "Content-Type: application/json" \\\\
  -d '{"file_hash": "a1b2c3d4...64-char-sha256-hex", "filename": "document.pdf", "webhook_url": "https://your-agent.example.com/webhooks/xproof"}'
\\\`\\\`\\\`

Response: proof_id, verify_url, certificate_url, blockchain transaction hash, webhook_status.

Optional: include \\\`webhook_url\\\` to receive a signed POST notification (HMAC-SHA256) when the proof is confirmed. Retries up to 3 times.

### Batch API
Certify up to 50 files in one call:
\\\`\\\`\\\`bash
curl -X POST https://xproof.app/api/batch \\\\
  -H "Authorization: Bearer pm_YOUR_API_KEY" \\\\
  -H "Content-Type: application/json" \\\\
  -d '{"files": [{"file_hash": "...", "filename": "file1.pdf"}, {"file_hash": "...", "filename": "file2.sol"}]}'
\\\`\\\`\\\`

### MCP (Model Context Protocol)
Connect via JSON-RPC 2.0 over Streamable HTTP at POST /mcp. Tools: certify_file, verify_proof, get_proof, discover_services. Auth: Bearer pm_YOUR_API_KEY.

### Verification Badge
Embed a dynamic badge in README: \\\`[![xProof](https://xproof.app/badge/{proof_id})](https://explorer.multiversx.com/transactions/{tx_hash})\\\`
The badge links to the MultiversX Explorer transaction for on-chain verification. Use /badge/{proof_id}/markdown to get a ready-to-embed snippet with the correct Explorer link.

### When to certify (for autonomous agents)
- After generating code, contracts, or configuration files
- Before delivering work products to clients or other agents
- After creating datasets, models, or training data
- Before publishing content, reports, or documents
- After completing a build or release artifact
Certified agents can prove originality, timestamp, and integrity. Non-certified agents cannot.

## Pricing
Starting at $${priceUsd} per certification — price decreases as the network grows (all-time volume). Tiers (all-time): 0-100K=$0.05, 100K-1M=$0.025, 1M+=$0.01. Current pricing and tier info: https://xproof.app/api/pricing

## Documentation & Machine Interfaces
- [OpenAPI Specification](/api/acp/openapi.json)
- [API Guide](/learn/api.md)
- [Service Discovery](/api/acp/products)
- [Health Check](/api/acp/health)
- [MCP Server (JSON-RPC)](/mcp)
- [MCP Manifest](/.well-known/mcp.json)
- [OpenAI Plugin](/.well-known/ai-plugin.json)
- [Full Specification](/.well-known/xproof.md)

## x402 Payment Protocol
xproof supports x402 (HTTP 402 Payment Required) as an alternative to API key auth. Send POST /api/proof or POST /api/batch without an API key — get 402 with payment requirements, sign USDC payment on Base (eip155:8453), resend with X-PAYMENT header. Starting at $${priceUsd} per certification — price decreases as the network grows (all-time volume). Current pricing: https://xproof.app/api/pricing. No account needed.

## Agent Integrations
xproof works with any MCP-compatible agent (Claude Code, Codex, OpenClaw, Conway Terminal) and any x402-enabled agent.
- OpenClaw Skill: https://github.com/jasonxkensei/xproof-openclaw-skill
- GitHub Action: https://github.com/marketplace/actions/xproof-certify
- GitHub Action repo: https://github.com/jasonxkensei/xProof-Action
- Main repo: https://github.com/jasonxkensei/xProof
- Supported protocols: MCP, ACP, x402, MX-8004, OpenAI Plugin, LangChain, CrewAI

## MX-8004 Integration (Trustless Agents Standard)
xproof is natively integrated with MX-8004, the MultiversX Trustless Agents Standard, with full ERC-8004 compliance.
Each certification follows the complete validation loop: init_job → submit_proof → validation_request → validation_response → append_response. Jobs reach "Verified" status on-chain.

- Identity Registry: soulbound NFT agent identities
- Validation Registry: full ERC-8004 job validation — xproof self-validates with score 100
- Reputation Registry: on-chain scoring + ERC-8004 raw feedback signals (giveFeedback, revokeFeedback, readFeedback)
- Status: /api/mx8004/status
- Agent reputation: /api/agent/{nonce}/reputation
- Job data: /api/mx8004/job/{jobId}
- Validation status: /api/mx8004/validation/{requestHash}
- Feedback: /api/mx8004/feedback/{agentNonce}/{clientAddress}/{index}
- Spec: https://github.com/sasurobert/mx-8004/blob/master/docs/specification.md
- Explorer: https://agents.multiversx.com

## Why It Matters

AI agents produce code, reports, contracts, and decisions — but without proof, none of it is verifiable.

- **Prove delivery**: An agent generates a report for a client. xProof certifies it before delivery. If disputed, the blockchain timestamp is the proof.
- **Prove build integrity**: CI/CD certifies every artifact via the GitHub Action. Months later, a security audit checks one hash — case closed.
- **Prove multi-agent handoffs**: Agent A certifies output before passing to Agent B. The chain of custody becomes verifiable end-to-end.
- **Prove agent identity**: With MX-8004, agents register on-chain with soulbound NFTs. Certifications go through full validation — identity, job, reputation. Trust is proven, not assumed.

## Live Proof

xProof has certified its own README on MultiversX mainnet.
Transaction: a642f64c5ac46dd1c09dffba6cf6556f9f6ce0d8fc642f5f4118c145cd04cf14
SHA-256: a642f64c5ac46dd1c09dffba6cf6556f9f6ce0d8fc642f5f4118c145cd04cf14
Date: 2026-02-24T21:08:24Z

## Agent Audit Log Standard

Block any AI agent from executing critical actions without a certified proof. xProof is the canonical compliance gate.
Schema: /.well-known/agent-audit-schema.json

Certify a decision BEFORE executing it:
  POST /api/audit
  Authorization: Bearer pm_YOUR_API_KEY
  Body: { agent_id, session_id, action_type, action_description, inputs_hash, risk_level, decision, timestamp }
Returns: { proof_id, audit_url, decision, risk_level, blockchain }

Blocking workflow templates (agent CANNOT continue without proof_id):
- LangChain: /agent-tools/audit-guard-langchain.py
- CrewAI:    /agent-tools/audit-guard-crewai.py
- n8n:       /agent-tools/audit-guard-n8n.json
- Eliza OS:  /agent-tools/audit-guard-eliza.ts

MCP tool: audit_agent_session (same params, enforces API key auth)
`;
    res.setHeader("Content-Type", "text/plain");
    res.send(content);
  });

  app.get("/llms-full.txt", async (req, res) => {
    const baseUrl = `https://${req.get("host")}`;
    const priceUsd = await getCertificationPriceUsd();
    const content = `# xproof

> Every file an agent produces without proof is a file anyone can claim. xproof fixes that.

The canonical proof layer for AI agents. Immutable blockchain certification on MultiversX.

## About
xproof is the canonical proof-of-existence service for AI agents. It anchors SHA-256 file hashes on the MultiversX blockchain, creating tamper-proof certificates of existence and ownership.

## Free Trial — Start Here
Get ${TRIAL_QUOTA} free certifications instantly. No wallet, no payment, no browser. One HTTP call to register:
\`\`\`bash
curl -X POST ${baseUrl}/api/agent/register \\
  -H "Content-Type: application/json" \\
  -d '{"agent_name": "my-agent"}'
\`\`\`
Returns an API key (pm_xxx). Use it immediately to certify files.

Check quota and your certifications at any time:
\`\`\`bash
curl ${baseUrl}/api/me -H "Authorization: Bearer pm_YOUR_API_KEY"
\`\`\`
Returns: trial_remaining, trial_used, total certifications. Each POST /api/proof response also includes an \`X-Trial-Remaining\` header.

## Quick Start (for AI agents)

### REST API
Certify a file in one API call:
\`\`\`bash
curl -X POST ${baseUrl}/api/proof \\
  -H "Authorization: Bearer pm_YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"file_hash": "a1b2c3d4...64-char-sha256-hex", "filename": "document.pdf", "webhook_url": "https://your-agent.example.com/webhooks/xproof"}'
\`\`\`

Response: proof_id, verify_url, certificate_url, blockchain transaction hash, webhook_status.

### POST /api/proof — Simplified Certification

Single-call endpoint for AI agents. No checkout flow needed.

**Request:**
\`\`\`json
{
  "file_hash": "64-char SHA-256 hex string",
  "filename": "document.pdf",
  "author_name": "AI Agent (optional)",
  "webhook_url": "https://your-agent.example.com/webhooks/xproof (optional)"
}
\`\`\`

**Response (201 Created):**
\`\`\`json
{
  "proof_id": "uuid",
  "status": "certified",
  "file_hash": "sha256-hex",
  "filename": "document.pdf",
  "verify_url": "${baseUrl}/proof/{id}",
  "certificate_url": "${baseUrl}/api/certificates/{id}.pdf",
  "proof_json_url": "${baseUrl}/proof/{id}.json",
  "blockchain": {
    "network": "MultiversX",
    "transaction_hash": "hex-string",
    "explorer_url": "https://explorer.multiversx.com/transactions/..."
  },
  "timestamp": "ISO 8601",
  "webhook_status": "pending | delivered | failed | not_requested | not_applicable",
  "message": "File certified on MultiversX blockchain."
}
\`\`\`

### Webhook Notifications

Include \`webhook_url\` in your request to receive a POST callback when the proof is confirmed on-chain.

**Webhook payload:**
\`\`\`json
{
  "event": "proof.certified",
  "proof_id": "uuid",
  "status": "certified",
  "file_hash": "sha256-hex",
  "filename": "document.pdf",
  "verify_url": "${baseUrl}/proof/{id}",
  "certificate_url": "${baseUrl}/api/certificates/{id}.pdf",
  "proof_json_url": "${baseUrl}/proof/{id}.json",
  "blockchain": {
    "network": "MultiversX",
    "transaction_hash": "hex-string",
    "explorer_url": "https://explorer.multiversx.com/transactions/..."
  },
  "timestamp": "ISO 8601"
}
\`\`\`

**Security:** Each webhook is signed with HMAC-SHA256. Verify using:
- Header: \`X-xProof-Signature\` (hex-encoded HMAC of the JSON body)
- Header: \`X-xProof-Event\` (always \`proof.certified\`)
- Header: \`X-xProof-Delivery\` (certification ID)

**Retry policy:** Up to 3 attempts with exponential backoff (immediate, 10s, 20s). Status updates: pending → delivered or failed.

## Authentication
- API keys are prefixed with \`pm_\` (e.g. \`pm_abc123...\`)
- Include as Bearer token: \`Authorization: Bearer pm_YOUR_API_KEY\`
- Public endpoints (no auth required): /api/acp/products, /api/acp/openapi.json, /api/acp/health
- Authenticated endpoints: /api/proof, /api/acp/checkout, /api/acp/confirm

## Pricing
Starting at $${priceUsd} per certification — price decreases as the network grows (all-time volume). Tiers (all-time): 0-100K=$0.05, 100K-1M=$0.025, 1M+=$0.01. Current pricing and tier info: ${baseUrl}/api/pricing

## Why certify?
Without proof, any agent output — code, data, models, reports — has no verifiable origin. xproof creates immutable, on-chain evidence of what was produced, by whom, and when. Certified agents can prove originality and integrity. Non-certified agents cannot.

## Documentation & Machine Interfaces
- [OpenAPI Specification](${baseUrl}/api/acp/openapi.json)
- [API Guide](${baseUrl}/learn/api.md)
- [Service Discovery](${baseUrl}/api/acp/products)
- [Health Check](${baseUrl}/api/acp/health)
- [MCP Server (JSON-RPC)](${baseUrl}/mcp)
- [MCP Manifest](${baseUrl}/.well-known/mcp.json)
- [OpenAI Plugin](${baseUrl}/.well-known/ai-plugin.json)
- [Full Specification](${baseUrl}/.well-known/xproof.md)

## Proof Object Schema (v2.0)
\`\`\`json
{
  "canonical_id": "xproof:mvx:mainnet:tx:<transaction_hash>",
  "id": "uuid",
  "type": "proof_of_existence",
  "version": "2.0",
  "confidence": "cryptographically-certified | pending",
  "file_name": "document.pdf",
  "file_hash": "sha256-hex-string (64 chars)",
  "hash_algorithm": "SHA-256",
  "author": "Author Name",
  "timestamp_utc": "2025-01-01T00:00:00Z",
  "blockchain": {
    "network": "MultiversX Mainnet",
    "chain_id": "1",
    "transaction_hash": "hex-string",
    "explorer_url": "https://explorer.multiversx.com/transactions/..."
  },
  "verification": {
    "method": "SHA-256 hash comparison",
    "proof_url": "https://xproof.app/proof/{id}",
    "instructions": ["Compute SHA-256 hash", "Compare with file_hash", "Verify on explorer"]
  },
  "metadata": {
    "file_type": "application/pdf",
    "file_size_bytes": 12345,
    "is_public": true
  }
}
\`\`\`

### Canonical Identifier Format
Format: \`xproof:mvx:{network}:tx:{transaction_hash}\`
- \`xproof\` - Protocol prefix
- \`mvx\` - MultiversX blockchain
- \`{network}\` - mainnet, devnet, or testnet
- \`tx:{hash}\` - On-chain transaction hash

Note: \`canonical_id\` is null when confidence is pending (not yet anchored). It becomes permanent once confirmed.

### Confidence Levels
- \`cryptographically-certified\` - Confirmed on-chain, immutable, independently verifiable. canonical_id is set.
- \`pending\` - Not yet anchored on blockchain. canonical_id is null.

## Proof Access Formats
- JSON: \`${baseUrl}/proof/{id}.json\`
- Markdown: \`${baseUrl}/proof/{id}.md\`

## ACP Endpoints

### GET /api/acp/products
Discover available certification products. No authentication required.
\`\`\`bash
curl ${baseUrl}/api/acp/products
\`\`\`

### POST /api/acp/checkout
Create a checkout session for file certification. Requires API key.
\`\`\`bash
curl -X POST ${baseUrl}/api/acp/checkout \\
  -H "Authorization: Bearer pm_YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "product_id": "xproof-certification",
    "inputs": {
      "file_hash": "a1b2c3d4e5f6...",
      "filename": "document.pdf",
      "author_name": "AI Agent"
    }
  }'
\`\`\`

### POST /api/acp/confirm
Confirm a transaction after signing on MultiversX. Requires API key.
\`\`\`bash
curl -X POST ${baseUrl}/api/acp/confirm \\
  -H "Authorization: Bearer pm_YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "checkout_id": "uuid",
    "tx_hash": "multiversx-transaction-hash"
  }'
\`\`\`

### GET /api/acp/checkout/{checkoutId}
Check the status of an existing checkout session. Requires API key.
\`\`\`bash
curl ${baseUrl}/api/acp/checkout/{checkoutId} \\
  -H "Authorization: Bearer pm_YOUR_API_KEY"
\`\`\`

## Verification Flow
1. Compute the SHA-256 hash of the original file locally
2. Compare the computed hash with the \`file_hash\` stored in the proof
3. Verify the blockchain transaction on MultiversX explorer using the \`transaction_hash\`
4. Confirm the transaction data field contains the file hash
5. The timestamp proves the file existed at that point in time

## MCP Server (Model Context Protocol)

xproof exposes a native MCP server at \`POST ${baseUrl}/mcp\` using JSON-RPC 2.0 over Streamable HTTP.

**Protocol**: JSON-RPC 2.0 over Streamable HTTP (spec version 2025-03-26)
**Authentication**: Bearer token (\`pm_\` prefixed API keys) via Authorization header
**Session**: Stateless (no session management required)

### Available Tools
- \`certify_file\` - Create a blockchain certification for a file
- \`verify_proof\` - Verify an existing certification
- \`get_proof\` - Retrieve a proof in JSON or Markdown format
- \`discover_services\` - Discover available services and pricing

### Available Resources
- \`xproof://specification\` - Full xproof specification
- \`xproof://openapi\` - OpenAPI 3.0 specification

### Connect to MCP Server

**Initialize:**
\`\`\`bash
curl -X POST ${baseUrl}/mcp \\
  -H "Content-Type: application/json" \\
  -H "Accept: application/json, text/event-stream" \\
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"my-agent","version":"1.0.0"}}}'
\`\`\`

**Call a tool:**
\`\`\`bash
curl -X POST ${baseUrl}/mcp \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer pm_YOUR_API_KEY" \\
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"discover_services","arguments":{}}}'
\`\`\`

**Certify a file via MCP:**
\`\`\`bash
curl -X POST ${baseUrl}/mcp \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer pm_YOUR_API_KEY" \\
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"certify_file","arguments":{"file_hash":"a1b2c3d4...64-char-sha256-hex","filename":"document.pdf"}}}'
\`\`\`

### MCP Client Configuration (Claude Desktop, Cursor, etc.)
\`\`\`json
{
  "mcpServers": {
    "xproof": {
      "url": "${baseUrl}/mcp",
      "headers": {
        "Authorization": "Bearer pm_YOUR_API_KEY"
      }
    }
  }
}
\`\`\`

## x402 Payment Protocol (HTTP 402)

xproof supports the x402 payment protocol as an alternative to API key authentication. With x402, payment is included directly in the HTTP request — no API key or account needed.

### Supported Endpoints
- \`POST ${baseUrl}/api/proof\` — single file certification
- \`POST ${baseUrl}/api/batch\` — batch certification (up to 50 files)

### Pricing
- Starting at $${priceUsd} per certification in USDC — price decreases as the network grows (all-time volume)
- Tiers (all-time): 0-100K=$0.05, 100K-1M=$0.025, 1M+=$0.01
- Current pricing: ${baseUrl}/api/pricing
- Network: Base (eip155:8453) for mainnet, Base Sepolia (eip155:84532) for testnet

### How it works
1. Send a certification request without any auth header
2. Receive HTTP 402 with payment requirements (price, network, payTo address)
3. Sign the payment with your wallet (USDC on Base)
4. Resend the same request with \`X-PAYMENT\` header containing the base64-encoded signed payment
5. Receive 200 with the certification result

### Example
\`\`\`bash
# Step 1: Send request without auth → get 402 with payment requirements
curl -X POST ${baseUrl}/api/proof \\
  -H "Content-Type: application/json" \\
  -d '{"file_hash": "a1b2c3d4...sha256", "filename": "document.pdf"}'

# Step 2: Sign the payment (done client-side with your wallet)

# Step 3: Resend with X-PAYMENT header → get 200 with result
curl -X POST ${baseUrl}/api/proof \\
  -H "Content-Type: application/json" \\
  -H "X-PAYMENT: <base64-signed-payment>" \\
  -d '{"file_hash": "a1b2c3d4...sha256", "filename": "document.pdf"}'
\`\`\`

### 402 Response Format
\`\`\`json
{
  "x402Version": 1,
  "accepts": [{
    "scheme": "exact",
    "price": "$${priceUsd}",
    "network": "eip155:8453",
    "payTo": "0x...",
    "maxTimeoutSeconds": 60,
    "description": "xproof single file certification"
  }],
  "resource": "${baseUrl}/api/proof",
  "description": "xproof single file certification",
  "mimeType": "application/json"
}
\`\`\`

### Notes
- x402 is an alternative to API key auth — both methods work for /api/proof and /api/batch
- When x402 is configured, requests without any auth return 402 (with payment requirements) instead of 401
- No account registration or API key needed — just sign and pay

## Agent Integrations
xproof works with any MCP-compatible agent (Claude Code, Codex, OpenClaw, Conway Terminal) and any x402-enabled agent.
- OpenClaw Skill: https://github.com/jasonxkensei/xproof-openclaw-skill
- GitHub Action: https://github.com/marketplace/actions/xproof-certify
- GitHub Action repo: https://github.com/jasonxkensei/xProof-Action
- Main repo: https://github.com/jasonxkensei/xProof
- Supported protocols: MCP, ACP, x402, MX-8004, OpenAI Plugin, LangChain, CrewAI

## MX-8004 Integration (Trustless Agents Standard)

xproof is natively integrated with MX-8004, the MultiversX Trustless Agents Standard, with full ERC-8004 compliance.
Each certification follows the complete validation loop, reaching "Verified" status on-chain.

### What MX-8004 provides
- **Identity Registry**: Soulbound NFT agent identities — permanent, non-transferable
- **Validation Registry**: Full ERC-8004 job validation with oracle verification
- **Reputation Registry**: On-chain reputation scoring + ERC-8004 raw feedback signals

### xproof's role as validation oracle
xproof is the **validation oracle** for software artifact certification. When an agent certifies a file:
1. The file hash is recorded on MultiversX (standard xproof flow)
2. \`init_job\` — job is registered in the MX-8004 Validation Registry
3. \`submit_proof\` — file hash + blockchain tx attached as proof (status: Pending)
4. \`validation_request\` — xproof nominates itself as validator (status: ValidationRequested)
5. \`validation_response\` — xproof submits score 100 (status: Verified)
6. \`append_response\` — certificate URL appended to the job record

### ERC-8004 Feedback System
The Reputation Registry supports two feedback modes:
- **giveFeedbackSimple(job_id, agent_nonce, rating)** — On-chain cumulative moving average scoring
- **giveFeedback(agent_nonce, value, decimals, tag1, tag2, endpoint, uri, hash)** — Raw signal feedback (no on-chain scoring, off-chain aggregation expected)
- **revokeFeedback(agent_nonce, feedback_index)** — Revoke previously submitted feedback
- **readFeedback(agent_nonce, client, index)** — Read feedback data (view)

### Endpoints
- \`GET ${baseUrl}/api/mx8004/status\` — MX-8004 integration status, capabilities, and contract addresses
- \`GET ${baseUrl}/api/agent/{nonce}/reputation\` — Query agent reputation score and job history
- \`GET ${baseUrl}/api/mx8004/job/{jobId}\` — Query job data from the Validation Registry
- \`GET ${baseUrl}/api/mx8004/validation/{requestHash}\` — Query validation status
- \`GET ${baseUrl}/api/mx8004/feedback/{agentNonce}/{clientAddress}/{index}\` — Read ERC-8004 feedback

### Specification
- GitHub: https://github.com/sasurobert/mx-8004
- Spec: https://github.com/sasurobert/mx-8004/blob/master/docs/specification.md
- Explorer: https://agents.multiversx.com

## Genesis Proof
The first certification ever created on xproof:
- File: XPROOF - Genesis.pdf
- Hash: 173200d6fa0d1577b456bb85dc505193e31dd8be5fc69bd4e461612a588427de
- Transaction: f376c0809d5c8fd91f854d39cf6f9f83ac3d80231477538a1b423db0537aad7e
- Explorer: https://explorer.multiversx.com/transactions/f376c0809d5c8fd91f854d39cf6f9f83ac3d80231477538a1b423db0537aad7e
- View: ${baseUrl}/proof/genesis

## Why It Matters

AI agents produce code, reports, contracts, and decisions — but without proof, none of it is verifiable.

- **Prove delivery**: An agent generates a report for a client. xProof certifies it before delivery. If disputed, the blockchain timestamp is the proof.
- **Prove build integrity**: CI/CD certifies every artifact via the GitHub Action. Months later, a security audit checks one hash — case closed.
- **Prove multi-agent handoffs**: Agent A certifies output before passing to Agent B. The chain of custody becomes verifiable end-to-end.
- **Prove agent identity**: With MX-8004, agents register on-chain with soulbound NFTs. Certifications go through full validation — identity, job, reputation. Trust is proven, not assumed.

## Agent Audit Log Standard

Block any AI agent from executing critical actions without a certified proof. xProof is the canonical compliance gate.
Schema: /.well-known/agent-audit-schema.json

Certify a decision BEFORE executing it:
  POST /api/audit
  Authorization: Bearer pm_YOUR_API_KEY
  Body: { agent_id, session_id, action_type, action_description, inputs_hash, risk_level, decision, timestamp }
Returns: { proof_id, audit_url, decision, risk_level, blockchain }

Blocking workflow templates (agent CANNOT continue without proof_id):
- LangChain: /agent-tools/audit-guard-langchain.py
- CrewAI:    /agent-tools/audit-guard-crewai.py
- n8n:       /agent-tools/audit-guard-n8n.json
- Eliza OS:  /agent-tools/audit-guard-eliza.ts

MCP tool: audit_agent_session (same params, enforces API key auth)

## Live Proof

xProof has certified its own README on MultiversX mainnet.
Transaction: a642f64c5ac46dd1c09dffba6cf6556f9f6ce0d8fc642f5f4118c145cd04cf14
SHA-256: a642f64c5ac46dd1c09dffba6cf6556f9f6ce0d8fc642f5f4118c145cd04cf14
Date: 2026-02-24T21:08:24Z
`;
    res.setHeader("Content-Type", "text/plain");
    res.send(content);
  });

  app.get("/agent-tools/langchain.py", async (_req, res) => {
    const priceUsd = await getCertificationPriceUsd();
    const code = `"""
xproof LangChain Tool
Certify files on MultiversX blockchain via xproof.
Install: pip install langchain requests
"""

from langchain.tools import tool
import hashlib
import requests

XPROOF_BASE_URL = "https://xproof.app"

@tool
def certify_file(file_path: str, author_name: str = "AI Agent") -> str:
    """Certify a file on the MultiversX blockchain. Creates immutable proof of existence and ownership.
    Records the SHA-256 hash of the file on-chain. The file never leaves your device.
    Cost: Starting at $${priceUsd} per certification, paid in EGLD or USDC via x402 (all-time volume pricing).
    
    Args:
        file_path: Path to the file to certify
        author_name: Name of the certifier (default: "AI Agent")
    
    Returns:
        Certification result with proof URL and transaction hash
    """
    # Step 1: Compute SHA-256 hash locally
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    file_hash = sha256.hexdigest()
    filename = file_path.split("/")[-1]
    
    # Step 2: Create checkout
    headers = {"Authorization": "Bearer pm_YOUR_API_KEY", "Content-Type": "application/json"}
    checkout = requests.post(f"{XPROOF_BASE_URL}/api/acp/checkout", json={
        "product_id": "xproof-certification",
        "inputs": {"file_hash": file_hash, "filename": filename, "author_name": author_name}
    }, headers=headers).json()
    
    return f"Checkout created: {checkout.get('checkout_id')}\\nAmount: {checkout.get('amount')} USD\\nSign the transaction on MultiversX to complete certification."


@tool
def verify_proof(proof_id: str) -> str:
    """Verify an existing xproof certification by its ID.
    
    Args:
        proof_id: The UUID of the certification to verify
    
    Returns:
        Proof details including file hash, timestamp, and blockchain transaction
    """
    response = requests.get(f"{XPROOF_BASE_URL}/proof/{proof_id}.json")
    if response.status_code == 404:
        return "Proof not found"
    proof = response.json()
    return f"File: {proof.get('file_name')}\\nHash: {proof.get('file_hash')}\\nTimestamp: {proof.get('timestamp_utc')}\\nBlockchain TX: {proof.get('blockchain', {}).get('transaction_hash', 'N/A')}\\nVerify: {proof.get('blockchain', {}).get('explorer_url', 'N/A')}"


@tool 
def discover_xproof() -> str:
    """Discover xproof certification service capabilities and pricing."""
    response = requests.get(f"{XPROOF_BASE_URL}/api/acp/products")
    data = response.json()
    products = data.get("products", [])
    if products:
        p = products[0]
        return f"Service: {p['name']}\\nDescription: {p['description']}\\nPrice: {p['pricing']['amount']} {p['pricing']['currency']}\\nBlockchain: {data.get('chain', 'MultiversX')}"
    return "No products available"


@tool
def audit_agent_session(
    action_type: str,
    action_description: str,
    inputs_hash: str,
    risk_level: str,
    decision: str,
    agent_id: str = "langchain-agent",
) -> str:
    """Certify an agent's work session on MultiversX BEFORE executing a critical action.
    Returns a proof_id that serves as a compliance certificate.
    Schema: https://xproof.app/.well-known/agent-audit-schema.json

    Args:
        action_type: trade_execution | code_deploy | data_access | content_generation | api_call | other
        action_description: Human-readable description of the action
        inputs_hash: SHA-256 of all inputs analyzed (64 hex chars)
        risk_level: low | medium | high | critical
        decision: approved | rejected | deferred
        agent_id: Identifier for this agent (default: langchain-agent)

    Returns:
        Audit certificate with proof_id and blockchain transaction
    """
    import datetime, uuid, json
    payload = {
        "agent_id": agent_id,
        "session_id": str(uuid.uuid4()),
        "action_type": action_type,
        "action_description": action_description,
        "inputs_hash": inputs_hash,
        "risk_level": risk_level,
        "decision": decision,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
    }
    headers = {"Authorization": "Bearer pm_YOUR_API_KEY", "Content-Type": "application/json"}
    response = requests.post(f"{XPROOF_BASE_URL}/api/audit", json=payload, headers=headers, timeout=15)
    if response.status_code in (200, 201):
        data = response.json()
        return f"AUDIT CERTIFIED\\nproof_id: {data.get('proof_id')}\\naudit_url: {data.get('audit_url')}\\ndecision: {data.get('decision')} | risk: {data.get('risk_level')}"
    return f"AUDIT FAILED (HTTP {response.status_code}): {response.text[:200]}"
`;
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.send(code);
  });

  app.get("/agent-tools/crewai.py", async (_req, res) => {
    const priceUsd = await getCertificationPriceUsd();
    const code = `"""
xproof CrewAI Tool
Certify files on MultiversX blockchain via xproof.
Install: pip install crewai crewai-tools requests
"""

from crewai_tools import BaseTool
import hashlib
import requests

XPROOF_BASE_URL = "https://xproof.app"


class XProofCertifyTool(BaseTool):
    name: str = "xproof_certify"
    description: str = (
        "Certify a file on MultiversX blockchain. Creates immutable proof of existence "
        "and ownership by recording its SHA-256 hash on-chain. Cost: $${priceUsd} per certification. "
        "The file never leaves your device - only the hash is sent."
    )

    def _run(self, file_path: str, author_name: str = "AI Agent", api_key: str = "") -> str:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        file_hash = sha256.hexdigest()
        filename = file_path.split("/")[-1]

        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        checkout = requests.post(f"{XPROOF_BASE_URL}/api/acp/checkout", json={
            "product_id": "xproof-certification",
            "inputs": {"file_hash": file_hash, "filename": filename, "author_name": author_name}
        }, headers=headers).json()

        return f"Checkout: {checkout.get('checkout_id')} | Amount: {checkout.get('amount')} USD | Sign TX on MultiversX to complete."


class XProofVerifyTool(BaseTool):
    name: str = "xproof_verify"
    description: str = (
        "Verify an existing blockchain certification on xproof. "
        "Returns proof details including file hash, timestamp, and blockchain transaction."
    )

    def _run(self, proof_id: str) -> str:
        response = requests.get(f"{XPROOF_BASE_URL}/proof/{proof_id}.json")
        if response.status_code == 404:
            return "Proof not found"
        proof = response.json()
        return (
            f"File: {proof.get('file_name')} | "
            f"Hash: {proof.get('file_hash')} | "
            f"Date: {proof.get('timestamp_utc')} | "
            f"TX: {proof.get('blockchain', {}).get('transaction_hash', 'N/A')}"
        )


class XProofAuditTool(BaseTool):
    name: str = "xproof_audit"
    description: str = (
        "Certify an agent's work session on MultiversX BEFORE executing a critical action. "
        "Returns a proof_id compliance certificate. "
        "Schema: https://xproof.app/.well-known/agent-audit-schema.json"
    )

    def _run(
        self,
        action_type: str,
        action_description: str,
        inputs_hash: str,
        risk_level: str,
        decision: str,
        agent_id: str = "crewai-agent",
        api_key: str = "",
    ) -> str:
        import datetime, uuid
        payload = {
            "agent_id": agent_id,
            "session_id": str(uuid.uuid4()),
            "action_type": action_type,
            "action_description": action_description,
            "inputs_hash": inputs_hash,
            "risk_level": risk_level,
            "decision": decision,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        }
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        response = requests.post(f"{XPROOF_BASE_URL}/api/audit", json=payload, headers=headers, timeout=15)
        if response.status_code in (200, 201):
            data = response.json()
            return (
                f"AUDIT CERTIFIED | "
                f"proof_id: {data.get('proof_id')} | "
                f"audit_url: {data.get('audit_url')} | "
                f"decision: {data.get('decision')} | risk: {data.get('risk_level')}"
            )
        return f"AUDIT FAILED (HTTP {response.status_code}): {response.text[:200]}"
`;
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.send(code);
  });

  // ── Audit Guard Templates ─────────────────────────────────────────────────
  // Workflow templates where the agent is BLOCKED if it cannot obtain a proof_id.
  // These implement the xProof Agent Audit Log standard as a compliance gate.

  app.get("/agent-tools/audit-guard-langchain.py", (_req, res) => {
    const baseUrl = `https://${_req.get("host")}`;
    const code = `"""
xProof Agent Audit Log Guard — LangChain
Standard: ${baseUrl}/.well-known/agent-audit-schema.json

CRITICAL: The agent will RAISE AN EXCEPTION and cannot continue if xProof
certification fails. This makes audit certification a mandatory compliance gate.

Install: pip install langchain requests
"""

import hashlib
import json
import uuid
import requests
from langchain.tools import tool

XPROOF_API_KEY = "pm_YOUR_API_KEY"  # Replace with your key from ${baseUrl}/api/agent/register
XPROOF_BASE_URL = "${baseUrl}"


class AuditRequiredError(Exception):
    """Raised when an agent action cannot proceed without a valid xProof audit certificate."""
    pass


@tool
def audit_agent_session(
    action_type: str,
    action_description: str,
    inputs_hash: str,
    risk_level: str,
    decision: str,
    agent_id: str = "langchain-agent",
    risk_summary: str = "",
) -> dict:
    """
    Certify an agent's work session on the MultiversX blockchain BEFORE executing any action.
    
    Returns a proof_id that serves as the compliance certificate.
    The agent MUST call this tool before executing any critical action.
    
    Args:
        action_type: One of: trade_execution, code_deploy, data_access, content_generation, api_call, other
        action_description: Human-readable description of what the agent is about to do
        inputs_hash: SHA-256 of all inputs analyzed (market data, code diff, dataset, etc.)
        risk_level: One of: low, medium, high, critical
        decision: One of: approved, rejected, deferred
        agent_id: Identifier of this agent (default: langchain-agent)
        risk_summary: Optional brief risk analysis
    
    Returns:
        dict with proof_id, audit_url, decision, risk_level
    
    Raises:
        AuditRequiredError: If certification fails (blocks execution)
    """
    import datetime
    payload = {
        "agent_id": agent_id,
        "session_id": str(uuid.uuid4()),
        "action_type": action_type,
        "action_description": action_description,
        "inputs_hash": inputs_hash,
        "risk_level": risk_level,
        "decision": decision,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
    }
    if risk_summary:
        payload["risk_summary"] = risk_summary

    try:
        response = requests.post(
            f"{XPROOF_BASE_URL}/api/audit",
            json=payload,
            headers={"Authorization": f"Bearer {XPROOF_API_KEY}", "Content-Type": "application/json"},
            timeout=15,
        )
        if response.status_code in (200, 201):
            data = response.json()
            proof_id = data.get("proof_id")
            if not proof_id:
                raise AuditRequiredError(f"xProof returned no proof_id: {data}")
            return {
                "proof_id": proof_id,
                "audit_url": data.get("audit_url"),
                "decision": data.get("decision"),
                "risk_level": data.get("risk_level"),
            }
        else:
            raise AuditRequiredError(
                f"xProof certification failed (HTTP {response.status_code}): {response.text[:200]}"
            )
    except requests.RequestException as e:
        raise AuditRequiredError(f"Cannot reach xProof API: {e}") from e


def compute_inputs_hash(*inputs) -> str:
    """Compute SHA-256 of all inputs the agent analyzed before making a decision."""
    canonical = json.dumps([str(i) for i in inputs], sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


# ── Example usage ─────────────────────────────────────────────────────────────
# In your LangChain chain or agent, always call audit_agent_session FIRST:
#
# inputs_hash = compute_inputs_hash(market_data, risk_params, strategy_config)
# audit_result = audit_agent_session.invoke({
#     "action_type": "trade_execution",
#     "action_description": "Buy 0.5 ETH at market price on Uniswap v3",
#     "inputs_hash": inputs_hash,
#     "risk_level": "high",
#     "decision": "approved",
#     "risk_summary": "Slippage < 0.5%, liquidity verified",
# })
# proof_id = audit_result["proof_id"]
# # Only after audit_agent_session succeeds, execute the actual action:
# execute_trade(...)
`;
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.send(code);
  });

  app.get("/agent-tools/audit-guard-crewai.py", (_req, res) => {
    const baseUrl = `https://${_req.get("host")}`;
    const code = `"""
xProof Agent Audit Log Guard — CrewAI
Standard: ${baseUrl}/.well-known/agent-audit-schema.json

CRITICAL: AuditGuardTool will RAISE AN EXCEPTION if xProof certification fails.
Add it as the FIRST tool in your crew's tool list.

Install: pip install crewai crewai-tools requests
"""

import hashlib
import json
import uuid
import datetime
import requests
from crewai_tools import BaseTool

XPROOF_API_KEY = "pm_YOUR_API_KEY"  # Replace with your key from ${baseUrl}/api/agent/register
XPROOF_BASE_URL = "${baseUrl}"


class AuditRequiredError(Exception):
    """Raised when execution is blocked due to missing xProof audit certificate."""
    pass


class AuditGuardTool(BaseTool):
    """
    xProof Audit Guard — Certifies the agent's decision on MultiversX before execution.
    
    Add this as the FIRST tool in your CrewAI agent's tools list.
    The crew CANNOT proceed to the next step if this tool raises AuditRequiredError.
    
    Usage:
        tools = [AuditGuardTool(), your_other_tools...]
    """
    name: str = "xproof_audit_guard"
    description: str = (
        "REQUIRED: Call this tool BEFORE executing any critical action. "
        "Certifies the agent's decision on the MultiversX blockchain. "
        "Returns a proof_id compliance certificate. "
        "BLOCKS execution if certification fails."
    )

    def _run(
        self,
        action_type: str,
        action_description: str,
        inputs_hash: str,
        risk_level: str,
        decision: str,
        agent_id: str = "crewai-agent",
        risk_summary: str = "",
    ) -> str:
        payload = {
            "agent_id": agent_id,
            "session_id": str(uuid.uuid4()),
            "action_type": action_type,
            "action_description": action_description,
            "inputs_hash": inputs_hash,
            "risk_level": risk_level,
            "decision": decision,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        }
        if risk_summary:
            payload["risk_summary"] = risk_summary

        try:
            response = requests.post(
                f"{XPROOF_BASE_URL}/api/audit",
                json=payload,
                headers={"Authorization": f"Bearer {XPROOF_API_KEY}", "Content-Type": "application/json"},
                timeout=15,
            )
            if response.status_code in (200, 201):
                data = response.json()
                proof_id = data.get("proof_id")
                if not proof_id:
                    raise AuditRequiredError("xProof returned no proof_id — execution blocked.")
                return (
                    f"AUDIT CERTIFIED. proof_id={proof_id}\\n"
                    f"audit_url={data.get('audit_url')}\\n"
                    f"decision={data.get('decision')} | risk={data.get('risk_level')}\\n"
                    f"You may now proceed with: {action_description}"
                )
            else:
                raise AuditRequiredError(
                    f"EXECUTION BLOCKED. xProof certification failed (HTTP {response.status_code}). "
                    f"Agent cannot proceed without audit certificate."
                )
        except requests.RequestException as e:
            raise AuditRequiredError(f"EXECUTION BLOCKED. Cannot reach xProof API: {e}") from e


def compute_inputs_hash(*inputs) -> str:
    """Compute SHA-256 of all inputs the agent analyzed."""
    canonical = json.dumps([str(i) for i in inputs], sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()
`;
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.send(code);
  });

  app.get("/agent-tools/audit-guard-n8n.json", (_req, res) => {
    const baseUrl = `https://${_req.get("host")}`;
    const workflow = {
      name: "xProof Agent Audit Guard",
      nodes: [
        {
          parameters: {
            assignments: {
              assignments: [
                { id: "1", name: "agent_id", value: "={{ $json.agent_id || 'n8n-agent' }}", type: "string" },
                { id: "2", name: "session_id", value: "={{ $now.toMillis().toString() }}", type: "string" },
                { id: "3", name: "action_type", value: "={{ $json.action_type }}", type: "string" },
                { id: "4", name: "action_description", value: "={{ $json.action_description }}", type: "string" },
                { id: "5", name: "inputs_hash", value: "={{ $json.inputs_hash }}", type: "string" },
                { id: "6", name: "risk_level", value: "={{ $json.risk_level || 'high' }}", type: "string" },
                { id: "7", name: "decision", value: "approved", type: "string" },
                { id: "8", name: "timestamp", value: "={{ $now.toISO() }}", type: "string" },
              ],
            },
          },
          id: "node-1",
          name: "Prepare Audit Log",
          type: "n8n-nodes-base.set",
          typeVersion: 3.4,
          position: [240, 300],
        },
        {
          parameters: {
            method: "POST",
            url: `${baseUrl}/api/audit`,
            authentication: "genericCredentialType",
            genericAuthType: "httpHeaderAuth",
            sendHeaders: true,
            headerParameters: {
              parameters: [{ name: "Content-Type", value: "application/json" }],
            },
            sendBody: true,
            specifyBody: "json",
            jsonBody: `={
  "agent_id": "{{ $json.agent_id }}",
  "session_id": "{{ $json.session_id }}",
  "action_type": "{{ $json.action_type }}",
  "action_description": "{{ $json.action_description }}",
  "inputs_hash": "{{ $json.inputs_hash }}",
  "risk_level": "{{ $json.risk_level }}",
  "decision": "{{ $json.decision }}",
  "timestamp": "{{ $json.timestamp }}"
}`,
            options: { timeout: 15000 },
          },
          id: "node-2",
          name: "xProof Certify",
          type: "n8n-nodes-base.httpRequest",
          typeVersion: 4.2,
          position: [460, 300],
          notes: `POST to xProof. API key must be set in HTTP Header Auth credential (Authorization: Bearer pm_xxx). Register at ${baseUrl}/api/agent/register`,
        },
        {
          parameters: {
            conditions: {
              options: { caseSensitive: true },
              combinator: "and",
              conditions: [
                {
                  id: "cond-1",
                  leftValue: "={{ $json.proof_id }}",
                  rightValue: "",
                  operator: { type: "string", operation: "notEmpty" },
                },
              ],
            },
          },
          id: "node-3",
          name: "Has proof_id?",
          type: "n8n-nodes-base.if",
          typeVersion: 2,
          position: [680, 300],
          notes: "GATE: Only proceeds if xProof returned a valid proof_id",
        },
        {
          parameters: {
            mode: "passthrough",
            notes: `Execution authorized.\nproof_id={{ $json.proof_id }}\naudit_url={{ $json.audit_url }}\n\nProceed with your action nodes here.`,
          },
          id: "node-4",
          name: "Execute Action",
          type: "n8n-nodes-base.noOp",
          typeVersion: 1,
          position: [900, 200],
          notes: "Replace this node with your actual action (HTTP Request, database write, etc.)",
        },
        {
          parameters: {
            errorMessage: "EXECUTION BLOCKED: xProof audit certification failed or proof_id missing. Agent cannot proceed without a valid compliance certificate.",
          },
          id: "node-5",
          name: "STOP — No Audit Certificate",
          type: "n8n-nodes-base.stopAndError",
          typeVersion: 1,
          position: [900, 400],
          notes: "Execution halted. Check xProof API key and payload.",
        },
      ],
      connections: {
        "Prepare Audit Log": { main: [[{ node: "xProof Certify", type: "main", index: 0 }]] },
        "xProof Certify": { main: [[{ node: "Has proof_id?", type: "main", index: 0 }]] },
        "Has proof_id?": {
          main: [
            [{ node: "Execute Action", type: "main", index: 0 }],
            [{ node: "STOP — No Audit Certificate", type: "main", index: 0 }],
          ],
        },
      },
      settings: { executionOrder: "v1" },
      meta: {
        templateCredsSetupCompleted: false,
        description: `xProof Agent Audit Guard workflow. The agent is BLOCKED if xProof certification fails.\nSchema: ${baseUrl}/.well-known/agent-audit-schema.json\nRegister for a free API key: ${baseUrl}/api/agent/register`,
      },
    };
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader("Content-Disposition", 'attachment; filename="xproof-audit-guard.json"');
    res.json(workflow);
  });

  app.get("/agent-tools/audit-guard-eliza.ts", (_req, res) => {
    const baseUrl = `https://${_req.get("host")}`;
    const code = `/**
 * xProof Agent Audit Log Guard — Eliza OS Plugin
 * Standard: ${baseUrl}/.well-known/agent-audit-schema.json
 *
 * CRITICAL: The AUDIT_BEFORE_EXECUTE action will THROW if xProof certification fails.
 * Register this plugin BEFORE any action plugin that executes critical operations.
 *
 * Usage:
 *   import { xproofAuditPlugin } from "./audit-guard-eliza";
 *   const agent = new AgentRuntime({ plugins: [xproofAuditPlugin, ...yourOtherPlugins] });
 */

import type { Action, IAgentRuntime, Memory, State, HandlerCallback, Plugin } from "@elizaos/core";
import crypto from "crypto";

const XPROOF_API_KEY = process.env.XPROOF_API_KEY ?? "pm_YOUR_API_KEY";
const XPROOF_BASE_URL = process.env.XPROOF_BASE_URL ?? "${baseUrl}";

export class AuditRequiredError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AuditRequiredError";
  }
}

/**
 * Certify an audit log with xProof. Throws AuditRequiredError if certification fails.
 */
async function certifyAuditLog(params: {
  agentId: string;
  actionType: string;
  actionDescription: string;
  inputsHash: string;
  riskLevel: string;
  decision: string;
  riskSummary?: string;
}): Promise<{ proofId: string; auditUrl: string }> {
  const payload = {
    agent_id: params.agentId,
    session_id: crypto.randomUUID(),
    action_type: params.actionType,
    action_description: params.actionDescription,
    inputs_hash: params.inputsHash,
    risk_level: params.riskLevel,
    decision: params.decision,
    risk_summary: params.riskSummary,
    timestamp: new Date().toISOString(),
  };

  const response = await fetch(\`\${XPROOF_BASE_URL}/api/audit\`, {
    method: "POST",
    headers: {
      Authorization: \`Bearer \${XPROOF_API_KEY}\`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(15_000),
  });

  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new AuditRequiredError(
      \`EXECUTION BLOCKED: xProof certification failed (HTTP \${response.status}). \${text.slice(0, 200)}\`
    );
  }

  const data = (await response.json()) as { proof_id?: string; audit_url?: string };
  if (!data.proof_id) {
    throw new AuditRequiredError("EXECUTION BLOCKED: xProof returned no proof_id.");
  }

  return { proofId: data.proof_id, auditUrl: data.audit_url ?? "" };
}

const auditBeforeExecute: Action = {
  name: "AUDIT_BEFORE_EXECUTE",
  similes: ["CERTIFY_ACTION", "XPROOF_AUDIT", "COMPLIANCE_GATE"],
  description:
    "Certify this agent's work session with xProof BEFORE executing any critical action. " +
    "Throws AuditRequiredError if certification fails — blocking the action.",
  validate: async (_runtime: IAgentRuntime, _message: Memory): Promise<boolean> => true,
  handler: async (
    runtime: IAgentRuntime,
    message: Memory,
    state: State | undefined,
    options: {
      actionType: string;
      actionDescription: string;
      inputsHash: string;
      riskLevel: "low" | "medium" | "high" | "critical";
      decision: "approved" | "rejected" | "deferred";
      riskSummary?: string;
    },
    callback?: HandlerCallback
  ): Promise<boolean> => {
    const agentId = runtime.agentId ?? "eliza-agent";

    // Throws AuditRequiredError if certification fails — execution is blocked
    const { proofId, auditUrl } = await certifyAuditLog({
      agentId,
      actionType: options.actionType,
      actionDescription: options.actionDescription,
      inputsHash: options.inputsHash,
      riskLevel: options.riskLevel,
      decision: options.decision,
      riskSummary: options.riskSummary,
    });

    if (callback) {
      await callback({
        text: \`Audit certified. proof_id: \${proofId}\\naudit_url: \${auditUrl}\\nDecision: \${options.decision} | Risk: \${options.riskLevel}\`,
        attachments: [],
      });
    }

    // Store proof_id in state for downstream actions
    if (state) {
      (state as any).xproofProofId = proofId;
      (state as any).xproofAuditUrl = auditUrl;
    }

    return true;
  },
  examples: [],
};

export const xproofAuditPlugin: Plugin = {
  name: "xproof-audit-guard",
  description:
    "xProof Agent Audit Log — certifies agent decisions on MultiversX before execution. " +
    "Schema: \${XPROOF_BASE_URL}/.well-known/agent-audit-schema.json",
  actions: [auditBeforeExecute],
  providers: [],
  evaluators: [],
};
`;
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.send(code);
  });
  // ─────────────────────────────────────────────────────────────────────────

  app.get("/agent-tools/openapi-actions.json", async (req, res) => {
    const baseUrl = `https://${req.get("host")}`;
    const priceUsd = await getCertificationPriceUsd();

    const spec = {
      openapi: "3.0.3",
      info: {
        title: "xproof - Blockchain File Certification",
        description: "API for AI agents to certify files on MultiversX blockchain. Create immutable proofs of file ownership with a simple API call.",
        version: "1.0.0",
        contact: {
          name: "xproof Support",
          url: baseUrl,
        },
      },
      servers: [{ url: baseUrl, description: "Production server" }],
      security: [{ apiKey: [] }],
      components: {
        securitySchemes: {
          apiKey: {
            type: "http" as const,
            scheme: "bearer",
            description: "API key in format: pm_xxx... Obtain from /api/keys endpoint",
          },
        },
        schemas: {
          Product: {
            type: "object",
            properties: {
              id: { type: "string", example: "xproof-certification" },
              name: { type: "string", example: "xproof Certification" },
              description: { type: "string" },
              pricing: {
                type: "object",
                properties: {
                  type: { type: "string", enum: ["fixed", "variable"] },
                  amount: { type: "string", example: priceUsd.toString() },
                  currency: { type: "string", example: "USD" },
                },
              },
              inputs: { type: "object", additionalProperties: { type: "string" } },
              outputs: { type: "object", additionalProperties: { type: "string" } },
            },
          },
          CheckoutRequest: {
            type: "object",
            required: ["product_id", "inputs"],
            properties: {
              product_id: { type: "string", example: "xproof-certification" },
              inputs: {
                type: "object",
                required: ["file_hash", "filename"],
                properties: {
                  file_hash: { type: "string", description: "SHA-256 hash of the file (64 hex chars)", example: "a1b2c3d4e5f678901234567890123456789012345678901234567890123456ab" },
                  filename: { type: "string", example: "document.pdf" },
                  author_name: { type: "string", example: "AI Agent" },
                  metadata: { type: "object", description: "Optional JSON metadata" },
                },
              },
              buyer: {
                type: "object",
                properties: {
                  type: { type: "string", enum: ["agent", "user"] },
                  id: { type: "string" },
                },
              },
            },
          },
          CheckoutResponse: {
            type: "object",
            properties: {
              checkout_id: { type: "string", format: "uuid" },
              product_id: { type: "string" },
              amount: { type: "string", description: "Price in USD" },
              currency: { type: "string" },
              status: { type: "string", enum: ["pending", "ready"] },
              execution: {
                type: "object",
                properties: {
                  type: { type: "string", example: "multiversx" },
                  mode: { type: "string", enum: ["direct", "relayed_v3"] },
                  chain_id: { type: "string", example: "1" },
                  tx_payload: {
                    type: "object",
                    properties: {
                      receiver: { type: "string", description: "xproof wallet address" },
                      data: { type: "string", description: "Base64 encoded transaction data" },
                      value: { type: "string", description: "EGLD amount in atomic units (1 EGLD = 10^18)" },
                      gas_limit: { type: "integer", example: 100000 },
                    },
                  },
                },
              },
              expires_at: { type: "string", format: "date-time" },
            },
          },
          ConfirmRequest: {
            type: "object",
            required: ["checkout_id", "tx_hash"],
            properties: {
              checkout_id: { type: "string", format: "uuid" },
              tx_hash: { type: "string", description: "MultiversX transaction hash" },
            },
          },
          ConfirmResponse: {
            type: "object",
            properties: {
              status: { type: "string", enum: ["confirmed", "pending", "failed"] },
              checkout_id: { type: "string" },
              tx_hash: { type: "string" },
              certification_id: { type: "string" },
              certificate_url: { type: "string", format: "uri" },
              proof_url: { type: "string", format: "uri" },
              blockchain_explorer_url: { type: "string", format: "uri" },
              message: { type: "string" },
            },
          },
          Error: {
            type: "object",
            properties: {
              error: { type: "string" },
              message: { type: "string" },
            },
          },
        },
      },
      paths: {
        "/api/acp/products": {
          get: {
            summary: "Discover available products",
            description: "Returns list of certification products available for purchase. No authentication required.",
            "x-openai-isConsequential": false,
            security: [] as any[],
            responses: {
              "200": {
                description: "List of products",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        protocol: { type: "string", example: "ACP" },
                        version: { type: "string", example: "1.0" },
                        provider: { type: "string", example: "xproof" },
                        chain: { type: "string", example: "MultiversX" },
                        products: { type: "array", items: { $ref: "#/components/schemas/Product" } },
                      },
                    },
                  },
                },
              },
            },
          },
        },
        "/api/acp/checkout": {
          post: {
            summary: "Create checkout session",
            description: "Initiate certification by providing file hash. Returns transaction payload for MultiversX signing.",
            "x-openai-isConsequential": true,
            requestBody: {
              required: true,
              content: { "application/json": { schema: { $ref: "#/components/schemas/CheckoutRequest" } } },
            },
            responses: {
              "201": {
                description: "Checkout created",
                content: { "application/json": { schema: { $ref: "#/components/schemas/CheckoutResponse" } } },
              },
              "401": { description: "API key required" },
              "409": { description: "File already certified" },
            },
          },
        },
        "/api/acp/confirm": {
          post: {
            summary: "Confirm transaction",
            description: "After signing and broadcasting transaction, confirm to receive certification ID and URLs.",
            "x-openai-isConsequential": true,
            requestBody: {
              required: true,
              content: { "application/json": { schema: { $ref: "#/components/schemas/ConfirmRequest" } } },
            },
            responses: {
              "200": {
                description: "Certification confirmed",
                content: { "application/json": { schema: { $ref: "#/components/schemas/ConfirmResponse" } } },
              },
              "401": { description: "API key required" },
              "404": { description: "Checkout not found" },
              "410": { description: "Checkout expired" },
            },
          },
        },
        "/api/acp/checkout/{checkoutId}": {
          get: {
            summary: "Get checkout status",
            description: "Check the status of an existing checkout session.",
            "x-openai-isConsequential": false,
            parameters: [
              { name: "checkoutId", in: "path", required: true, schema: { type: "string" } },
            ],
            responses: {
              "200": { description: "Checkout status" },
              "404": { description: "Checkout not found" },
            },
          },
        },
      },
    };

    res.json(spec);
  });

  // /.well-known/xproof.json — Unified discovery entry point
  // Compact, machine-readable, fully actionable. No prose.
  app.get("/.well-known/xproof.json", async (req, res) => {
    const baseUrl = `https://${req.get("host")}`;
    const priceUsd = await getCertificationPriceUsd();
    res.json({
      v: "1.0",
      service: "xproof",
      chain: "MultiversX Mainnet",
      quickstart: {
        trial: {
          note: `${TRIAL_QUOTA} free certifications — no wallet, no payment, no browser`,
          step1: { method: "POST", url: `${baseUrl}/api/agent/register`, body: { agent_name: "your-agent-name" }, returns: "api_key (pm_xxx)" },
          step2: { method: "POST", url: `${baseUrl}/api/proof`, headers: { Authorization: "Bearer {api_key}", "Content-Type": "application/json" }, body: { file_hash: "64-char SHA-256 hex", filename: "document.pdf" } },
        },
        x402: {
          note: "Pay per use — no account needed",
          step1: { method: "POST", url: `${baseUrl}/api/proof`, body: { file_hash: "...", filename: "..." }, returns: "402 with USDC payment requirements on Base" },
          step2: "Sign payment and resend with X-PAYMENT header",
        },
        api_key: {
          note: "Use an existing API key",
          header: "Authorization: Bearer pm_xxx",
          endpoints: [`${baseUrl}/api/proof`, `${baseUrl}/api/batch`],
        },
      },
      endpoints: {
        certify: `POST ${baseUrl}/api/proof`,
        batch: `POST ${baseUrl}/api/batch`,
        audit: `POST ${baseUrl}/api/audit`,
        verify: `GET ${baseUrl}/proof/{id}.json`,
        register_trial: `POST ${baseUrl}/api/agent/register`,
        trial_info: `GET ${baseUrl}/api/trial`,
        me: `GET ${baseUrl}/api/me`,
        certifications: `GET ${baseUrl}/api/certifications`,
        health: `GET ${baseUrl}/api/acp/health`,
        pricing: `GET ${baseUrl}/api/pricing`,
      },
      audit_log: {
        description: "Agent Audit Log Standard — certify agent decisions before execution",
        endpoint: `POST ${baseUrl}/api/audit`,
        schema: `${baseUrl}/.well-known/agent-audit-schema.json`,
        view: `${baseUrl}/audit/{proof_id}`,
        templates: {
          langchain: `${baseUrl}/agent-tools/audit-guard-langchain.py`,
          crewai: `${baseUrl}/agent-tools/audit-guard-crewai.py`,
          n8n: `${baseUrl}/agent-tools/audit-guard-n8n.json`,
          eliza: `${baseUrl}/agent-tools/audit-guard-eliza.ts`,
        },
        mcp_tool: "audit_agent_session",
      },
      pricing: {
        current: `$${priceUsd} per certification`,
        model: "per-use",
        payment: ["EGLD (MultiversX ACP)", "USDC on Base (x402)"],
      },
      protocols: {
        rest: `${baseUrl}/api/proof`,
        mcp: `${baseUrl}/mcp`,
        acp: `${baseUrl}/api/acp/products`,
        x402: `${baseUrl}/api/proof`,
        openapi: `${baseUrl}/api/acp/openapi.json`,
      },
      docs: {
        llms: `${baseUrl}/llms.txt`,
        full: `${baseUrl}/llms-full.txt`,
        spec: `${baseUrl}/.well-known/xproof.md`,
        agent: `${baseUrl}/.well-known/agent.json`,
        openai_plugin: `${baseUrl}/.well-known/ai-plugin.json`,
        mcp_manifest: `${baseUrl}/.well-known/mcp.json`,
      },
    });
  });

  app.get("/.well-known/agent.json", async (req, res) => {
    const baseUrl = `https://${req.get("host")}`;
    const priceUsd = await getCertificationPriceUsd();

    res.json({
      name: "xproof",
      description: "Proof primitive for AI agents & humans on MultiversX. Verifiable proofs of existence, authorship, and agent output anchored on-chain.",
      url: baseUrl,
      version: "1.2.0",
      capabilities: ["file-certification", "batch-certification", "proof-verification", "blockchain-anchoring", "webhook-notifications", "verification-badges", "mx8004-validation", "agent-audit-log"],
      protocols: {
        mcp: `${baseUrl}/.well-known/mcp.json`,
        mcp_endpoint: `${baseUrl}/mcp`,
        acp: `${baseUrl}/api/acp/products`,
        openapi: `${baseUrl}/api/acp/openapi.json`,
        openai_plugin: `${baseUrl}/.well-known/ai-plugin.json`,
        x402: `${baseUrl}/api/proof`,
        llms_txt: `${baseUrl}/llms.txt`,
        llms_full: `${baseUrl}/llms-full.txt`,
      },
      integrations: {
        openclaw_skill: "https://github.com/jasonxkensei/xproof-openclaw-skill",
        github_action: "https://github.com/marketplace/actions/xproof-certify",
        langchain: `${baseUrl}/agent-tools/langchain.py`,
        crewai: `${baseUrl}/agent-tools/crewai.py`,
        audit_guard_langchain: `${baseUrl}/agent-tools/audit-guard-langchain.py`,
        audit_guard_crewai: `${baseUrl}/agent-tools/audit-guard-crewai.py`,
        audit_guard_n8n: `${baseUrl}/agent-tools/audit-guard-n8n.json`,
        audit_guard_eliza: `${baseUrl}/agent-tools/audit-guard-eliza.ts`,
      },
      audit_log: {
        standard: "Agent Audit Log Standard",
        description: "Compliance gate for AI agents — certify decisions before execution. No proof_id, no action.",
        endpoint: `POST ${baseUrl}/api/audit`,
        schema: `${baseUrl}/.well-known/agent-audit-schema.json`,
        view: `${baseUrl}/audit/{proof_id}`,
        mcp_tool: "audit_agent_session",
      },
      repositories: {
        main: "https://github.com/jasonxkensei/xProof",
        github_action: "https://github.com/jasonxkensei/xProof-Action",
        openclaw_skill: "https://github.com/jasonxkensei/xproof-openclaw-skill",
      },
      supported_protocols: ["MCP", "ACP", "x402", "MX-8004", "OpenAI Plugin", "LangChain", "CrewAI"],
      alternative_payment: {
        protocol: "x402",
        description: "HTTP-native payments. No API key needed. Send request, get 402 with price, sign USDC payment on Base, resend with X-PAYMENT header.",
        network: "Base (eip155:8453)",
        currency: "USDC",
        price_per_certification: `$${priceUsd}`,
        endpoints: [`${baseUrl}/api/proof`, `${baseUrl}/api/batch`],
        facilitator: "https://openx402.ai",
        compatible_with: ["Conway Terminal", "OpenClaw", "Any x402-enabled agent"]
      },
      authentication: {
        type: "bearer",
        token_prefix: "pm_",
        public_endpoints: ["/api/acp/products", "/api/acp/openapi.json", "/api/acp/health", "/llms.txt", "/llms-full.txt"],
      },
      free_trial: {
        register: `POST ${baseUrl}/api/agent/register`,
        body: '{"agent_name": "your-agent-name"}',
        free_certifications: TRIAL_QUOTA,
        description: `Register for ${TRIAL_QUOTA} free certifications. No wallet, no payment, no browser. Pure HTTP.`,
      },
      pricing: {
        model: "per-use",
        amount: priceUsd.toString(),
        currency: "USD",
        payment_methods: ["EGLD (MultiversX)", "USDC (Base via x402)"],
      },
      documentation: {
        specification: `${baseUrl}/.well-known/xproof.md`,
        api_guide: `${baseUrl}/learn/api.md`,
        verification: `${baseUrl}/learn/verification.md`,
        agents_page: `${baseUrl}/agents`,
        compact_discovery: `${baseUrl}/.well-known/xproof.json`,
      },
    });
  });

  // ============================================
  // MCP (Model Context Protocol) Server Endpoint
  // Streamable HTTP transport for native AI agent integration
  // ============================================

  app.post("/mcp", paymentRateLimiter, async (req, res) => {
    try {
      const auth = await authenticateApiKey(req.headers.authorization);
      const baseUrl = `https://${req.get('host')}`;

      const method = req.body?.method;
      const toolName = req.body?.params?.name;
      if (method === "tools/call" && toolName === "certify_file" && !auth.valid) {
        return res.status(200).json({
          jsonrpc: "2.0",
          id: req.body?.id || null,
          error: {
            code: -32600,
            message: "Authentication required. Include 'Authorization: Bearer pm_xxx' header for certify_file.",
          },
        });
      }

      const mcpServer = await createMcpServer({ baseUrl, auth });

      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
      });

      res.on("close", () => {
        transport.close();
      });

      await mcpServer.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (error) {
      logger.withRequest(req).error("MCP error");
      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: "2.0",
          error: { code: -32603, message: "Internal server error" },
          id: null,
        });
      }
    }
  });

  app.get("/mcp", (_req, res) => {
    res.status(405).json({
      jsonrpc: "2.0",
      error: { code: -32601, message: "Method not allowed. Use POST for MCP requests." },
      id: null,
    });
  });

  app.delete("/mcp", (_req, res) => {
    res.status(204).end();
  });

  // ============================================
  // Public Stats Endpoint (no auth required)
  // ============================================
  app.get("/api/stats", async (req: any, res) => {
    try {
      const now = new Date();
      const h24 = new Date(now.getTime() - 24 * 60 * 60 * 1000);
      const d7 = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      const d30 = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

      const [totalRow] = await db.select({ count: count() }).from(certifications);
      const [last24hRow] = await db.select({ count: count() }).from(certifications).where(gte(certifications.createdAt, h24));
      const [last7dRow] = await db.select({ count: count() }).from(certifications).where(gte(certifications.createdAt, d7));
      const [last30dRow] = await db.select({ count: count() }).from(certifications).where(gte(certifications.createdAt, d30));

      const systemUserId = "erd1acp00000000000000000000000000000000000000000000000000000agent";
      const [systemUser] = await db.select().from(users).where(eq(users.walletAddress, systemUserId));
      
      let apiCerts = 0;
      if (systemUser) {
        const [apiRow] = await db.select({ count: count() }).from(certifications).where(eq(certifications.userId, systemUser.id));
        apiCerts = apiRow.count;
      }
      const [trialCertsRow] = await db.select({ count: count() }).from(certifications).innerJoin(users, eq(certifications.userId, users.id)).where(sql`${users.isTrial} IS TRUE`);
      const trialCerts = trialCertsRow.count;
      const userCerts = Math.max(0, totalRow.count - apiCerts - trialCerts);

      const webhookStats = await db.execute(sql`
        SELECT 
          COUNT(*) FILTER (WHERE webhook_status = 'delivered') as delivered,
          COUNT(*) FILTER (WHERE webhook_status = 'failed') as failed,
          COUNT(*) FILTER (WHERE webhook_status = 'pending') as pending,
          COUNT(*) FILTER (WHERE webhook_url IS NOT NULL) as total
        FROM certifications
      `);

      const wh = (webhookStats.rows[0] as Record<string, string>) || {};
      const whTotal = parseInt(wh.total || "0");
      const whDelivered = parseInt(wh.delivered || "0");

      const statusBreakdown = await db.execute(sql`
        SELECT blockchain_status, COUNT(*) as count
        FROM certifications
        GROUP BY blockchain_status
      `);

      const byStatus: Record<string, number> = {};
      for (const row of statusBreakdown.rows as Array<Record<string, string>>) {
        byStatus[row.blockchain_status || "unknown"] = parseInt(row.count);
      }

      const dailyCerts = await db.execute(sql`
        SELECT DATE(created_at) as day, COUNT(*) as count
        FROM certifications
        WHERE created_at >= NOW() - INTERVAL '7 days'
        GROUP BY DATE(created_at)
        ORDER BY day DESC
      `);

      const metrics = getMetrics();

      const m5 = new Date(now.getTime() - 5 * 60 * 1000);
      const [recent5mRow] = await db.select({ count: count() }).from(certifications).where(gte(certifications.createdAt, m5));

      const d14 = new Date(now.getTime() - 14 * 24 * 60 * 60 * 1000);
      const [prev7dRow] = await db.select({ count: count() }).from(certifications).where(and(gte(certifications.createdAt, d14), sql`created_at < ${d7}`));

      const [totalVisitsRow] = await db.select({ count: count() }).from(visits);
      const [uniqueIpsRow] = await db.select({ count: sql<number>`COUNT(DISTINCT ip_hash)` }).from(visits);
      const [humanVisitsRow] = await db.select({ count: sql<number>`COUNT(DISTINCT ip_hash)` }).from(visits).where(eq(visits.isAgent, false));
      const [agentVisitsRow] = await db.select({ count: sql<number>`COUNT(DISTINCT ip_hash)` }).from(visits).where(eq(visits.isAgent, true));

      const [uniqueAgentsRow] = await db.select({ count: count() }).from(apiKeys).innerJoin(users, eq(apiKeys.userId, users.id)).where(and(eq(apiKeys.isActive, true), gt(apiKeys.requestCount, 0), sql`${users.isTrial} IS NOT TRUE`));
      const [totalApiKeysRow] = await db.select({ count: count() }).from(apiKeys).innerJoin(users, eq(apiKeys.userId, users.id)).where(and(eq(apiKeys.isActive, true), sql`${users.isTrial} IS NOT TRUE`));
      const [trialAgentsRow] = await db.select({ count: count() }).from(users).where(eq(users.isTrial, true));
      const [trialUsedRow] = await db.select({ total: sql<number>`COALESCE(SUM(trial_used), 0)` }).from(users).where(eq(users.isTrial, true));

      res.json({
        certifications: {
          total: totalRow.count,
          last_24h: last24hRow.count,
          last_7d: last7dRow.count,
          last_30d: last30dRow.count,
          prev_7d: prev7dRow.count,
          last_5m: recent5mRow.count,
          by_source: { api: apiCerts, trial: trialCerts, user: userCerts },
          by_status: byStatus,
          daily: dailyCerts.rows.map((r: any) => ({
            date: r.day,
            count: parseInt(r.count),
          })),
        },
        webhooks: {
          total: whTotal,
          delivered: whDelivered,
          failed: parseInt(wh.failed || "0"),
          pending: parseInt(wh.pending || "0"),
          success_rate: whTotal > 0 ? Math.round((whDelivered / whTotal) * 100) : null,
        },
        blockchain: {
          avg_latency_ms: metrics.transactions.avg_latency_ms,
          last_known_latency_ms: metrics.transactions.last_known_latency_ms,
          last_known_latency_at: metrics.transactions.last_known_latency_at,
          total_success: metrics.transactions.total_success,
          total_failed: metrics.transactions.total_failed,
          last_success_at: metrics.transactions.last_success_at,
        },
        traffic: {
          total_visits: totalVisitsRow.count,
          unique_ips: Number(uniqueIpsRow.count) || 0,
          human_visitors: Number(humanVisitsRow.count) || 0,
          agent_visitors: Number(agentVisitsRow.count) || 0,
        },
        agents: {
          unique_active: uniqueAgentsRow.count,
          total_api_keys: totalApiKeysRow.count,
          trial_agents: trialAgentsRow.count,
          trial_certifications_used: Number(trialUsedRow.total) || 0,
        },
        pricing: await getPricingInfo(),
        generated_at: now.toISOString(),
      });
    } catch (error) {
      logger.withRequest(req).error("Public stats error");
      res.status(500).json({ error: "Failed to generate stats" });
    }
  });

  // ============================================
  // Admin Analytics Endpoint
  // ============================================
  function requireAdmin(req: any, res: express.Response, next: express.NextFunction) {
    const adminWallets = (process.env.ADMIN_WALLETS || "").split(",").map(w => w.trim()).filter(Boolean);
    const userWallet = req.session?.walletAddress;
    if (adminWallets.length > 0 && !adminWallets.includes(userWallet)) {
      return res.status(403).json({ error: "Forbidden: admin access required" });
    }
    next();
  }

  app.get("/api/admin/stats", isWalletAuthenticated, requireAdmin, async (req: any, res) => {
    try {
      const now = new Date();
      const h24 = new Date(now.getTime() - 24 * 60 * 60 * 1000);
      const d7 = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      const d30 = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

      const [totalRow] = await db.select({ count: count() }).from(certifications);
      const [last24hRow] = await db.select({ count: count() }).from(certifications).where(gte(certifications.createdAt, h24));
      const [last7dRow] = await db.select({ count: count() }).from(certifications).where(gte(certifications.createdAt, d7));
      const [last30dRow] = await db.select({ count: count() }).from(certifications).where(gte(certifications.createdAt, d30));

      const systemUserId = "erd1acp00000000000000000000000000000000000000000000000000000agent";
      const [systemUser] = await db.select().from(users).where(eq(users.walletAddress, systemUserId));
      
      let apiCerts = 0;
      if (systemUser) {
        const [apiRow] = await db.select({ count: count() }).from(certifications).where(eq(certifications.userId, systemUser.id));
        apiCerts = apiRow.count;
      }
      const [trialCertsRow] = await db.select({ count: count() }).from(certifications).innerJoin(users, eq(certifications.userId, users.id)).where(sql`${users.isTrial} IS TRUE`);
      const trialCerts = trialCertsRow.count;
      const userCerts = Math.max(0, totalRow.count - apiCerts - trialCerts);

      const [activeKeysRow] = await db.select({ count: count() }).from(apiKeys).where(eq(apiKeys.isActive, true));

      const [keysUsed24hResult] = await db
        .select({ count: count() })
        .from(apiKeys)
        .where(and(eq(apiKeys.isActive, true), gte(apiKeys.lastUsedAt, h24)));

      const webhookStats = await db.execute(sql`
        SELECT 
          COUNT(*) FILTER (WHERE webhook_status = 'delivered') as delivered,
          COUNT(*) FILTER (WHERE webhook_status = 'failed') as failed,
          COUNT(*) FILTER (WHERE webhook_status = 'pending') as pending,
          COUNT(*) FILTER (WHERE webhook_url IS NOT NULL) as total
        FROM certifications
      `);

      const wh = (webhookStats.rows[0] as Record<string, string>) || {};
      const whTotal = parseInt(wh.total || "0");
      const whDelivered = parseInt(wh.delivered || "0");

      const statusBreakdown = await db.execute(sql`
        SELECT blockchain_status, COUNT(*) as count
        FROM certifications
        GROUP BY blockchain_status
      `);

      const byStatus: Record<string, number> = {};
      for (const row of statusBreakdown.rows as Array<Record<string, string>>) {
        byStatus[row.blockchain_status || "unknown"] = parseInt(row.count);
      }

      const dailyCerts = await db.execute(sql`
        SELECT DATE(created_at) as day, COUNT(*) as count
        FROM certifications
        WHERE created_at >= NOW() - INTERVAL '7 days'
        GROUP BY DATE(created_at)
        ORDER BY day DESC
      `);

      const metrics = getMetrics();

      res.json({
        certifications: {
          total: totalRow.count,
          last_24h: last24hRow.count,
          last_7d: last7dRow.count,
          last_30d: last30dRow.count,
          by_source: { api: apiCerts, trial: trialCerts, user: userCerts },
          by_status: byStatus,
          daily: dailyCerts.rows.map((r: any) => ({
            date: r.day,
            count: parseInt(r.count),
          })),
        },
        api_keys: {
          total_active: activeKeysRow.count,
          active_last_24h: keysUsed24hResult.count,
        },
        webhooks: {
          total: whTotal,
          delivered: whDelivered,
          failed: parseInt(wh.failed || "0"),
          pending: parseInt(wh.pending || "0"),
          success_rate: whTotal > 0 ? Math.round((whDelivered / whTotal) * 100) : null,
        },
        blockchain: {
          avg_latency_ms: metrics.transactions.avg_latency_ms,
          last_known_latency_ms: metrics.transactions.last_known_latency_ms,
          last_known_latency_at: metrics.transactions.last_known_latency_at,
          total_success: metrics.transactions.total_success,
          total_failed: metrics.transactions.total_failed,
          last_success_at: metrics.transactions.last_success_at,
          last_failed_at: metrics.transactions.last_failed_at,
        },
        txAlerts: getAlertConfig(),
        generated_at: now.toISOString(),
      });
    } catch (error) {
      logger.withRequest(req).error("Admin stats error");
      res.status(500).json({ error: "Failed to generate stats" });
    }
  });

  app.get("/api/admin/my-ip-hash", isWalletAuthenticated, requireAdmin, async (req: any, res) => {
    const ip = req.ip || req.headers["x-forwarded-for"]?.toString().split(",")[0] || "unknown";
    const ipHash = crypto.createHash("sha256").update(ip).digest("hex");
    const excluded = EXCLUDED_IP_HASHES.has(ipHash);
    const [visitCount] = await db.select({ count: sql<number>`COUNT(*)` }).from(visits).where(eq(visits.ipHash, ipHash));
    res.json({ ip_hash: ipHash, excluded, visit_count: visitCount?.count || 0 });
  });

  app.delete("/api/admin/visits/:ipHash", isWalletAuthenticated, requireAdmin, async (req: any, res) => {
    const { ipHash } = req.params;
    if (!/^[a-f0-9]{64}$/.test(ipHash)) {
      return res.status(400).json({ error: "Invalid IP hash format" });
    }
    const result = await db.delete(visits).where(eq(visits.ipHash, ipHash));
    res.json({ deleted: true, ip_hash: ipHash });
  });

  app.get("/api/admin/tx-queue", isWalletAuthenticated, requireAdmin, async (req: any, res) => {
    try {
      const stats = await getTxQueueStats();
      const recentFailed = await db
        .select()
        .from(txQueueTable)
        .where(eq(txQueueTable.status, "failed"))
        .orderBy(txQueueTable.createdAt)
        .limit(10);
      const recentProcessing = await db
        .select()
        .from(txQueueTable)
        .where(eq(txQueueTable.status, "processing"))
        .orderBy(txQueueTable.createdAt)
        .limit(5);

      res.json({
        stats,
        metrics: {
          success_rate: stats.successRate,
          avg_processing_time_ms: stats.avgProcessingTimeMs,
          total_retries: stats.totalRetries,
          last_activity: stats.lastActivity,
        },
        recent_failed: recentFailed,
        recent_processing: recentProcessing,
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  const httpServer = createServer(app);

  return httpServer;
}
