import { type Express } from "express";
import crypto from "crypto";
import { db } from "../db";
import { logger } from "../logger";
import { certifications, users, apiKeys } from "@shared/schema";
import { eq, desc, sql, and, count } from "drizzle-orm";
import { z } from "zod";
import { isWalletAuthenticated } from "../walletAuth";
import { getCertificationPriceEgld } from "../pricing";
import { recordOnBlockchain, broadcastSignedTransaction } from "../blockchain";

export function registerCertificationsRoutes(app: Express) {
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

        const { verifyTransactionOnChain } = await import("../verifyTransaction");
        const { recordTransaction } = await import("../metrics");

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
          authMethod: "web",
          ...(blockchainLatencyMs !== null ? { blockchainLatencyMs } : {}),
        })
        .returning();

      if (blockchainStatus === "pending") {
        const { scheduleVerificationRetry } = await import("../verifyTransaction");
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

        const { verifyTransactionOnChain } = await import("../verifyTransaction");
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
            authMethod: "web",
          })
          .returning();

        if (broadcastBlockchainStatus === "pending") {
          const { scheduleVerificationRetry } = await import("../verifyTransaction");
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
}
