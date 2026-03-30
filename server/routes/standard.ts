import { type Express } from "express";
import crypto from "crypto";
import { db, pool } from "../db";
import { logger } from "../logger";
import { certifications, users, apiKeys } from "@shared/schema";
import { eq, sql } from "drizzle-orm";
import { z } from "zod";
import { paymentRateLimiter, publicReadRateLimiter } from "../reliability";
import { isX402Configured, verifyX402Payment, send402Response } from "../x402";
import { recordOnBlockchain, isMultiversXConfigured } from "../blockchain";
import { getCertificationPriceEgld, getCertificationPriceUsd } from "../pricing";
import { isMX8004Configured, recordCertificationAsJob } from "../mx8004";
import { isAdminWallet, getApiKeyOwnerWallet, getTrialUser, consumeTrialCredit, getUserCreditBalance, consumeCredit, buildCanonicalId } from "./helpers";

export function registerStandardRoutes(app: Express) {
  app.post("/api/standard/validate", publicReadRateLimiter, async (req, res) => {
    try {
      const { proof } = req.body;
      if (!proof) {
        return res.status(400).json({
          valid: false,
          error: "Missing 'proof' in request body",
          standard: "https://github.com/xproof-io/agent-proof-standard",
        });
      }

      const result = standardProofSchema.safeParse(proof);
      if (!result.success) {
        const fieldErrors: Record<string, string> = {};
        for (const issue of result.error.issues) {
          const path = issue.path.join(".");
          fieldErrors[path || "root"] = issue.message;
        }
        return res.json({
          valid: false,
          errors: fieldErrors,
          standard_version: "1.0",
        });
      }

      const canonical = `${proof.version}|${proof.agent_id}|${proof.instruction_hash}|${proof.action_hash}|${proof.timestamp}`;
      const canonicalHash = crypto.createHash("sha256").update(canonical).digest("hex");

      return res.json({
        valid: true,
        standard_version: "1.0",
        canonical_hash: canonicalHash,
        fields_present: {
          action_type: !!proof.action_type,
          post_id: !!proof.post_id,
          target_author: !!proof.target_author,
          session_id: !!proof.session_id,
          chain_anchor: !!proof.chain_anchor,
          metadata: !!proof.metadata,
        },
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post("/api/standard/anchor", paymentRateLimiter, async (req, res) => {
    try {
      const { proof } = req.body;
      if (!proof) {
        return res.status(400).json({
          error: "Missing 'proof' in request body",
          standard: "https://github.com/xproof-io/agent-proof-standard",
        });
      }

      const parseResult = standardProofSchema.safeParse(proof);
      if (!parseResult.success) {
        const fieldErrors: Record<string, string> = {};
        for (const issue of parseResult.error.issues) {
          fieldErrors[issue.path.join(".") || "root"] = issue.message;
        }
        return res.status(400).json({
          error: "INVALID_PROOF_FORMAT",
          errors: fieldErrors,
        });
      }

      let authMethod: "api_key" | "x402" = "api_key";
      let apiKeyUserId: string | null = null;
      const authHeader = req.headers.authorization;
      const hasBearerToken = authHeader && authHeader.startsWith("Bearer ");
      const hasX402Payment = !!req.headers["x-payment"];

      if (hasBearerToken) {
        const rawKey = authHeader!.slice(7);
        if (!rawKey.startsWith("pm_")) {
          return res.status(401).json({ error: "INVALID_API_KEY", message: "API key must start with 'pm_' prefix" });
        }
        const keyHash = crypto.createHash("sha256").update(rawKey).digest("hex");
        const [apiKey] = await db.select().from(apiKeys).where(eq(apiKeys.keyHash, keyHash));
        if (!apiKey || !apiKey.isActive) {
          return res.status(401).json({ error: "INVALID_API_KEY", message: "Invalid or expired API key" });
        }
        apiKeyUserId = apiKey.userId || null;
        authMethod = "api_key";

        db.update(apiKeys)
          .set({ lastUsedAt: new Date(), requestCount: (apiKey.requestCount || 0) + 1 })
          .where(eq(apiKeys.id, apiKey.id))
          .execute()
          .catch((err) => logger.error("Failed to update API key stats", { error: err.message }));
      } else if (hasX402Payment && isX402Configured()) {
        const x402Result = await verifyX402Payment(req, "proof");
        if (!x402Result.valid) {
          return res.status(402).json({ error: "PAYMENT_FAILED", message: x402Result.error || "x402 payment verification failed" });
        }
        authMethod = "x402";
        res.setHeader("X-Payment-Method", "x402");
      } else if (isX402Configured()) {
        return await send402Response(res, req, "proof");
      } else {
        return res.status(401).json({
          error: "AUTH_REQUIRED",
          message: "Standard anchor requires API key (Bearer pm_...) or x402 payment",
        });
      }

      const canonical = `${proof.version}|${proof.agent_id}|${proof.instruction_hash}|${proof.action_hash}|${proof.timestamp}`;
      const canonicalHash = crypto.createHash("sha256").update(canonical).digest("hex");

      const fileName = `standard_proof_${proof.agent_id.slice(0, 20)}_${Date.now()}`;
      const authorName = proof.agent_id;

      if (!isMultiversXConfigured()) {
        return res.status(503).json({ error: "Blockchain anchoring is not configured" });
      }

      const result = await recordOnBlockchain(canonicalHash, fileName, authorName);

      const standardMetadata = {
        standard_version: proof.version,
        standard_proof: true,
        agent_id: proof.agent_id,
        instruction_hash: proof.instruction_hash,
        action_hash: proof.action_hash,
        signature: proof.signature,
        ...(proof.action_type && { action_type: proof.action_type }),
        ...(proof.post_id && { post_id: proof.post_id }),
        ...(proof.target_author && { target_author: proof.target_author }),
        ...(proof.session_id && { session_id: proof.session_id }),
        ...(proof.metadata || {}),
      };

      const userId = apiKeyUserId || "standard-anchor";

      const [cert] = await db.insert(certifications).values({
        userId,
        fileName,
        fileHash: canonicalHash,
        fileType: "application/x-agent-proof-standard",
        authorName,
        transactionHash: result.transactionHash,
        transactionUrl: result.explorerUrl,
        blockchainStatus: result.status === "confirmed" ? "confirmed" : "pending",
        authMethod,
        metadata: standardMetadata,
        isPublic: true,
      }).returning();

      const baseUrl = `https://${req.get("host")}`;

      return res.status(201).json({
        proof_id: cert.id,
        canonical_hash: canonicalHash,
        chain_anchor: {
          chain: "multiversx",
          network: "mainnet",
          tx_hash: result.transactionHash,
          explorer_url: result.explorerUrl,
          status: result.status,
        },
        proof_url: `${baseUrl}/proof/${cert.id}`,
        standard_version: "1.0",
        auth_method: authMethod,
      });
    } catch (err: any) {
      logger.error("Standard anchor error", { error: err.message });
      res.status(500).json({ error: err.message });
    }
  });

  app.get("/api/standard/spec", publicReadRateLimiter, (_req, res) => {
    res.json({
      name: "Agent Proof Standard",
      version: "1.0",
      description: "Open format for certifying AI agent actions with cryptographic accountability",
      license: "CC0 1.0 Universal (Public Domain)",
      endpoints: {
        validate: "POST /api/standard/validate — Free format validation (no auth)",
        anchor: "POST /api/standard/anchor — Blockchain anchoring (API key or x402)",
        spec: "GET /api/standard/spec — This specification",
      },
      proof_format: {
        required: ["version", "agent_id", "instruction_hash", "action_hash", "timestamp", "signature"],
        optional: ["action_type", "post_id", "target_author", "session_id", "chain_anchor", "metadata"],
      },
      signature_scheme: {
        canonical: "version|agent_id|instruction_hash|action_hash|timestamp",
        algorithms: ["Ed25519", "ECDSA (secp256k1)"],
        format: "hex:<hex-encoded-signature>",
      },
      hash_format: "sha256:<64-hex-chars>",
      trust_integration: "Proofs anchored via this standard contribute to xProof trust scores",
    });
  });
}
