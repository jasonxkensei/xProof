import { type Express } from "express";
import crypto from "crypto";
import { db } from "../db";
import { logger } from "../logger";
import { apiKeys, creditPurchases } from "@shared/schema";
import { eq } from "drizzle-orm";
import { CREDIT_PACKAGES, getPackage, verifyUsdcOnBase } from "../credits";
import { addCredits, getUserCreditBalance } from "./helpers";

export function registerCreditsRoutes(app: Express) {
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
}
