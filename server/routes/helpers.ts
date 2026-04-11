import express from "express";
import crypto from "crypto";
import { db } from "../db";
import { logger } from "../logger";
import { users, apiKeys } from "@shared/schema";
import { eq, and, gte } from "drizzle-orm";
import { sql } from "drizzle-orm";

export const TRIAL_QUOTA = 10;

const rateLimitMap = new Map<string, { count: number; resetAt: number }>();
const RATE_LIMIT_MAX = 100;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;

export function checkRateLimit(identifier: string): { allowed: boolean; remaining: number; resetAt: number } {
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

export const RATE_LIMIT_MAX_VALUE = RATE_LIMIT_MAX;

export async function validateApiKey(req: express.Request, res: express.Response, next: express.NextFunction) {
  const authHeader = req.headers.authorization;

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

  (req as any).apiKey = apiKey;
  next();
}

export function isAdminWallet(walletAddress: string): boolean {
  const adminWallets = (process.env.ADMIN_WALLETS || "").split(",").map(w => w.trim()).filter(Boolean);
  return adminWallets.includes(walletAddress);
}

export async function getApiKeyOwnerWallet(apiKeyRecord: any): Promise<string | null> {
  if (!apiKeyRecord?.userId) return null;
  const [user] = await db.select().from(users).where(eq(users.id, apiKeyRecord.userId));
  return user?.walletAddress || null;
}

export async function getTrialUser(apiKeyRecord: any): Promise<{ isTrial: boolean; remaining: number; userId: string } | null> {
  if (!apiKeyRecord?.userId) return null;
  const [user] = await db.select().from(users).where(eq(users.id, apiKeyRecord.userId));
  if (!user || !user.isTrial) return null;
  return {
    isTrial: true,
    remaining: (user.trialQuota || 0) - (user.trialUsed || 0),
    userId: user.id,
  };
}

export async function consumeTrialCredit(userId: string, count: number = 1): Promise<void> {
  await db.update(users)
    .set({ trialUsed: sql`trial_used + ${count}` })
    .where(eq(users.id, userId));
}

export async function getUserCreditBalance(userId: string): Promise<number> {
  const [user] = await db.select({ creditBalance: users.creditBalance }).from(users).where(eq(users.id, userId));
  return user?.creditBalance ?? 0;
}

export async function consumeCredit(userId: string, count: number = 1): Promise<void> {
  await db.update(users)
    .set({ creditBalance: sql`GREATEST(0, credit_balance - ${count})` })
    .where(eq(users.id, userId));
}

export async function addCredits(userId: string, amount: number): Promise<void> {
  await db.update(users)
    .set({ creditBalance: sql`credit_balance + ${amount}` })
    .where(eq(users.id, userId));
}

export const registerRateLimitMap = new Map<string, { count: number; resetAt: number }>();
export const REGISTER_RATE_LIMIT_MAX = 10;
export const REGISTER_RATE_LIMIT_WINDOW_MS = 60 * 60 * 1000;

export function requireAdmin(req: any, res: express.Response, next: express.NextFunction) {
  const adminSecret = process.env.ADMIN_SECRET;
  if (adminSecret && req.headers["x-admin-secret"] === adminSecret) {
    return next();
  }
  const adminWallets = (process.env.ADMIN_WALLETS || "").split(",").map(w => w.trim()).filter(Boolean);
  const userWallet = req.session?.walletAddress;
  if (adminWallets.length > 0 && !adminWallets.includes(userWallet)) {
    return res.status(403).json({ error: "Forbidden: admin access required" });
  }
  next();
}

export function getNetworkLabel(chainId: string): string {
  switch (chainId) {
    case "1": return "mainnet";
    case "D": return "devnet";
    case "T": return "testnet";
    default: return "mainnet";
  }
}

export function buildCanonicalId(chainId: string, txHash: string | null): string | null {
  if (!txHash) return null;
  return `xproof:mvx:${getNetworkLabel(chainId)}:tx:${txHash}`;
}

export const EXCLUDED_IP_HASHES = new Set((process.env.EXCLUDE_IP_HASHES || "").split(",").map(h => h.trim()).filter(Boolean));

// ── Context Drift Computation ─────────────────────────────────────────────────
// Reusable helper: takes an ordered array of metadata objects (earliest first)
// and returns a drift summary. Used by the confidence-trail endpoint and the
// agent profile endpoint so both surfaces expose coherence data to consumers.

export const DRIFT_MONITORED_FIELDS = [
  "model_hash",
  "tools_version",
  "strategy_snapshot",
  "operator_scope",
] as const;

export interface DriftSummary {
  context_coherent: boolean;
  drift_score: number;
  fields_monitored: string[];
  fields_drifted: string[];
  fields_stable: string[];
  fields_absent: string[];
}

export function computeDrift(
  metadataRows: Record<string, any>[]
): DriftSummary {
  const FIELDS = DRIFT_MONITORED_FIELDS as unknown as string[];

  const contexts = metadataRows.map(meta => {
    const ctx: Record<string, string | null> = {};
    for (const f of FIELDS) ctx[f] = meta[f] ?? null;
    return ctx;
  });

  const fieldsDriftedSet = new Set<string>();
  let totalComparisons = 0;
  let totalDrifts = 0;

  for (let i = 1; i < contexts.length; i++) {
    const prev = contexts[i - 1];
    const curr = contexts[i];
    for (const f of FIELDS) {
      if (curr[f] !== null && prev[f] !== null) {
        totalComparisons++;
        if (curr[f] !== prev[f]) {
          totalDrifts++;
          fieldsDriftedSet.add(f);
        }
      }
    }
  }

  const fieldsAbsent = FIELDS.filter(f => contexts.every(c => c[f] === null));
  const fieldsDrifted = Array.from(fieldsDriftedSet);
  const fieldsStable = FIELDS.filter(
    f => !fieldsAbsent.includes(f) && !fieldsDrifted.includes(f)
  );
  const driftScore =
    totalComparisons > 0
      ? Math.round((totalDrifts / totalComparisons) * 100) / 100
      : 0;

  return {
    context_coherent: fieldsDrifted.length === 0,
    drift_score: driftScore,
    fields_monitored: FIELDS,
    fields_drifted: fieldsDrifted,
    fields_stable: fieldsStable,
    fields_absent: fieldsAbsent,
  };
}
