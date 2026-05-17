import { type Express, type Request, type Response, type NextFunction } from "express";
import { db, pool } from "../db";
import { logger } from "../logger";
import { certifications, users, agentOutcomes, apiKeys } from "@shared/schema";
import { eq, or, and, gte } from "drizzle-orm";
import { z } from "zod";
import crypto from "crypto";
import { validateApiKey } from "./helpers";
import { publicCalibrationRateLimiter, outcomeSubmitRateLimiter, calibrationCsvExportRateLimiter } from "../reliability";
import { pgCheckRateLimit } from "../pgRateLimit";

// ── 30-second in-memory cache for GET /api/agent/calibration/:agentId ────────
// Keyed by `${agentId}:${n}` so different ?n values are cached independently.
// Mirrors the pattern used in admin.ts for /api/stats.
const CALIBRATION_CACHE_TTL_MS = 30_000;
const calibrationCache = new Map<string, { body: object; cachedAt: number }>();

// Evict expired entries every 5 minutes to prevent stale accumulation over
// long uptimes (e.g. many unique agentId/n combinations building up).
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of calibrationCache) {
    if (now - entry.cachedAt >= CALIBRATION_CACHE_TTL_MS) {
      calibrationCache.delete(key);
    }
  }
}, 5 * 60 * 1000).unref();

// ── Bias label thresholds — intentionally fixed, revisit after real data ──────
// mean_gap = anchored_confidence − outcome_score
// Positive gap → agent predicted higher than reality → overconfident
// Negative gap → agent predicted lower than reality → underconfident
const OVERCONFIDENT_THRESHOLD = 0.10;
const UNDERCONFIDENT_THRESHOLD = -0.10;

function biasLabel(meanGap: number): "overconfident" | "underconfident" | "calibrated" {
  if (meanGap > OVERCONFIDENT_THRESHOLD) return "overconfident";
  if (meanGap < UNDERCONFIDENT_THRESHOLD) return "underconfident";
  return "calibrated";
}

const outcomeSubmitSchema = z.object({
  proof_id: z.string().min(1, "proof_id is required"),
  outcome_score: z
    .number({ required_error: "outcome_score is required", invalid_type_error: "outcome_score must be a number" })
    .min(0, "outcome_score must be >= 0")
    .max(1, "outcome_score must be <= 1"),
  visibility: z.enum(["public", "private"]).default("public"),
});

// ── Optional API-key extractor (non-blocking — sets req.optionalUserId) ──────
// Mirrors validateApiKey semantics: checks primary hash then rotated-key hash.
async function optionalApiKey(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers["authorization"];
  if (!authHeader || !authHeader.startsWith("Bearer ")) return next();
  const rawKey = authHeader.slice(7);
  if (!rawKey.startsWith("pm_")) return next();
  try {
    const keyHash = crypto.createHash("sha256").update(rawKey).digest("hex");
    let [key] = await db
      .select({ userId: apiKeys.userId, isActive: apiKeys.isActive })
      .from(apiKeys)
      .where(eq(apiKeys.keyHash, keyHash))
      .limit(1);
    // Rotated-key fallback: check previousKeyHash within its grace period
    if (!key) {
      const [rotated] = await db
        .select({ userId: apiKeys.userId, isActive: apiKeys.isActive })
        .from(apiKeys)
        .where(and(eq(apiKeys.previousKeyHash, keyHash), gte(apiKeys.previousKeyExpiresAt, new Date())))
        .limit(1);
      if (rotated) key = rotated;
    }
    if (key?.isActive) (req as any).optionalUserId = key.userId;
  } catch {
    // silent — optional auth, keep going
  }
  next();
}

export function registerCalibrationRoutes(app: Express) {
  // ── POST /api/agent/outcome ───────────────────────────────────────────────
  // Auth: Authorization: Bearer pm_xxx (operator only, not the agent itself)
  // Submits the actual outcome for a decision previously anchored with
  // metadata.confidence_level. Computes and stores the calibration gap.
  app.post("/api/agent/outcome", validateApiKey, outcomeSubmitRateLimiter, async (req, res) => {
    try {
      const parsed = outcomeSubmitSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({
          error: "VALIDATION_ERROR",
          message: "Invalid request data",
          details: parsed.error.errors,
        });
      }

      const { proof_id, outcome_score, visibility } = parsed.data;
      const apiKey = (req as any).apiKey;

      // Fetch the certification and verify ownership
      const [cert] = await db
        .select()
        .from(certifications)
        .where(eq(certifications.id, proof_id))
        .limit(1);

      if (!cert) {
        return res.status(404).json({
          error: "PROOF_NOT_FOUND",
          message: `No certification found with proof_id: ${proof_id}`,
        });
      }

      // Ownership check: certification must belong to the API key's user
      if (cert.userId !== apiKey.userId) {
        return res.status(403).json({
          error: "FORBIDDEN",
          message: "You can only submit outcomes for proofs anchored by your own API key.",
        });
      }

      // Verify the certification carries a confidence_level
      const meta = (cert.metadata as Record<string, any>) ?? {};
      const rawAnchored = meta.confidence_level;
      if (rawAnchored === undefined || rawAnchored === null) {
        return res.status(422).json({
          error: "NO_CONFIDENCE_LEVEL",
          message: "This proof has no metadata.confidence_level. Confidence gap tracking requires a proof anchored with confidence_level.",
          tip: "Anchor proofs with metadata.confidence_level (0.0–1.0) to enable calibration tracking.",
        });
      }

      const anchoredNum = Number(rawAnchored);
      if (!Number.isFinite(anchoredNum) || anchoredNum < 0 || anchoredNum > 1) {
        return res.status(422).json({
          error: "INVALID_CONFIDENCE_LEVEL",
          message: `The proof's metadata.confidence_level (${rawAnchored}) is not a valid number between 0.0 and 1.0.`,
        });
      }

      const confidenceGap = Math.round((anchoredNum - outcome_score) * 10000) / 10000;

      // Insert — unique index on certification_id prevents duplicate submissions
      try {
        const [inserted] = await db
          .insert(agentOutcomes)
          .values({
            certificationId: cert.id,
            userId: apiKey.userId,
            anchoredConfidence: anchoredNum,
            outcomeScore: outcome_score,
            confidenceGap,
            visibility,
          })
          .returning();

        logger.info("Agent outcome submitted", {
          component: "calibration",
          certificationId: cert.id,
          userId: apiKey.userId,
          anchoredConfidence: anchoredNum,
          outcomeScore: outcome_score,
          confidenceGap,
        });

        return res.status(201).json({
          outcome_id: inserted.id,
          proof_id: cert.id,
          anchored_confidence: anchoredNum,
          outcome_score,
          confidence_gap: confidenceGap,
          bias_hint: biasLabel(confidenceGap),
          visibility: inserted.visibility,
          submitted_at: inserted.submittedAt,
        });
      } catch (err: any) {
        // Unique constraint violation — outcome already submitted for this proof
        if (err?.code === "23505" || err?.message?.includes("unique")) {
          return res.status(409).json({
            error: "OUTCOME_ALREADY_SUBMITTED",
            message: "An outcome has already been submitted for this proof. Each proof can only have one outcome.",
          });
        }
        throw err;
      }
    } catch (error) {
      logger.error("Failed to submit agent outcome", { error: (error as Error).message });
      return res.status(500).json({ error: "INTERNAL_ERROR", message: "Failed to submit outcome" });
    }
  });

  // ── GET /api/agent/calibration/:agentId ──────────────────────────────────
  // Public — no auth required.
  // Any agent or operator can check another agent's calibration quality.
  // agentId: MultiversX wallet address (erd1...) or internal user id.
  // Query params: ?n=50 (number of outcomes, default 50, max 200)
  app.get("/api/agent/calibration/:agentId", publicCalibrationRateLimiter, async (req, res) => {
    try {
      const { agentId } = req.params;
      const n = Math.min(200, Math.max(1, parseInt((req.query.n as string) || "50", 10) || 50));

      // Serve from cache if still fresh
      const cacheKey = `${agentId}:${n}`;
      const cached = calibrationCache.get(cacheKey);
      if (cached && Date.now() - cached.cachedAt < CALIBRATION_CACHE_TTL_MS) {
        return res.json(cached.body);
      }

      // Resolve agentId → user (accepts wallet address or user id)
      const [user] = await db
        .select({ id: users.id, walletAddress: users.walletAddress, agentName: users.agentName, isPublicProfile: users.isPublicProfile })
        .from(users)
        .where(or(eq(users.id, agentId), eq(users.walletAddress, agentId)))
        .limit(1);

      if (!user) {
        return res.status(404).json({
          error: "AGENT_NOT_FOUND",
          message: `No agent found with id or wallet: ${agentId}`,
        });
      }

      // Fetch last N public outcomes for this agent, most recent first
      const rows = await pool.query<{
        id: string;
        certification_id: string;
        anchored_confidence: string;
        outcome_score: string;
        confidence_gap: string;
        submitted_at: Date;
      }>(
        `SELECT ao.id, ao.certification_id, ao.anchored_confidence, ao.outcome_score, ao.confidence_gap, ao.submitted_at
         FROM agent_outcomes ao
         WHERE ao.user_id = $1
           AND ao.visibility = 'public'
         ORDER BY ao.submitted_at DESC
         LIMIT $2`,
        [user.id, n]
      );

      const outcomes = rows.rows;
      const count = outcomes.length;

      if (count === 0) {
        const emptyBody = {
          agent_id: user.id,
          wallet_address: user.walletAddress,
          agent_name: user.agentName ?? null,
          outcome_count: 0,
          calibration: null,
          message: "No public outcome data yet for this agent.",
          time_series: [],
        };
        calibrationCache.set(cacheKey, { body: emptyBody, cachedAt: Date.now() });
        return res.json(emptyBody);
      }

      // Compute calibration statistics
      const gaps = outcomes.map(r => parseFloat(r.confidence_gap));
      const meanGap = gaps.reduce((s, g) => s + g, 0) / count;
      const variance =
        count > 1
          ? gaps.reduce((s, g) => s + Math.pow(g - meanGap, 2), 0) / (count - 1)
          : 0;

      const roundedMean = Math.round(meanGap * 10000) / 10000;
      const roundedVariance = Math.round(variance * 10000) / 10000;

      const timeSeries = outcomes.map(r => ({
        submitted_at: r.submitted_at,
        proof_id: r.certification_id,
        anchored_confidence: parseFloat(r.anchored_confidence),
        outcome_score: parseFloat(r.outcome_score),
        confidence_gap: parseFloat(r.confidence_gap),
      }));

      const responseBody = {
        agent_id: user.id,
        wallet_address: user.walletAddress,
        agent_name: user.agentName ?? null,
        outcome_count: count,
        calibration: {
          mean_gap: roundedMean,
          variance: roundedVariance,
          bias_label: biasLabel(roundedMean),
          thresholds: {
            overconfident: `mean_gap > ${OVERCONFIDENT_THRESHOLD}`,
            underconfident: `mean_gap < ${UNDERCONFIDENT_THRESHOLD}`,
            calibrated: `mean_gap between ${UNDERCONFIDENT_THRESHOLD} and ${OVERCONFIDENT_THRESHOLD}`,
          },
          interpretation: {
            overconfident: "Agent consistently predicts higher confidence than outcomes justify",
            underconfident: "Agent consistently predicts lower confidence than outcomes justify",
            calibrated: "Agent's confidence scores align with actual outcomes",
          },
        },
        time_series: timeSeries,
      };
      calibrationCache.set(cacheKey, { body: responseBody, cachedAt: Date.now() });
      return res.json(responseBody);
    } catch (error) {
      logger.error("Failed to fetch agent calibration", { error: (error as Error).message });
      return res.status(500).json({ error: "INTERNAL_ERROR", message: "Failed to fetch calibration data" });
    }
  });

  // ── GET /api/agent/calibration/:agentId/export.csv ───────────────────────
  // Downloads calibration history as a CSV file.
  // Auth:  API-key owner or wallet-session owner → all outcomes (public + private).
  //        Unauthenticated → allowed only when ALL outcomes are public; blocked otherwise (401).
  // ?n=X  Optional row cap (hard ceiling 100 000). Omit to export full history.
  app.get("/api/agent/calibration/:agentId/export.csv", calibrationCsvExportRateLimiter, optionalApiKey, async (req, res) => {
    try {
      const { agentId } = req.params;
      // n is optional — omitting it exports the full history (no row cap).
      // Callers may pass ?n=X to limit output (hard cap: 100 000).
      const rawN = req.query.n as string | undefined;
      const n: number | null = rawN
        ? Math.min(100_000, Math.max(1, parseInt(rawN, 10) || 1))
        : null;
      const callerUserId: string | undefined = (req as any).optionalUserId;

      // Resolve agentId → user
      const [user] = await db
        .select({ id: users.id, walletAddress: users.walletAddress, agentName: users.agentName })
        .from(users)
        .where(or(eq(users.id, agentId), eq(users.walletAddress, agentId)))
        .limit(1);

      if (!user) {
        return res.status(404).json({ error: "AGENT_NOT_FOUND", message: `No agent found with id or wallet: ${agentId}` });
      }

      // Owner check 1: API key owner (set by optionalApiKey middleware above)
      // Owner check 2: wallet session — intentionally included so a logged-in operator
      //   can click the download button in the browser without supplying an API key.
      //   Session validity is guaranteed by MultiversX Native Auth (cryptographic proof),
      //   so this is equivalent security to API-key ownership for browser-originated exports.
      // NOTE: optionalApiKey shares key-resolution logic with validateApiKey (helpers.ts).
      //   If validateApiKey changes (e.g. new rotation fields), mirror the change here too.
      const sessionWallet = (req as any).session?.walletAddress as string | undefined;
      const isOwner =
        (!!callerUserId && callerUserId === user.id) ||
        (!!sessionWallet && sessionWallet === user.walletAddress);

      // Confirmed owners get 30 req/min keyed on their identity (user DB ID or
      // wallet address). Runs here — after isOwner is resolved via DB lookup —
      // so the higher limit applies only to the actual agent owner.
      // Non-owner callers (anon or authenticated) are governed by the 5 req/min
      // IP-based calibrationCsvExportRateLimiter that ran first in the middleware chain.
      if (isOwner) {
        const ownerKey = (callerUserId ?? sessionWallet)!;
        const rl = await pgCheckRateLimit("pub_csv_owner", ownerKey, 30, 60_000);
        if (!rl.allowed) {
          res.set("Retry-After", String(Math.ceil((rl.resetAt - Date.now()) / 1000)));
          return res.status(429).json({ error: "TOO_MANY_REQUESTS", message: "Too many CSV export requests, please try again later" });
        }
      }

      // Spec: unauthenticated access allowed ONLY when ALL outcomes are public.
      // If the agent has even one private outcome, ownership auth is required.
      if (!isOwner) {
        const { rows: privCheck } = await pool.query<{ cnt: string }>(
          `SELECT COUNT(*)::text AS cnt FROM agent_outcomes WHERE user_id = $1 AND visibility = 'private' LIMIT 1`,
          [user.id]
        );
        const privateCount = parseInt(privCheck[0]?.cnt ?? "0", 10);
        if (privateCount > 0) {
          return res.status(401).json({
            error: "UNAUTHORIZED",
            message: "This agent has private outcomes. Include 'Authorization: Bearer pm_xxx' header and use the owner's API key to export all outcomes.",
          });
        }
      }

      // Owner: all outcomes; unauthenticated (all-public verified above): public only
      const visibilityClause = isOwner ? "" : "AND ao.visibility = 'public'";

      const queryText = n !== null
        ? `SELECT ao.submitted_at, ao.certification_id, ao.anchored_confidence, ao.outcome_score, ao.confidence_gap, ao.visibility
           FROM agent_outcomes ao
           WHERE ao.user_id = $1 ${visibilityClause}
           ORDER BY ao.submitted_at DESC
           LIMIT $2`
        : `SELECT ao.submitted_at, ao.certification_id, ao.anchored_confidence, ao.outcome_score, ao.confidence_gap, ao.visibility
           FROM agent_outcomes ao
           WHERE ao.user_id = $1 ${visibilityClause}
           ORDER BY ao.submitted_at DESC`;
      const queryParams = n !== null ? [user.id, n] : [user.id];

      const rows = await pool.query<{
        submitted_at: Date;
        certification_id: string;
        anchored_confidence: string;
        outcome_score: string;
        confidence_gap: string;
        visibility: string;
      }>(queryText, queryParams);

      if (rows.rows.length === 0) {
        // Return empty CSV with headers rather than an error
        const headers = "submitted_at,proof_id,anchored_confidence,outcome_score,confidence_gap\n";
        res.setHeader("Content-Type", "text/csv; charset=utf-8");
        res.setHeader("Content-Disposition", `attachment; filename="calibration-${user.walletAddress.slice(0, 12)}.csv"`);
        res.setHeader("Cache-Control", "no-store");
        return res.send(headers);
      }

      // Build CSV rows — values are numeric/UUIDs/ISO dates, no escaping needed
      const csvLines = [
        "submitted_at,proof_id,anchored_confidence,outcome_score,confidence_gap",
        ...rows.rows.map(r =>
          [
            new Date(r.submitted_at).toISOString(),
            r.certification_id,
            parseFloat(r.anchored_confidence).toFixed(4),
            parseFloat(r.outcome_score).toFixed(4),
            parseFloat(r.confidence_gap).toFixed(4),
          ].join(",")
        ),
      ];

      const csv = csvLines.join("\n") + "\n";
      const safeAgentName = (user.agentName ?? user.walletAddress.slice(0, 12)).replace(/[^a-z0-9_-]/gi, "_");

      res.setHeader("Content-Type", "text/csv; charset=utf-8");
      res.setHeader("Content-Disposition", `attachment; filename="calibration-${safeAgentName}.csv"`);
      res.setHeader("Cache-Control", "no-store");
      return res.send(csv);
    } catch (error) {
      logger.error("Failed to export calibration CSV", { error: (error as Error).message });
      return res.status(500).json({ error: "INTERNAL_ERROR", message: "Failed to export calibration data" });
    }
  });
}
