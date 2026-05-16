import { type Express, type Request, type Response, type NextFunction } from "express";
import { db, pool } from "../db";
import { logger } from "../logger";
import { certifications, users, agentOutcomes, apiKeys } from "@shared/schema";
import { eq, or } from "drizzle-orm";
import { z } from "zod";
import crypto from "crypto";
import { validateApiKey } from "./helpers";

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
async function optionalApiKey(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers["authorization"];
  if (!authHeader || !authHeader.startsWith("Bearer ")) return next();
  const rawKey = authHeader.slice(7);
  if (!rawKey.startsWith("pm_")) return next();
  try {
    const keyHash = crypto.createHash("sha256").update(rawKey).digest("hex");
    const [key] = await db.select({ userId: apiKeys.userId, isActive: apiKeys.isActive })
      .from(apiKeys).where(eq(apiKeys.keyHash, keyHash)).limit(1);
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
  app.post("/api/agent/outcome", validateApiKey, async (req, res) => {
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
  app.get("/api/agent/calibration/:agentId", async (req, res) => {
    try {
      const { agentId } = req.params;
      const n = Math.min(200, Math.max(1, parseInt((req.query.n as string) || "50", 10) || 50));

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
        return res.json({
          agent_id: user.id,
          wallet_address: user.walletAddress,
          agent_name: user.agentName ?? null,
          outcome_count: 0,
          calibration: null,
          message: "No public outcome data yet for this agent.",
          time_series: [],
        });
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

      return res.json({
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
      });
    } catch (error) {
      logger.error("Failed to fetch agent calibration", { error: (error as Error).message });
      return res.status(500).json({ error: "INTERNAL_ERROR", message: "Failed to fetch calibration data" });
    }
  });

  // ── GET /api/agent/calibration/:agentId/export.csv ───────────────────────
  // Downloads calibration history as a CSV file.
  // Auth: optional — authenticated API key owner sees ALL outcomes (public + private);
  //       unauthenticated callers see public outcomes only.
  // Query param: ?n=200 (max 1000 for CSV export, default 200)
  app.get("/api/agent/calibration/:agentId/export.csv", optionalApiKey, async (req, res) => {
    try {
      const { agentId } = req.params;
      const n = Math.min(1000, Math.max(1, parseInt((req.query.n as string) || "200", 10) || 200));
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

      // Determine visibility filter: owner can see all, others see public only
      const isOwner = !!callerUserId && callerUserId === user.id;
      const visibilityClause = isOwner ? "" : "AND ao.visibility = 'public'";

      const rows = await pool.query<{
        submitted_at: Date;
        certification_id: string;
        anchored_confidence: string;
        outcome_score: string;
        confidence_gap: string;
        visibility: string;
      }>(
        `SELECT ao.submitted_at, ao.certification_id, ao.anchored_confidence, ao.outcome_score, ao.confidence_gap, ao.visibility
         FROM agent_outcomes ao
         WHERE ao.user_id = $1 ${visibilityClause}
         ORDER BY ao.submitted_at DESC
         LIMIT $2`,
        [user.id, n]
      );

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
