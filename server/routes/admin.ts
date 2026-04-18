import { type Express } from "express";
import crypto from "crypto";
import { db, pool } from "../db";
import { logger } from "../logger";
import { certifications, users, apiKeys, visits, txQueue as txQueueTable } from "@shared/schema";
import { eq, desc, sql, and, gte, gt, count } from "drizzle-orm";
import { isWalletAuthenticated } from "../walletAuth";
import { computeTrustScoreByWallet } from "../trust";
import { getAlertConfig } from "../txAlerts";
import { getMetrics } from "../metrics";
import { getPricingInfo } from "../pricing";
import { getTxQueueStats } from "../txQueue";
import { requireAdmin, EXCLUDED_IP_HASHES } from "./helpers";

export function registerAdminRoutes(app: Express) {
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

      const sourceBreakdown = await db.execute(sql`
        SELECT
          COUNT(*) FILTER (WHERE c.auth_method IN ('api_key', 'x402', 'acp') AND (u.is_trial IS NOT TRUE OR u.id IS NULL)) as api_certs,
          COUNT(*) FILTER (WHERE u.is_trial IS TRUE) as trial_certs,
          COUNT(*) FILTER (WHERE (u.is_trial IS NOT TRUE OR u.id IS NULL) AND (c.auth_method IS NULL OR c.auth_method NOT IN ('api_key', 'x402', 'acp'))) as user_certs
        FROM certifications c
        LEFT JOIN users u ON c.user_id = u.id
      `);
      const src = (sourceBreakdown.rows[0] as Record<string, string>) || {};
      const apiCerts = parseInt(src.api_certs || "0");
      const trialCerts = parseInt(src.trial_certs || "0");
      const userCerts = parseInt(src.user_certs || "0");

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

      const [uniqueAgentsRow] = await db.select({ count: sql<number>`COUNT(DISTINCT ${users.id})` }).from(apiKeys).innerJoin(users, eq(apiKeys.userId, users.id)).where(and(eq(apiKeys.isActive, true), gt(apiKeys.requestCount, 0), sql`${users.isTrial} IS NOT TRUE`));
      const [totalApiKeysRow] = await db.select({ count: sql<number>`COUNT(DISTINCT ${users.id})` }).from(apiKeys).innerJoin(users, eq(apiKeys.userId, users.id)).where(and(eq(apiKeys.isActive, true), sql`${users.isTrial} IS NOT TRUE`, sql`${users.walletAddress} != 'erd1hlx4xanncp2wm9aly2q6ywuthl2q9jwe9sxvxpx4gg62zcrvd0uqr8gyu9'`));
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

      const adminSourceBreakdown = await db.execute(sql`
        SELECT
          COUNT(*) FILTER (WHERE c.auth_method IN ('api_key', 'x402', 'acp') AND (u.is_trial IS NOT TRUE OR u.id IS NULL)) as api_certs,
          COUNT(*) FILTER (WHERE u.is_trial IS TRUE) as trial_certs,
          COUNT(*) FILTER (WHERE (u.is_trial IS NOT TRUE OR u.id IS NULL) AND (c.auth_method IS NULL OR c.auth_method NOT IN ('api_key', 'x402', 'acp'))) as user_certs
        FROM certifications c
        LEFT JOIN users u ON c.user_id = u.id
      `);
      const adminSrc = (adminSourceBreakdown.rows[0] as Record<string, string>) || {};
      const apiCerts = parseInt(adminSrc.api_certs || "0");
      const trialCerts = parseInt(adminSrc.trial_certs || "0");
      const userCerts = parseInt(adminSrc.user_certs || "0");

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

  app.get("/api/admin/utm-stats", isWalletAuthenticated, requireAdmin, async (req: any, res) => {
    try {
      // First-touch attribution: earliest UTM visit per IP (not per source).
      // Conversion = user who registered within 24h of their first UTM touch, matched by ip_hash.
      const rows = await db.execute(sql`
        WITH first_touch AS (
          SELECT DISTINCT ON (ip_hash) ip_hash, utm_source, created_at AS touched_at
          FROM visits
          WHERE utm_source IS NOT NULL
          ORDER BY ip_hash, created_at ASC
        ),
        conversions AS (
          SELECT ft.utm_source, COUNT(DISTINCT u.id) AS conv_count
          FROM first_touch ft
          INNER JOIN users u ON u.registration_ip_hash = ft.ip_hash
            AND u.created_at >= ft.touched_at
            AND u.created_at <= ft.touched_at + INTERVAL '24 hours'
          GROUP BY ft.utm_source
        )
        SELECT
          v.utm_source,
          COUNT(*) AS visits,
          COUNT(DISTINCT v.ip_hash) AS unique_ips,
          COALESCE(MAX(c.conv_count), 0) AS conversions,
          MIN(v.created_at) AS first_seen,
          MAX(v.created_at) AS last_seen
        FROM visits v
        LEFT JOIN conversions c ON c.utm_source = v.utm_source
        WHERE v.utm_source IS NOT NULL
        GROUP BY v.utm_source
        ORDER BY visits DESC
        LIMIT 100
      `);

      const summary = await db.execute(sql`
        SELECT
          COUNT(*) AS total_utm_visits,
          COUNT(DISTINCT ip_hash) AS total_utm_unique_ips,
          COUNT(DISTINCT utm_source) AS total_sources,
          (
            SELECT COUNT(DISTINCT u.id)
            FROM (
              SELECT DISTINCT ON (ip_hash) ip_hash, created_at AS touched_at
              FROM visits WHERE utm_source IS NOT NULL
              ORDER BY ip_hash, created_at ASC
            ) ft
            INNER JOIN users u ON u.registration_ip_hash = ft.ip_hash
              AND u.created_at >= ft.touched_at
              AND u.created_at <= ft.touched_at + INTERVAL '24 hours'
          ) AS total_conversions
        FROM visits
        WHERE utm_source IS NOT NULL
      `);

      const s = (summary.rows[0] as Record<string, string>) || {};
      res.json({
        rows: (rows.rows as Array<Record<string, string | null>>).map(r => ({
          utm_source: r.utm_source,
          visits: parseInt(r.visits as string || "0"),
          unique_ips: parseInt(r.unique_ips as string || "0"),
          conversions: parseInt(r.conversions as string || "0"),
          first_seen: r.first_seen,
          last_seen: r.last_seen,
        })),
        summary: {
          total_utm_visits: parseInt(s.total_utm_visits || "0"),
          total_utm_unique_ips: parseInt(s.total_utm_unique_ips || "0"),
          total_sources: parseInt(s.total_sources || "0"),
          total_conversions: parseInt(s.total_conversions || "0"),
        },
        generated_at: new Date().toISOString(),
      });
    } catch (error) {
      logger.withRequest(req).error("UTM stats error");
      res.status(500).json({ error: "Failed to generate UTM stats" });
    }
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

  // ============================================
  // Admin: Trial Account Management
  // ============================================
  app.get("/api/admin/trial/orphans", isWalletAuthenticated, requireAdmin, async (req: any, res) => {
    try {
      const result = await db.execute(sql`
        SELECT u.id as user_id, u.wallet_address, u.company_name as agent_name,
               u.trial_quota, u.trial_used, u.created_at,
               COUNT(c.id)::int as cert_count,
               COUNT(ak.id)::int as key_count,
               MAX(c.created_at) as last_cert_at,
               ARRAY_AGG(DISTINCT c.file_name) FILTER (WHERE c.file_name IS NOT NULL) as file_names
        FROM users u
        LEFT JOIN certifications c ON c.user_id = u.id
        LEFT JOIN api_keys ak ON ak.user_id = u.id
        WHERE u.wallet_address LIKE 'erd1trial%'
        GROUP BY u.id
        HAVING COUNT(c.id) > 0 OR COUNT(ak.id) > 0
        ORDER BY COUNT(c.id) DESC
      `);
      res.json({
        orphans: result.rows,
        total: result.rows.length,
        total_certs: result.rows.reduce((s: number, r: any) => s + r.cert_count, 0),
        total_keys: result.rows.reduce((s: number, r: any) => s + r.key_count, 0),
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post("/api/admin/trial/migrate", isWalletAuthenticated, requireAdmin, async (req: any, res) => {
    try {
      const trial_user_id = typeof req.body?.trial_user_id === "string" ? req.body.trial_user_id.trim() : "";
      const target_wallet = typeof req.body?.target_wallet === "string" ? req.body.target_wallet.trim() : "";

      if (!trial_user_id || !target_wallet) {
        return res.status(400).json({ error: "trial_user_id and target_wallet are required" });
      }
      if (!target_wallet.startsWith("erd1") || target_wallet.length < 30) {
        return res.status(400).json({ error: "target_wallet must be a valid MultiversX address (starts with erd1)" });
      }

      const [trialUser] = await db.select().from(users).where(eq(users.id, trial_user_id));
      if (!trialUser || !trialUser.walletAddress?.startsWith("erd1trial")) {
        return res.status(404).json({ error: "Trial user not found or not a trial account" });
      }

      const [targetUser] = await db.select().from(users).where(eq(users.walletAddress, target_wallet));
      if (!targetUser) {
        return res.status(404).json({ error: "Target wallet user not found" });
      }

      // Atomic transfer inside a transaction
      const transferred = await db.transaction(async (tx) => {
        const certs = await tx.select({ id: certifications.id }).from(certifications).where(eq(certifications.userId, trialUser.id));
        if (certs.length > 0) {
          await tx.update(certifications).set({ userId: targetUser.id }).where(eq(certifications.userId, trialUser.id));
        }

        const keys = await tx.select({ id: apiKeys.id }).from(apiKeys).where(eq(apiKeys.userId, trialUser.id));
        if (keys.length > 0) {
          await tx.update(apiKeys).set({
            userId: targetUser.id,
            name: sql`REPLACE(name, 'Trial: ', '')`,
          }).where(eq(apiKeys.userId, trialUser.id));
        }

        return { certs: certs.length, keys: keys.length };
      });

      // Recalculate trust score
      let updatedScore: any = null;
      try {
        const trust = await computeTrustScoreByWallet(target_wallet);
        if (trust) {
          updatedScore = { score: trust.score, level: trust.level };
          await pool.query(
            `INSERT INTO trust_score_snapshots (wallet_address, score, level, cert_total, active_attestations, rank, snapshot_date)
             VALUES ($1, $2, $3, $4, $5, 0, CURRENT_DATE)
             ON CONFLICT (wallet_address, snapshot_date) DO UPDATE SET
               score = EXCLUDED.score, level = EXCLUDED.level,
               cert_total = EXCLUDED.cert_total, active_attestations = EXCLUDED.active_attestations`,
            [target_wallet, trust.score, trust.level, trust.certTotal, trust.activeAttestations ?? 0]
          );
        }
      } catch {}

      logger.withRequest(req).info("Admin trial migration", {
        trialUserId: trialUser.id,
        targetWallet: target_wallet,
        certs: transferred.certs,
        keys: transferred.keys,
      });

      res.json({
        success: true,
        transferred: { certifications: transferred.certs, api_keys: transferred.keys },
        target_wallet,
        trust_score: updatedScore,
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // ============================================
  // DELETE /api/admin/cleanup/test-agents
  // Removes test agents created during development
  // ============================================
  app.delete("/api/admin/cleanup/test-agents", requireAdmin, async (req, res) => {
    try {
      const deleted = await db.delete(users)
        .where(eq(users.companyName, "test-onboard-agent"))
        .returning({ id: users.id, companyName: users.companyName });
      
      res.json({
        success: true,
        message: `Deleted ${deleted.length} test agent(s)`,
        deleted: deleted.map(u => ({ id: u.id, name: u.companyName })),
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

}
