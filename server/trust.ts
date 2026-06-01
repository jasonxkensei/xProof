import { db, pool } from "./db";
import { certifications, users, agentViolations } from "@shared/schema";
import { eq, sql, and } from "drizzle-orm";
import { logger } from "./logger";

export type TrustLevel = "Newcomer" | "Active" | "Trusted" | "Verified";

export type TransparencyTier = "Tier 1" | "Tier 2" | "Tier 3";

export const VIOLATION_PENALTY = { fault: -150, breach: -500 } as const;

export interface TrustScore {
  score: number;
  level: TrustLevel;
  certTotal: number;
  certLast30d: number;
  streakWeeks: number;
  activeAttestations: number;
  attestationBonus: number;
  transparencyTier: TransparencyTier;
  transparencyBonus: number;
  metadataCount: number;
  auditCount: number;
  firstCertAt: string | null;
  lastCertAt: string | null;
  violationPenalty: number;
  violations: { fault: number; breach: number; proposed: number };
}

export function getTrustLevel(score: number): TrustLevel {
  if (score >= 700) return "Verified";
  if (score >= 300) return "Trusted";
  if (score >= 100) return "Active";
  return "Newcomer";
}

export function getTrustLevelColor(level: TrustLevel): string {
  switch (level) {
    case "Verified": return "#10B981";
    case "Trusted": return "#22C55E";
    case "Active": return "#3B82F6";
    case "Newcomer": return "#6B7280";
  }
}

export function getTransparencyTier(metadataCount: number, auditCount: number): TransparencyTier {
  if (auditCount >= 5) return "Tier 3";
  if (metadataCount >= 3) return "Tier 2";
  return "Tier 1";
}

async function computeViolationPenalty(walletAddress: string): Promise<{ penalty: number; fault: number; breach: number; proposed: number }> {
  try {
    const rows = await db.execute(sql`
      SELECT type, status, COUNT(*)::int as cnt
      FROM agent_violations
      WHERE wallet_address = ${walletAddress}
      GROUP BY type, status
    `);
    let faultConfirmed = 0;
    let breachConfirmed = 0;
    let proposed = 0;
    for (const r of rows.rows as any[]) {
      if (r.status === "confirmed" && r.type === "fault") faultConfirmed = Number(r.cnt);
      if (r.status === "confirmed" && r.type === "breach") breachConfirmed = Number(r.cnt);
      if (r.status === "proposed") proposed += Number(r.cnt);
    }
    const penalty = (faultConfirmed * VIOLATION_PENALTY.fault) + (breachConfirmed * VIOLATION_PENALTY.breach);
    return { penalty, fault: faultConfirmed, breach: breachConfirmed, proposed };
  } catch {
    return { penalty: 0, fault: 0, breach: 0, proposed: 0 };
  }
}

function computeTransparencyBonus(metadataCount: number, auditCount: number): number {
  let bonus = 0;
  bonus += Math.min(50, metadataCount * 5);
  bonus += Math.min(100, auditCount * 15);
  return Math.min(200, bonus);
}

function computeScore(
  confirmed: number,
  last30d: number,
  streakWeeks: number,
  firstAt: Date | null,
  lastAt: Date | null,
  attestationBonus: number = 0,
  transparencyBonus: number = 0,
): number {
  const daysSinceFirst = firstAt
    ? Math.floor((Date.now() - firstAt.getTime()) / (1000 * 60 * 60 * 24))
    : 0;
  const daysSinceLastCert = lastAt
    ? Math.floor((Date.now() - lastAt.getTime()) / (1000 * 60 * 60 * 24))
    : Infinity;

  const baseScore = confirmed * 10;
  const recencyBonus = last30d * 5;

  let ageBonus = 0;
  if (daysSinceLastCert <= 30) {
    ageBonus = Math.min(150, daysSinceFirst * 0.3);
  } else if (daysSinceLastCert <= 90) {
    const rawAge = Math.min(150, daysSinceFirst * 0.3);
    const decayFactor = 1 - (daysSinceLastCert - 30) / 60;
    ageBonus = Math.max(0, Math.round(rawAge * decayFactor));
  }

  const streakBonus = Math.min(100, streakWeeks * 8);

  return Math.round(baseScore + recencyBonus + ageBonus + streakBonus + attestationBonus + transparencyBonus);
}

function issuerBonusFromCertCount(confirmedCerts: number): number {
  if (confirmedCerts >= 30) return 50;
  if (confirmedCerts >= 10) return 40;
  if (confirmedCerts >= 3) return 25;
  return 10;
}

function computeStreakFromWeekNumbers(weekNumbers: number[]): number {
  if (weekNumbers.length === 0) return 0;

  const sorted = [...new Set(weekNumbers)].sort((a, b) => b - a);
  const currentIsoWeek = getIsoWeekNumber(new Date());

  if (currentIsoWeek - sorted[0] > 2) return 0;

  let streak = 1;
  for (let i = 1; i < sorted.length; i++) {
    const gap = sorted[i - 1] - sorted[i];
    if (gap <= 2) {
      streak++;
    } else {
      break;
    }
  }

  return streak;
}

function getIsoWeekNumber(date: Date): number {
  const epoch = new Date(Date.UTC(2024, 0, 1));
  const daysSinceEpoch = Math.floor((date.getTime() - epoch.getTime()) / (1000 * 60 * 60 * 24));
  return Math.floor(daysSinceEpoch / 7);
}

async function computeStreakWeeks(userId: string): Promise<number> {
  const rows = await db.execute(sql`
    SELECT DISTINCT FLOOR(EXTRACT(EPOCH FROM created_at - '2024-01-01'::timestamp) / 604800)::int AS week_num
    FROM certifications
    WHERE user_id = ${userId}
      AND blockchain_status = 'confirmed'
      AND is_public = true
    ORDER BY week_num DESC
  `);

  const weekNumbers = (rows.rows as any[]).map((r) => Number(r.week_num));
  return computeStreakFromWeekNumbers(weekNumbers);
}

async function computeStreakWeeksBatch(userIds: string[]): Promise<Map<string, number>> {
  if (userIds.length === 0) return new Map();
  try {
    const result = await pool.query<{ user_id: string; week_num: number }>(
      `SELECT user_id::text, FLOOR(EXTRACT(EPOCH FROM created_at - '2024-01-01'::timestamp) / 604800)::int AS week_num
       FROM certifications
       WHERE user_id = ANY($1)
         AND blockchain_status = 'confirmed'
         AND is_public = true
       ORDER BY user_id, week_num DESC`,
      [userIds],
    );
    const weeksByUser = new Map<string, number[]>();
    for (const row of result.rows) {
      const uid = row.user_id;
      if (!weeksByUser.has(uid)) weeksByUser.set(uid, []);
      weeksByUser.get(uid)!.push(Number(row.week_num));
    }
    const out = new Map<string, number>();
    for (const id of userIds) {
      out.set(id, computeStreakFromWeekNumbers(weeksByUser.get(id) ?? []));
    }
    return out;
  } catch {
    return new Map(userIds.map((id) => [id, 0]));
  }
}

async function computeAttestationBonus(walletAddress: string): Promise<{ bonus: number; count: number }> {
  try {
    const now = new Date();
    const rows = await db.execute(sql`
      SELECT
        a.issuer_wallet,
        COUNT(c.id) FILTER (WHERE c.blockchain_status = 'confirmed' AND c.is_public = true) AS issuer_confirmed_certs
      FROM attestations a
      LEFT JOIN users u ON u.wallet_address = a.issuer_wallet
      LEFT JOIN certifications c ON c.user_id = u.id
      WHERE a.subject_wallet = ${walletAddress}
        AND a.status = 'active'
        AND (a.expires_at IS NULL OR a.expires_at > ${now})
        AND u.is_public_profile = true
      GROUP BY a.issuer_wallet
      ORDER BY issuer_confirmed_certs DESC
    `);
    const allRows = rows.rows as any[];
    const count = allRows.length;
    const bonus = allRows
      .slice(0, 3)
      .reduce((sum, r) => sum + issuerBonusFromCertCount(Number(r.issuer_confirmed_certs || 0)), 0);
    return { bonus, count };
  } catch {
    return { bonus: 0, count: 0 };
  }
}

async function computeAttestationBonusBatch(walletAddresses: string[]): Promise<Map<string, { bonus: number; count: number }>> {
  if (walletAddresses.length === 0) return new Map();
  try {
    const now = new Date();
    const result = await pool.query<{ subject_wallet: string; issuer_wallet: string; issuer_confirmed_certs: string }>(
      `SELECT
         a.subject_wallet,
         a.issuer_wallet,
         COUNT(c.id) FILTER (WHERE c.blockchain_status = 'confirmed' AND c.is_public = true) AS issuer_confirmed_certs
       FROM attestations a
       LEFT JOIN users u ON u.wallet_address = a.issuer_wallet
       LEFT JOIN certifications c ON c.user_id = u.id
       WHERE a.subject_wallet = ANY($1)
         AND a.status = 'active'
         AND (a.expires_at IS NULL OR a.expires_at > $2)
         AND u.is_public_profile = true
       GROUP BY a.subject_wallet, a.issuer_wallet`,
      [walletAddresses, now],
    );
    const rowsBySubject = new Map<string, { issuer_wallet: string; issuer_confirmed_certs: number }[]>();
    for (const row of result.rows) {
      const sw = row.subject_wallet;
      if (!rowsBySubject.has(sw)) rowsBySubject.set(sw, []);
      rowsBySubject.get(sw)!.push({ issuer_wallet: row.issuer_wallet, issuer_confirmed_certs: Number(row.issuer_confirmed_certs || 0) });
    }
    const out = new Map<string, { bonus: number; count: number }>();
    for (const wallet of walletAddresses) {
      const rows = (rowsBySubject.get(wallet) ?? []).sort((a, b) => b.issuer_confirmed_certs - a.issuer_confirmed_certs);
      const count = rows.length;
      const bonus = rows.slice(0, 3).reduce((sum, r) => sum + issuerBonusFromCertCount(r.issuer_confirmed_certs), 0);
      out.set(wallet, { bonus, count });
    }
    return out;
  } catch {
    return new Map();
  }
}

async function computeTransparencyCounts(userId: string): Promise<{ metadataCount: number; auditCount: number }> {
  try {
    const [result] = await db
      .select({
        metadataCount: sql<number>`COUNT(*) FILTER (WHERE blockchain_status = 'confirmed' AND is_public = true AND metadata IS NOT NULL AND (metadata->>'model_hash' IS NOT NULL OR metadata->>'strategy_hash' IS NOT NULL OR metadata->>'version_number' IS NOT NULL))`,
        auditCount: sql<number>`COUNT(*) FILTER (WHERE blockchain_status = 'confirmed' AND is_public = true AND metadata IS NOT NULL AND metadata->>'agent_id' IS NOT NULL)`,
      })
      .from(certifications)
      .where(eq(certifications.userId, userId));
    return {
      metadataCount: Number(result.metadataCount || 0),
      auditCount: Number(result.auditCount || 0),
    };
  } catch {
    return { metadataCount: 0, auditCount: 0 };
  }
}

export async function computeTrustScore(userId: string): Promise<TrustScore> {
  const cutoff30d = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

  const [totals] = await db
    .select({
      confirmed: sql<number>`COUNT(*) FILTER (WHERE blockchain_status = 'confirmed' AND is_public = true)`,
      last30d: sql<number>`COUNT(*) FILTER (WHERE created_at >= ${cutoff30d} AND blockchain_status = 'confirmed' AND is_public = true)`,
      firstAt: sql<Date>`MIN(created_at) FILTER (WHERE blockchain_status = 'confirmed' AND is_public = true)`,
      lastAt: sql<Date>`MAX(created_at) FILTER (WHERE blockchain_status = 'confirmed' AND is_public = true)`,
    })
    .from(certifications)
    .where(eq(certifications.userId, userId));

  const confirmed = Number(totals.confirmed || 0);
  const last30d = Number(totals.last30d || 0);
  const firstAt = totals.firstAt ? new Date(totals.firstAt) : null;
  const lastAt = totals.lastAt ? new Date(totals.lastAt) : null;

  const [user] = await db.select({ walletAddress: users.walletAddress }).from(users).where(eq(users.id, userId));
  const walletAddress = user?.walletAddress || "";

  const [streakWeeks, attestationResult, transparencyCounts, violationResult] = await Promise.all([
    computeStreakWeeks(userId),
    computeAttestationBonus(walletAddress),
    computeTransparencyCounts(userId),
    computeViolationPenalty(walletAddress),
  ]);

  const { bonus: attestationBonus, count: activeAttestations } = attestationResult;
  const { metadataCount, auditCount } = transparencyCounts;
  const tBonus = computeTransparencyBonus(metadataCount, auditCount);
  const rawScore = computeScore(confirmed, last30d, streakWeeks, firstAt, lastAt, attestationBonus, tBonus);
  const score = Math.max(0, rawScore + violationResult.penalty);

  return {
    score,
    level: getTrustLevel(score),
    certTotal: confirmed,
    certLast30d: last30d,
    streakWeeks,
    activeAttestations,
    attestationBonus,
    transparencyTier: getTransparencyTier(metadataCount, auditCount),
    transparencyBonus: tBonus,
    metadataCount,
    auditCount,
    firstCertAt: firstAt ? firstAt.toISOString() : null,
    lastCertAt: lastAt ? lastAt.toISOString() : null,
    violationPenalty: violationResult.penalty,
    violations: { fault: violationResult.fault, breach: violationResult.breach, proposed: violationResult.proposed },
  };
}

// ─── Per-wallet trust score read-through cache ───────────────────────────────
//
// Security guarantee: public read paths NEVER trigger live trust recomputation.
// The cache is populated ONLY by the scheduled background refresh worker.
// Public reads go: in-memory cache → trust_score_snapshots.full_trust_data → null.
// A null response means the wallet has not yet been indexed; it will appear after
// the next scheduled refresh cycle.
//
const TRUST_CACHE_MAX_ENTRIES = 5000;
const trustCache = new Map<string, { value: TrustScore | null; cachedAt: number }>();

function setTrustCache(key: string, value: TrustScore | null) {
  if (trustCache.size >= TRUST_CACHE_MAX_ENTRIES) {
    const oldestKey = trustCache.keys().next().value;
    if (oldestKey !== undefined) trustCache.delete(oldestKey);
  }
  trustCache.set(key, { value, cachedAt: Date.now() });
}

// Public read — bounded: in-memory cache first, then single indexed snapshot row.
// NO live computation is ever triggered from this function.
export async function computeTrustScoreByWallet(walletAddress: string): Promise<TrustScore | null> {
  const cached = trustCache.get(walletAddress);
  if (cached) return cached.value;

  // Single bounded indexed read from the precomputed snapshot table.
  try {
    const snap = await pool.query<{ full_trust_data: unknown }>(
      `SELECT full_trust_data
       FROM trust_score_snapshots
       WHERE wallet_address = $1
         AND full_trust_data IS NOT NULL
       ORDER BY snapshot_date DESC LIMIT 1`,
      [walletAddress],
    );
    if (snap.rows.length > 0 && snap.rows[0].full_trust_data) {
      const value = snap.rows[0].full_trust_data as TrustScore;
      setTrustCache(walletAddress, value);
      return value;
    }
  } catch { /* snapshot read failure is non-fatal; return null below */ }

  // Wallet not yet indexed.  The scheduled refresh will populate it.
  return null;
}

export type CalibrationLabel = "calibrated" | "overconfident" | "underconfident";

export interface LeaderboardEntry {
  walletAddress: string;
  agentName: string | null;
  agentCategory: string | null;
  agentDescription: string | null;
  agentWebsite: string | null;
  trustScore: number;
  trustLevel: TrustLevel;
  certTotal: number;
  certLast30d: number;
  streakWeeks: number;
  activeAttestations: number;
  attestationBonus: number;
  transparencyTier: TransparencyTier;
  transparencyBonus: number;
  firstCertAt: string | null;
  lastCertAt: string | null;
  scoreDelta7d: number;
  rank: number;
  previousLevel: TrustLevel | null;
  violationCount: number;
  violationPenalty: number;
  calibrationLabel: CalibrationLabel | null;
}

export interface LeaderboardFilters {
  page?: number;
  limit?: number;
  category?: string;
  search?: string;
  attestedOnly?: boolean;
  calibratedOnly?: boolean;
  sortBy?: "score" | "certs" | "streak" | "attestations" | "calibration";
}

export interface LeaderboardResult {
  entries: LeaderboardEntry[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
}

// ─── Leaderboard in-memory cache ─────────────────────────────────────────────
//
// Security guarantee: public read paths NEVER trigger live leaderboard
// recomputation.  The cache is populated ONLY by the scheduled background
// refresh worker (runLeaderboardRefreshCycle).  Public reads go:
//   in-memory cache → leaderboard_snapshot table → empty list.
//
let leaderboardCache: { allEntries: LeaderboardEntry[]; cachedAt: number } | null = null;

async function computeAllLeaderboardEntries(): Promise<LeaderboardEntry[]> {
  const cutoff30d = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

  const rows = await db.execute(sql`
    SELECT
      u.id,
      u.wallet_address,
      u.agent_name,
      u.agent_category,
      u.agent_description,
      u.agent_website,
      COUNT(c.id) FILTER (WHERE c.blockchain_status = 'confirmed' AND c.is_public = true) AS cert_total,
      COUNT(c.id) FILTER (WHERE c.blockchain_status = 'confirmed' AND c.is_public = true AND c.created_at >= ${cutoff30d}) AS cert_last_30d,
      MIN(c.created_at) FILTER (WHERE c.blockchain_status = 'confirmed' AND c.is_public = true) AS first_cert_at,
      MAX(c.created_at) FILTER (WHERE c.blockchain_status = 'confirmed' AND c.is_public = true) AS last_cert_at,
      COUNT(c.id) FILTER (WHERE c.blockchain_status = 'confirmed' AND c.is_public = true AND c.metadata IS NOT NULL AND (c.metadata->>'model_hash' IS NOT NULL OR c.metadata->>'strategy_hash' IS NOT NULL OR c.metadata->>'version_number' IS NOT NULL)) AS metadata_count,
      COUNT(c.id) FILTER (WHERE c.blockchain_status = 'confirmed' AND c.is_public = true AND c.metadata IS NOT NULL AND c.metadata->>'agent_id' IS NOT NULL) AS audit_count
    FROM users u
    LEFT JOIN certifications c ON c.user_id = u.id
    WHERE u.is_public_profile = true
      AND u.wallet_address NOT LIKE 'erd1trial%'
    GROUP BY u.id, u.wallet_address, u.agent_name, u.agent_category, u.agent_description, u.agent_website
    HAVING COUNT(c.id) FILTER (WHERE c.blockchain_status = 'confirmed' AND c.is_public = true) > 0
  `);

  const allRows = rows.rows as any[];
  const userIds = allRows.map((r) => r.id);
  const walletAddresses = allRows.map((r) => r.wallet_address);

  const cutoff7d = new Date();
  cutoff7d.setDate(cutoff7d.getDate() - 7);

  const [streakMap, attestationMap, oldScoreMap, prevLevelMap, violationMap, calibrationMap] = await Promise.all([
    computeStreakWeeksBatch(userIds),
    computeAttestationBonusBatch(walletAddresses),
    getOldScoreBatch(walletAddresses, cutoff7d),
    getPreviousLevelBatch(walletAddresses),
    computeViolationPenaltyBatch(walletAddresses),
    computeCalibrationLabelBatch(),
  ]);

  const entries: LeaderboardEntry[] = allRows.map((row) => {
    const confirmed = Number(row.cert_total || 0);
    const last30d = Number(row.cert_last_30d || 0);
    const firstAt = row.first_cert_at ? new Date(row.first_cert_at) : null;
    const lastAt = row.last_cert_at ? new Date(row.last_cert_at) : null;
    const streakWeeks = streakMap.get(row.id) || 0;
    const attestationResult = attestationMap.get(row.wallet_address) || { bonus: 0, count: 0 };
    const activeAttestations = attestationResult.count;
    const attestationBonus = attestationResult.bonus;
    const mCount = Number(row.metadata_count || 0);
    const aCount = Number(row.audit_count || 0);
    const tBonus = computeTransparencyBonus(mCount, aCount);
    const vResult = violationMap.get(row.wallet_address) || { penalty: 0, fault: 0, breach: 0, proposed: 0 };
    const rawScore = computeScore(confirmed, last30d, streakWeeks, firstAt, lastAt, attestationBonus, tBonus);
    const score = Math.max(0, rawScore + vResult.penalty);

    return {
      walletAddress: row.wallet_address,
      agentName: row.agent_name || null,
      agentCategory: row.agent_category || null,
      agentDescription: row.agent_description || null,
      agentWebsite: row.agent_website || null,
      trustScore: score,
      trustLevel: getTrustLevel(score),
      certTotal: confirmed,
      certLast30d: last30d,
      streakWeeks,
      activeAttestations,
      attestationBonus,
      transparencyTier: getTransparencyTier(mCount, aCount),
      transparencyBonus: tBonus,
      firstCertAt: firstAt ? firstAt.toISOString() : null,
      lastCertAt: lastAt ? lastAt.toISOString() : null,
      scoreDelta7d: oldScoreMap.has(row.wallet_address) ? score - (oldScoreMap.get(row.wallet_address) as number) : 0,
      rank: 0,
      previousLevel: prevLevelMap.get(row.wallet_address) ?? null,
      violationCount: vResult.fault + vResult.breach,
      violationPenalty: vResult.penalty,
      calibrationLabel: calibrationMap.get(row.id) ?? null,
    };
  });

  entries.sort((a, b) => b.trustScore - a.trustScore);
  entries.forEach((e, i) => { e.rank = i + 1; });

  leaderboardCache = { allEntries: entries, cachedAt: Date.now() };
  return entries;
}

// ─── Scheduled background refresh worker ─────────────────────────────────────
//
// ALL expensive trust/leaderboard recomputation is confined here.
// Public request handlers MUST NOT call computeTrustScore() or
// computeAllLeaderboardEntries() — not directly and not via background triggers
// initiated from the request path.
//
// The scheduler runs two independent cycles on a fixed interval:
//   • runLeaderboardRefreshCycle() — recomputes the full leaderboard and persists
//     it to the leaderboard_snapshot table (single-row upsert).
//   • runTrustRefreshCycle()      — refreshes per-wallet trust scores for all
//     public profiles, persisting to trust_score_snapshots.full_trust_data.
//
// Both cycles are guarded by a running-flag to prevent overlap.  The per-wallet
// cycle also caps parallel DB queries with TRUST_REFRESH_CONCURRENCY so that a
// large profile count cannot saturate the connection pool.

const TRUST_REFRESH_INTERVAL_MS  = 5 * 60 * 1000;  // Full cycle every 5 min
const TRUST_REFRESH_CONCURRENCY  = 5;               // Max parallel wallet recomputes
const SCHEDULER_STARTUP_JITTER   = 20_000;          // 0-20 s startup jitter

let _trustRefreshRunning       = false;
let _leaderboardRefreshRunning = false;

export async function runTrustRefreshCycle(): Promise<void> {
  if (_trustRefreshRunning) {
    logger.debug("Trust refresh cycle already running, skipping", { component: "trust-scheduler" });
    return;
  }
  _trustRefreshRunning = true;
  const cycleStart = Date.now();
  let succeeded = 0;
  let failed = 0;
  try {
    const result = await pool.query<{ id: string; wallet_address: string }>(
      `SELECT id::text AS id, wallet_address
       FROM users
       WHERE is_public_profile = true
         AND wallet_address NOT LIKE 'erd1trial%'
       ORDER BY wallet_address`,
    );
    const rows = result.rows;
    for (let i = 0; i < rows.length; i += TRUST_REFRESH_CONCURRENCY) {
      const batch = rows.slice(i, i + TRUST_REFRESH_CONCURRENCY);
      await Promise.all(batch.map(async ({ id, wallet_address }) => {
        try {
          const trust = await computeTrustScore(id);
          setTrustCache(wallet_address, trust);
          await pool.query(
            `INSERT INTO trust_score_snapshots
               (wallet_address, score, level, cert_total, active_attestations, rank, snapshot_date, full_trust_data)
             VALUES ($1, $2, $3, $4, $5, 0, CURRENT_DATE, $6::jsonb)
             ON CONFLICT (wallet_address, snapshot_date) DO UPDATE
               SET full_trust_data      = EXCLUDED.full_trust_data,
                   score                = EXCLUDED.score,
                   level                = EXCLUDED.level,
                   cert_total           = EXCLUDED.cert_total,
                   active_attestations  = EXCLUDED.active_attestations`,
            [
              wallet_address,
              trust.score,
              trust.level,
              trust.certTotal,
              trust.activeAttestations ?? 0,
              JSON.stringify(trust),
            ],
          );
          succeeded++;
        } catch (err: any) {
          failed++;
          logger.warn("Trust refresh failed for wallet", {
            component: "trust-scheduler",
            wallet: wallet_address,
            error: err?.message ?? String(err),
          });
        }
      }));
    }
    logger.info("Trust refresh cycle complete", {
      component: "trust-scheduler",
      total: rows.length,
      succeeded,
      failed,
      durationMs: Date.now() - cycleStart,
    });
  } catch (err: any) {
    logger.error("Trust refresh cycle error", {
      component: "trust-scheduler",
      error: err?.message ?? String(err),
      durationMs: Date.now() - cycleStart,
    });
  } finally { _trustRefreshRunning = false; }
}

export async function runLeaderboardRefreshCycle(): Promise<void> {
  if (_leaderboardRefreshRunning) {
    logger.debug("Leaderboard refresh cycle already running, skipping", { component: "trust-scheduler" });
    return;
  }
  _leaderboardRefreshRunning = true;
  const cycleStart = Date.now();
  try {
    const entries = await computeAllLeaderboardEntries();
    await pool.query(
      `INSERT INTO leaderboard_snapshot (id, entries, computed_at)
       VALUES (1, $1::jsonb, NOW())
       ON CONFLICT (id) DO UPDATE
         SET entries     = EXCLUDED.entries,
             computed_at = EXCLUDED.computed_at`,
      [JSON.stringify(entries)],
    );
    leaderboardCache = { allEntries: entries, cachedAt: Date.now() };
    logger.info("Leaderboard refresh cycle complete", {
      component: "trust-scheduler",
      entries: entries.length,
      durationMs: Date.now() - cycleStart,
    });
  } catch (err: any) {
    logger.error("Leaderboard refresh cycle error", {
      component: "trust-scheduler",
      error: err?.message ?? String(err),
      durationMs: Date.now() - cycleStart,
    });
  } finally { _leaderboardRefreshRunning = false; }
}

// Warm the in-memory caches at startup by reading EXISTING snapshot rows —
// zero live computation.  Scheduled refresh cycles will keep data fresh.
export async function warmCachesFromSnapshots(): Promise<void> {
  try {
    const snap = await pool.query<{ entries: LeaderboardEntry[]; computed_at: string }>(
      `SELECT entries, computed_at FROM leaderboard_snapshot WHERE id = 1`,
    );
    if (snap.rows.length > 0) {
      leaderboardCache = { allEntries: snap.rows[0].entries, cachedAt: Date.now() };
      logger.info("Leaderboard cache warmed from snapshot", {
        component: "trust-scheduler",
        entries: snap.rows[0].entries.length,
        snapshotAt: snap.rows[0].computed_at,
      });
    } else {
      logger.info("No leaderboard snapshot found; awaiting first refresh cycle", {
        component: "trust-scheduler",
      });
    }
  } catch (err: any) {
    logger.warn("Failed to warm leaderboard cache from snapshot", {
      component: "trust-scheduler",
      error: err?.message ?? String(err),
    });
  }
}

// Start both refresh cycles.  Called once from server startup after migrations
// complete.  A small random jitter prevents thundering-herd on multi-instance
// restarts.
export function startTrustRefreshScheduler(): void {
  const jitter = Math.floor(Math.random() * SCHEDULER_STARTUP_JITTER);
  logger.info("Trust refresh scheduler starting", { component: "trust-scheduler", jitterMs: jitter });
  setTimeout(async () => {
    await runLeaderboardRefreshCycle();
    await runTrustRefreshCycle();
    setInterval(runLeaderboardRefreshCycle, TRUST_REFRESH_INTERVAL_MS);
    setInterval(runTrustRefreshCycle, TRUST_REFRESH_INTERVAL_MS);
  }, jitter);
}

export async function getLeaderboard(filters: LeaderboardFilters = {}): Promise<LeaderboardResult> {
  const page = Math.max(1, filters.page || 1);
  const limit = Math.min(100, Math.max(1, filters.limit || 50));

  let allEntries: LeaderboardEntry[];

  if (leaderboardCache) {
    // Serve from in-memory cache — no DB work.
    allEntries = leaderboardCache.allEntries;
  } else {
    // Cache is cold (server restart before first refresh cycle completes).
    // Do a single bounded read from the precomputed snapshot table.
    // This NEVER calls computeAllLeaderboardEntries().
    try {
      const snap = await pool.query<{ entries: LeaderboardEntry[] }>(
        `SELECT entries FROM leaderboard_snapshot WHERE id = 1`,
      );
      if (snap.rows.length > 0) {
        leaderboardCache = { allEntries: snap.rows[0].entries, cachedAt: Date.now() };
        allEntries = leaderboardCache.allEntries;
      } else {
        // No snapshot yet — first scheduled refresh hasn't run.
        allEntries = [];
      }
    } catch {
      allEntries = [];
    }
  }

  let entries = [...allEntries];

  if (filters.category) {
    entries = entries.filter((e) => e.agentCategory === filters.category);
  }
  if (filters.search) {
    const q = filters.search.toLowerCase();
    entries = entries.filter(
      (e) =>
        e.walletAddress.toLowerCase().includes(q) ||
        (e.agentName || "").toLowerCase().includes(q),
    );
  }
  if (filters.attestedOnly) {
    entries = entries.filter((e) => e.activeAttestations > 0);
  }
  if (filters.calibratedOnly) {
    entries = entries.filter((e) => e.calibrationLabel !== null);
  }

  if (filters.sortBy === "certs") entries.sort((a, b) => b.certTotal - a.certTotal);
  else if (filters.sortBy === "streak") entries.sort((a, b) => b.streakWeeks - a.streakWeeks);
  else if (filters.sortBy === "attestations") entries.sort((a, b) => b.activeAttestations - a.activeAttestations);
  else if (filters.sortBy === "calibration") {
    // Calibrated > Underconfident > Overconfident > None (null)
    const CALIBRATION_ORDER: Record<string, number> = {
      calibrated: 0,
      underconfident: 1,
      overconfident: 2,
    };
    entries.sort((a, b) => {
      const aOrder = a.calibrationLabel !== null ? (CALIBRATION_ORDER[a.calibrationLabel] ?? 3) : 3;
      const bOrder = b.calibrationLabel !== null ? (CALIBRATION_ORDER[b.calibrationLabel] ?? 3) : 3;
      if (aOrder !== bOrder) return aOrder - bOrder;
      return b.trustScore - a.trustScore;
    });
  }

  const total = entries.length;
  const totalPages = Math.max(1, Math.ceil(total / limit));
  const start = (page - 1) * limit;
  const paged = entries.slice(start, start + limit);

  return { entries: paged, total, page, limit, totalPages };
}

// Thresholds match calibration.ts constants (no import to avoid circular dep)
const CAL_OVER = 0.10;
const CAL_UNDER = -0.10;

function calibrationLabelFromMean(mean: number): CalibrationLabel {
  if (mean > CAL_OVER) return "overconfident";
  if (mean < CAL_UNDER) return "underconfident";
  return "calibrated";
}

async function computeCalibrationLabelBatch(): Promise<Map<string, CalibrationLabel>> {
  try {
    const result = await db.execute(sql`
      SELECT ao.user_id::text AS user_id, AVG(ao.confidence_gap) AS mean_gap
      FROM agent_outcomes ao
      JOIN users u ON u.id = ao.user_id
      WHERE ao.visibility = 'public'
        AND u.is_public_profile = true
        AND u.wallet_address NOT LIKE 'erd1trial%'
      GROUP BY ao.user_id
      HAVING COUNT(*) > 0
    `);
    return new Map(
      (result.rows as any[]).map((r) => [
        r.user_id as string,
        calibrationLabelFromMean(Number(r.mean_gap)),
      ])
    );
  } catch (err: any) {
    console.error("[leaderboard] calibration batch failed:", err?.message);
    return new Map();
  }
}

async function computeViolationPenaltyBatch(walletAddresses: string[]): Promise<Map<string, { penalty: number; fault: number; breach: number; proposed: number }>> {
  if (walletAddresses.length === 0) return new Map();
  try {
    const result = await pool.query<{ wallet_address: string; type: string; status: string; cnt: string }>(
      `SELECT wallet_address, type, status, COUNT(*)::int AS cnt
       FROM agent_violations
       WHERE wallet_address = ANY($1)
       GROUP BY wallet_address, type, status`,
      [walletAddresses],
    );
    const raw = new Map<string, { fault: number; breach: number; proposed: number }>();
    for (const row of result.rows) {
      if (!raw.has(row.wallet_address)) raw.set(row.wallet_address, { fault: 0, breach: 0, proposed: 0 });
      const entry = raw.get(row.wallet_address)!;
      const cnt = Number(row.cnt);
      if (row.status === "confirmed" && row.type === "fault") entry.fault = cnt;
      else if (row.status === "confirmed" && row.type === "breach") entry.breach = cnt;
      else if (row.status === "proposed") entry.proposed += cnt;
    }
    const out = new Map<string, { penalty: number; fault: number; breach: number; proposed: number }>();
    for (const wallet of walletAddresses) {
      const entry = raw.get(wallet) ?? { fault: 0, breach: 0, proposed: 0 };
      out.set(wallet, {
        penalty: (entry.fault * VIOLATION_PENALTY.fault) + (entry.breach * VIOLATION_PENALTY.breach),
        ...entry,
      });
    }
    return out;
  } catch {
    return new Map();
  }
}

async function getOldScoreBatch(wallets: string[], cutoff: Date): Promise<Map<string, number>> {
  if (wallets.length === 0) return new Map();
  try {
    const result = await pool.query<{ wallet_address: string; score: string }>(
      `SELECT DISTINCT ON (wallet_address) wallet_address, score
       FROM trust_score_snapshots
       WHERE wallet_address = ANY($1) AND snapshot_date <= $2
       ORDER BY wallet_address, snapshot_date DESC`,
      [wallets, cutoff.toISOString().split("T")[0]],
    );
    const out = new Map<string, number>();
    for (const row of result.rows) {
      out.set(row.wallet_address, Number(row.score));
    }
    return out;
  } catch {
    return new Map();
  }
}

async function getPreviousLevelBatch(wallets: string[]): Promise<Map<string, TrustLevel>> {
  if (wallets.length === 0) return new Map();
  try {
    const result = await pool.query<{ wallet_address: string; level: string }>(
      `SELECT wallet_address, level
       FROM (
         SELECT wallet_address, level,
                ROW_NUMBER() OVER (PARTITION BY wallet_address ORDER BY snapshot_date DESC) AS rn
         FROM trust_score_snapshots
         WHERE wallet_address = ANY($1)
       ) ranked
       WHERE rn = 2`,
      [wallets],
    );
    const out = new Map<string, TrustLevel>();
    for (const row of result.rows) {
      out.set(row.wallet_address, row.level as TrustLevel);
    }
    return out;
  } catch {
    return new Map();
  }
}

export interface CalibrationSummary {
  meanGap: number;
  biasLabel: CalibrationLabel;
  outcomeCount: number;
}

export async function getCalibrationSummaryByWallet(walletAddress: string): Promise<CalibrationSummary | null> {
  try {
    const result = await db.execute(sql`
      SELECT AVG(ao.confidence_gap)::float AS mean_gap, COUNT(*)::int AS cnt
      FROM agent_outcomes ao
      JOIN users u ON u.id = ao.user_id
      WHERE u.wallet_address = ${walletAddress} AND ao.visibility = 'public'
    `);
    const row = result.rows[0] as any;
    const cnt = Number(row?.cnt ?? 0);
    if (cnt === 0) return null;
    const meanGap = Number(row.mean_gap);
    return { meanGap, biasLabel: calibrationLabelFromMean(meanGap), outcomeCount: cnt };
  } catch {
    return null;
  }
}

export function generateTrustBadgeSvg(level: TrustLevel, score: number, attestationCount = 0, violationCount = 0, calibrationLabel?: string | null): string {
  const levelColor = getTrustLevelColor(level);
  const levelColorDark = adjustColor(levelColor, -30);

  // Format score compactly: 43701 → "43.7k", 1234 → "1.2k", 999 → "999"
  const scoreFormatted = score >= 10000
    ? `${Math.round(score / 100) / 10}k`
    : score >= 1000
    ? `${(score / 1000).toFixed(1)}k`
    : `${score}`;

  // Attestation marker appended to level (compact, no prose)
  const attestMark = attestationCount > 0 ? " ✦" : "";

  // Badge text — concise: level name + optional attestation mark + score
  // Violations and calibration labels are intentionally omitted — too verbose for an embeddable badge
  const labelText = "xproof";
  const rightLabel = level + attestMark;
  const rightScore = scoreFormatted;

  // xproof logo mark — icon-only crop of xproof-logo.png (cols 0-157 of 542, full height 168)
  // encoded at 45×48px (3x) for crisp rendering, displayed at 15×16px in badge
  const LOGO_MARK_B64 = "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";

  // Layout constants
  const h = 28;
  const r = 6;
  const lCharW = 6.8;
  const rCharW = 6.5;
  const scoreCharW = 6.0;
  // Logo mark rendered at 18×19px in badge (preserving 157:168 aspect ratio of cropped PNG)
  const iconW = 18;
  const iconH = 19;
  const dotGap = 4;
  const lPad = 7;
  const rPad = 12;
  const scoreSep = 8;

  const labelWidth = Math.round(lPad + iconW + dotGap + labelText.length * lCharW + lPad);
  const rightWidth = Math.round(rPad + rightLabel.length * rCharW + scoreSep + rightScore.length * scoreCharW + rPad);
  const totalWidth = labelWidth + rightWidth;

  const midY = h / 2;
  const textY = midY + 4;

  // Icon position: centered vertically in the left section
  const iconX = lPad;
  const iconY = Math.round(midY - iconH / 2);

  // X for label text center
  const labelCx = Math.round(lPad + iconW + dotGap + (labelText.length * lCharW) / 2);
  const rightLabelStartX = Math.round(labelWidth + rPad);
  const scoreStartX = Math.round(labelWidth + rPad + rightLabel.length * rCharW + scoreSep);

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="${h}" role="img" aria-label="xproof trust: ${level} ${score}">
  <title>xproof · ${level} · ${score}</title>
  <defs>
    <linearGradient id="lbg" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="#252525"/>
      <stop offset="100%" stop-color="#181818"/>
    </linearGradient>
    <linearGradient id="rst" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="${levelColor}"/>
      <stop offset="100%" stop-color="${levelColorDark}"/>
    </linearGradient>
    <clipPath id="cr">
      <rect width="${totalWidth}" height="${h}" rx="${r}"/>
    </clipPath>
  </defs>
  <g clip-path="url(#cr)">
    <rect width="${totalWidth}" height="${h}" fill="url(#lbg)"/>
    <rect x="${labelWidth}" width="${rightWidth}" height="${h}" fill="url(#rst)"/>
  </g>
  <rect width="${totalWidth}" height="${h}" rx="${r}" fill="none" stroke="rgba(255,255,255,0.1)" stroke-width="1"/>
  <image href="data:image/png;base64,${LOGO_MARK_B64}" x="${iconX}" y="${iconY}" width="${iconW}" height="${iconH}"/>
  <text x="${labelCx}" y="${textY}" fill="rgba(255,255,255,0.92)" text-anchor="middle"
        font-family="'Segoe UI','Helvetica Neue',Arial,sans-serif" font-weight="700" font-size="11"
        letter-spacing="0.6" text-rendering="geometricPrecision">${labelText}</text>
  <text x="${rightLabelStartX}" y="${textY}" fill="rgba(255,255,255,0.97)" text-anchor="start"
        font-family="'Segoe UI','Helvetica Neue',Arial,sans-serif" font-weight="700" font-size="11"
        text-rendering="geometricPrecision">${rightLabel}</text>
  <text x="${scoreStartX}" y="${textY}" fill="rgba(255,255,255,0.65)" text-anchor="start"
        font-family="'Segoe UI','Helvetica Neue',Arial,sans-serif" font-weight="400" font-size="10"
        text-rendering="geometricPrecision">${rightScore}</text>
</svg>`;
}

function adjustColor(hex: string, amount: number): string {
  const num = parseInt(hex.replace("#", ""), 16);
  const r = Math.max(0, Math.min(255, (num >> 16) + amount));
  const g = Math.max(0, Math.min(255, ((num >> 8) & 0x00ff) + amount));
  const b = Math.max(0, Math.min(255, (num & 0x0000ff) + amount));
  return `#${((r << 16) | (g << 8) | b).toString(16).padStart(6, "0")}`;
}
