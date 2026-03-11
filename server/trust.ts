import { db } from "./db";
import { certifications, users, agentViolations } from "@shared/schema";
import { eq, sql, and } from "drizzle-orm";

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
    ORDER BY week_num DESC
  `);

  const weekNumbers = (rows.rows as any[]).map((r) => Number(r.week_num));
  return computeStreakFromWeekNumbers(weekNumbers);
}

async function computeStreakWeeksBatch(userIds: string[]): Promise<Map<string, number>> {
  if (userIds.length === 0) return new Map();

  const results = await Promise.all(
    userIds.map(async (id) => {
      const streak = await computeStreakWeeks(id);
      return [id, streak] as [string, number];
    }),
  );

  return new Map(results);
}

async function computeAttestationBonus(walletAddress: string): Promise<{ bonus: number; count: number }> {
  try {
    const now = new Date();
    const rows = await db.execute(sql`
      SELECT
        a.issuer_wallet,
        COUNT(c.id) FILTER (WHERE c.blockchain_status = 'confirmed') AS issuer_confirmed_certs
      FROM attestations a
      LEFT JOIN users u ON u.wallet_address = a.issuer_wallet
      LEFT JOIN certifications c ON c.user_id = u.id
      WHERE a.subject_wallet = ${walletAddress}
        AND a.status = 'active'
        AND (a.expires_at IS NULL OR a.expires_at > ${now})
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
    const results = await Promise.all(
      walletAddresses.map(async (wallet) => {
        const result = await computeAttestationBonus(wallet);
        return [wallet, result] as [string, { bonus: number; count: number }];
      }),
    );
    return new Map(results);
  } catch {
    return new Map();
  }
}

async function computeTransparencyCounts(userId: string): Promise<{ metadataCount: number; auditCount: number }> {
  try {
    const [result] = await db
      .select({
        metadataCount: sql<number>`COUNT(*) FILTER (WHERE blockchain_status = 'confirmed' AND metadata IS NOT NULL AND (metadata->>'model_hash' IS NOT NULL OR metadata->>'strategy_hash' IS NOT NULL OR metadata->>'version_number' IS NOT NULL))`,
        auditCount: sql<number>`COUNT(*) FILTER (WHERE blockchain_status = 'confirmed' AND metadata IS NOT NULL AND metadata->>'agent_id' IS NOT NULL)`,
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
      confirmed: sql<number>`COUNT(*) FILTER (WHERE blockchain_status = 'confirmed')`,
      last30d: sql<number>`COUNT(*) FILTER (WHERE created_at >= ${cutoff30d} AND blockchain_status = 'confirmed')`,
      firstAt: sql<Date>`MIN(created_at) FILTER (WHERE blockchain_status = 'confirmed')`,
      lastAt: sql<Date>`MAX(created_at) FILTER (WHERE blockchain_status = 'confirmed')`,
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

export async function computeTrustScoreByWallet(walletAddress: string): Promise<TrustScore | null> {
  const [user] = await db
    .select({ id: users.id })
    .from(users)
    .where(eq(users.walletAddress, walletAddress));
  if (!user) return null;
  return computeTrustScore(user.id);
}

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
}

export interface LeaderboardFilters {
  page?: number;
  limit?: number;
  category?: string;
  search?: string;
  attestedOnly?: boolean;
  sortBy?: "score" | "certs" | "streak" | "attestations";
}

export interface LeaderboardResult {
  entries: LeaderboardEntry[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
}

export async function getLeaderboard(filters: LeaderboardFilters = {}): Promise<LeaderboardResult> {
  const page = Math.max(1, filters.page || 1);
  const limit = Math.min(100, Math.max(1, filters.limit || 50));
  const cutoff30d = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

  const rows = await db.execute(sql`
    SELECT
      u.id,
      u.wallet_address,
      u.agent_name,
      u.agent_category,
      u.agent_description,
      u.agent_website,
      COUNT(c.id) FILTER (WHERE c.blockchain_status = 'confirmed') AS cert_total,
      COUNT(c.id) FILTER (WHERE c.blockchain_status = 'confirmed' AND c.created_at >= ${cutoff30d}) AS cert_last_30d,
      MIN(c.created_at) FILTER (WHERE c.blockchain_status = 'confirmed') AS first_cert_at,
      MAX(c.created_at) FILTER (WHERE c.blockchain_status = 'confirmed') AS last_cert_at,
      COUNT(c.id) FILTER (WHERE c.blockchain_status = 'confirmed' AND c.metadata IS NOT NULL AND (c.metadata->>'model_hash' IS NOT NULL OR c.metadata->>'strategy_hash' IS NOT NULL OR c.metadata->>'version_number' IS NOT NULL)) AS metadata_count,
      COUNT(c.id) FILTER (WHERE c.blockchain_status = 'confirmed' AND c.metadata IS NOT NULL AND c.metadata->>'agent_id' IS NOT NULL) AS audit_count
    FROM users u
    LEFT JOIN certifications c ON c.user_id = u.id
    WHERE u.is_public_profile = true
    GROUP BY u.id, u.wallet_address, u.agent_name, u.agent_category, u.agent_description, u.agent_website
  `);

  const allRows = rows.rows as any[];
  const userIds = allRows.map((r) => r.id);
  const walletAddresses = allRows.map((r) => r.wallet_address);

  const cutoff7d = new Date();
  cutoff7d.setDate(cutoff7d.getDate() - 7);

  const [streakMap, attestationMap, oldScoreMap, prevLevelMap, violationMap] = await Promise.all([
    computeStreakWeeksBatch(userIds),
    computeAttestationBonusBatch(walletAddresses),
    getOldScoreBatch(walletAddresses, cutoff7d),
    getPreviousLevelBatch(walletAddresses),
    computeViolationPenaltyBatch(walletAddresses),
  ]);

  let entries = allRows.map((row) => {
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
    };
  });

  entries.sort((a, b) => b.trustScore - a.trustScore);
  entries.forEach((e, i) => { e.rank = i + 1; });

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

  if (filters.sortBy === "certs") entries.sort((a, b) => b.certTotal - a.certTotal);
  else if (filters.sortBy === "streak") entries.sort((a, b) => b.streakWeeks - a.streakWeeks);
  else if (filters.sortBy === "attestations") entries.sort((a, b) => b.activeAttestations - a.activeAttestations);

  const total = entries.length;
  const totalPages = Math.max(1, Math.ceil(total / limit));
  const start = (page - 1) * limit;
  const paged = entries.slice(start, start + limit);

  return { entries: paged, total, page, limit, totalPages };
}

async function computeViolationPenaltyBatch(walletAddresses: string[]): Promise<Map<string, { penalty: number; fault: number; breach: number; proposed: number }>> {
  if (walletAddresses.length === 0) return new Map();
  try {
    const results = await Promise.all(
      walletAddresses.map(async (wallet) => {
        const result = await computeViolationPenalty(wallet);
        return [wallet, result] as [string, { penalty: number; fault: number; breach: number; proposed: number }];
      }),
    );
    return new Map(results);
  } catch {
    return new Map();
  }
}

async function getOldScoreBatch(wallets: string[], cutoff: Date): Promise<Map<string, number>> {
  if (wallets.length === 0) return new Map();
  try {
    const results = await Promise.all(
      wallets.map(async (w) => {
        const r = await db.execute(sql`
          SELECT score FROM trust_score_snapshots
          WHERE wallet_address = ${w} AND snapshot_date <= ${cutoff.toISOString().split("T")[0]}
          ORDER BY snapshot_date DESC LIMIT 1
        `);
        return [w, r.rows.length > 0 ? Number((r.rows[0] as any).score) : null] as [string, number | null];
      }),
    );
    return new Map(results.filter(([, v]) => v !== null) as Array<[string, number]>);
  } catch {
    return new Map();
  }
}

async function getPreviousLevelBatch(wallets: string[]): Promise<Map<string, TrustLevel>> {
  if (wallets.length === 0) return new Map();
  try {
    const results = await Promise.all(
      wallets.map(async (w) => {
        const r = await db.execute(sql`
          SELECT level FROM trust_score_snapshots
          WHERE wallet_address = ${w}
          ORDER BY snapshot_date DESC LIMIT 1 OFFSET 1
        `);
        return [w, r.rows.length > 0 ? (r.rows[0] as any).level as TrustLevel : null] as [string, TrustLevel | null];
      }),
    );
    return new Map(results.filter(([, v]) => v !== null) as Array<[string, TrustLevel]>);
  } catch {
    return new Map();
  }
}

export function generateTrustBadgeSvg(level: TrustLevel, score: number, attestationCount = 0, violationCount = 0): string {
  const levelColor = getTrustLevelColor(level);
  const levelColorDark = adjustColor(levelColor, -20);
  const hasAttestations = attestationCount > 0;

  const labelText = "xproof";
  const attestedLabel = hasAttestations ? ` · ${attestationCount} attested` : "";
  const violationLabel = violationCount > 0 ? ` · ${violationCount} violation${violationCount > 1 ? "s" : ""}` : "";
  const statusText = `${level}${attestedLabel}${violationLabel} (${score})`;
  const pad = 10;
  const labelCharW = 6.8;
  const statusCharW = 6.2;
  const dotR = 3.5;
  const dotSpace = 12;
  const labelWidth = Math.round(labelText.length * labelCharW + pad * 2);
  const statusWidth = Math.round(statusText.length * statusCharW + pad * 2 + dotSpace);
  const totalWidth = labelWidth + statusWidth;
  const h = 24;
  const r = 5;

  const attestedStarX = labelWidth + dotSpace + (statusWidth - dotSpace) / 2 + statusText.length * statusCharW * 0.1;

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="${h}" role="img" aria-label="${labelText}: ${statusText}">
  <title>${labelText}: ${statusText}</title>
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="#1E1E1E"/>
      <stop offset="100%" stop-color="#161616"/>
    </linearGradient>
    <linearGradient id="st" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="${levelColor}"/>
      <stop offset="100%" stop-color="${levelColorDark}"/>
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
  <circle cx="${labelWidth + pad + dotR}" cy="${h / 2}" r="${dotR}" fill="${levelColor}"/>
  <g text-anchor="middle" font-family="'Segoe UI','Helvetica Neue',Arial,sans-serif" font-weight="600" font-size="11" text-rendering="geometricPrecision">
    <text x="${labelWidth / 2}" y="${h / 2 + 4}" fill="rgba(255,255,255,0.9)" letter-spacing="0.5">${labelText}</text>
    <text x="${labelWidth + dotSpace + (statusWidth - dotSpace) / 2}" y="${h / 2 + 4}" fill="rgba(255,255,255,0.95)">${statusText}</text>
  </g>
</svg>`;
}

function adjustColor(hex: string, amount: number): string {
  const num = parseInt(hex.replace("#", ""), 16);
  const r = Math.max(0, Math.min(255, (num >> 16) + amount));
  const g = Math.max(0, Math.min(255, ((num >> 8) & 0x00ff) + amount));
  const b = Math.max(0, Math.min(255, (num & 0x0000ff) + amount));
  return `#${((r << 16) | (g << 8) | b).toString(16).padStart(6, "0")}`;
}
