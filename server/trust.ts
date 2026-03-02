import { db } from "./db";
import { certifications, users } from "@shared/schema";
import { eq, and, sql, gte, count } from "drizzle-orm";

export type TrustLevel = "Newcomer" | "Active" | "Trusted" | "Verified";

export interface TrustScore {
  score: number;
  level: TrustLevel;
  certTotal: number;
  certLast30d: number;
  streakWeeks: number;
  firstCertAt: string | null;
  lastCertAt: string | null;
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

function computeScore(
  confirmed: number,
  last30d: number,
  streakWeeks: number,
  firstAt: Date | null,
  lastAt: Date | null,
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

  return Math.round(baseScore + recencyBonus + ageBonus + streakBonus);
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

  const rows = await db.execute(sql`
    SELECT user_id,
      ARRAY_AGG(DISTINCT FLOOR(EXTRACT(EPOCH FROM created_at - '2024-01-01'::timestamp) / 604800)::int ORDER BY FLOOR(EXTRACT(EPOCH FROM created_at - '2024-01-01'::timestamp) / 604800)::int DESC) AS week_nums
    FROM certifications
    WHERE user_id = ANY(${userIds})
      AND blockchain_status = 'confirmed'
    GROUP BY user_id
  `);

  const result = new Map<string, number>();
  for (const row of rows.rows as any[]) {
    const weekNums = (row.week_nums || []).map(Number);
    result.set(row.user_id, computeStreakFromWeekNumbers(weekNums));
  }
  return result;
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

  const streakWeeks = await computeStreakWeeks(userId);
  const score = computeScore(confirmed, last30d, streakWeeks, firstAt, lastAt);

  return {
    score,
    level: getTrustLevel(score),
    certTotal: confirmed,
    certLast30d: last30d,
    streakWeeks,
    firstCertAt: firstAt ? firstAt.toISOString() : null,
    lastCertAt: lastAt ? lastAt.toISOString() : null,
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
  firstCertAt: string | null;
  lastCertAt: string | null;
}

export async function getLeaderboard(): Promise<LeaderboardEntry[]> {
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
      MAX(c.created_at) FILTER (WHERE c.blockchain_status = 'confirmed') AS last_cert_at
    FROM users u
    LEFT JOIN certifications c ON c.user_id = u.id
    WHERE u.is_public_profile = true
    GROUP BY u.id, u.wallet_address, u.agent_name, u.agent_category, u.agent_description, u.agent_website
  `);

  const allRows = rows.rows as any[];
  const userIds = allRows.map((r) => r.id);
  const streakMap = await computeStreakWeeksBatch(userIds);

  const entries = allRows.map((row) => {
    const confirmed = Number(row.cert_total || 0);
    const last30d = Number(row.cert_last_30d || 0);
    const firstAt = row.first_cert_at ? new Date(row.first_cert_at) : null;
    const lastAt = row.last_cert_at ? new Date(row.last_cert_at) : null;
    const streakWeeks = streakMap.get(row.id) || 0;
    const score = computeScore(confirmed, last30d, streakWeeks, firstAt, lastAt);

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
      firstCertAt: firstAt ? firstAt.toISOString() : null,
      lastCertAt: lastAt ? lastAt.toISOString() : null,
    };
  });
  entries.sort((a, b) => b.trustScore - a.trustScore);
  return entries.slice(0, 50);
}

export function generateTrustBadgeSvg(level: TrustLevel, score: number): string {
  const levelColor = getTrustLevelColor(level);
  const levelColorDark = adjustColor(levelColor, -20);

  const labelText = "xproof";
  const statusText = `${level} (${score})`;
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
