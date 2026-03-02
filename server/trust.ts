import { db } from "./db";
import { certifications, users } from "@shared/schema";
import { eq, and, sql, gte, count } from "drizzle-orm";

export type TrustLevel = "Newcomer" | "Active" | "Trusted" | "Verified";

export interface TrustScore {
  score: number;
  level: TrustLevel;
  certTotal: number;
  certLast30d: number;
  firstCertAt: string | null;
  lastCertAt: string | null;
}

export function getTrustLevel(score: number): TrustLevel {
  if (score >= 700) return "Verified";
  if (score >= 300) return "Trusted";
  if (score >= 100) return "Active";
  return "Newcomer";
}

function computeScore(confirmed: number, last30d: number, firstAt: Date | null, lastAt: Date | null): number {
  const daysSinceFirst = firstAt
    ? Math.floor((Date.now() - firstAt.getTime()) / (1000 * 60 * 60 * 24))
    : 0;
  const daysSinceLastCert = lastAt
    ? Math.floor((Date.now() - lastAt.getTime()) / (1000 * 60 * 60 * 24))
    : Infinity;

  const baseScore = confirmed * 10;
  const recencyBonus = last30d * 5;
  const ageBonus = daysSinceLastCert <= 60 ? Math.min(150, daysSinceFirst * 0.3) : 0;
  return Math.round(baseScore + recencyBonus + ageBonus);
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

  const score = computeScore(confirmed, last30d, firstAt, lastAt);

  return {
    score,
    level: getTrustLevel(score),
    certTotal: confirmed,
    certLast30d: last30d,
    firstCertAt: firstAt ? firstAt.toISOString() : null,
    lastCertAt: lastAt ? lastAt.toISOString() : null,
  };
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

  const entries = (rows.rows as any[]).map((row) => {
    const confirmed = Number(row.cert_total || 0);
    const last30d = Number(row.cert_last_30d || 0);
    const firstAt = row.first_cert_at ? new Date(row.first_cert_at) : null;
    const lastAt = row.last_cert_at ? new Date(row.last_cert_at) : null;
    const score = computeScore(confirmed, last30d, firstAt, lastAt);

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
      firstCertAt: firstAt ? firstAt.toISOString() : null,
      lastCertAt: lastAt ? lastAt.toISOString() : null,
    };
  });

  entries.sort((a, b) => b.trustScore - a.trustScore);
  return entries.slice(0, 50);
}
