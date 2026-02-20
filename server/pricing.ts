import { logger } from "./logger";
import { db } from "./db";
import { certifications } from "@shared/schema";
import { count } from "drizzle-orm";

const PRICING_TIERS = [
  { min: 0, max: 100000, priceUsd: 0.05 },
  { min: 100001, max: 1000000, priceUsd: 0.025 },
  { min: 1000001, max: Infinity, priceUsd: 0.01 },
];

let cachedPrice: { egldUsd: number; timestamp: number } | null = null;
const CACHE_DURATION_MS = 5 * 60 * 1000; // 5 minutes cache

let cachedTotalCount: { count: number; timestamp: number } | null = null;
const COUNT_CACHE_DURATION_MS = 60 * 1000;

async function getTotalCertificationCount(): Promise<number> {
  if (cachedTotalCount && Date.now() - cachedTotalCount.timestamp < COUNT_CACHE_DURATION_MS) {
    return cachedTotalCount.count;
  }

  try {
    const result = await db.select({ value: count() }).from(certifications);
    const totalCount = result[0]?.value ?? 0;
    cachedTotalCount = { count: totalCount, timestamp: Date.now() };
    return totalCount;
  } catch (error) {
    logger.error("Failed to fetch total certification count", { component: "pricing" });
    if (cachedTotalCount) {
      logger.info("Using cached certification count as fallback", { component: "pricing" });
      return cachedTotalCount.count;
    }
    return 0;
  }
}

function getPriceForCount(totalCount: number): number {
  for (const tier of PRICING_TIERS) {
    if (totalCount >= tier.min && totalCount <= tier.max) {
      return tier.priceUsd;
    }
  }
  // Fallback to lowest tier price (should not happen)
  return PRICING_TIERS[PRICING_TIERS.length - 1].priceUsd;
}

export async function getEgldUsdPrice(): Promise<number> {
  if (cachedPrice && Date.now() - cachedPrice.timestamp < CACHE_DURATION_MS) {
    return cachedPrice.egldUsd;
  }

  try {
    const response = await fetch(
      "https://api.coingecko.com/api/v3/simple/price?ids=elrond-erd-2&vs_currencies=usd"
    );
    
    if (!response.ok) {
      throw new Error(`CoinGecko API error: ${response.status}`);
    }

    const data = await response.json();
    const egldUsd = data["elrond-erd-2"]?.usd;

    if (!egldUsd || typeof egldUsd !== "number") {
      throw new Error("Invalid price data from CoinGecko");
    }

    cachedPrice = { egldUsd, timestamp: Date.now() };
    logger.info("EGLD/USD price updated", { component: "pricing", egldUsd });
    
    return egldUsd;
  } catch (error) {
    logger.error("Failed to fetch EGLD price", { component: "pricing" });
    if (cachedPrice) {
      logger.info("Using cached EGLD price as fallback", { component: "pricing" });
      return cachedPrice.egldUsd;
    }
    return 30; // Fallback price if no cache and API fails
  }
}

export function usdToEgld(usdAmount: number, egldUsdPrice: number): string {
  const egldAmount = usdAmount / egldUsdPrice;
  const atomicUnits = BigInt(Math.floor(egldAmount * 1e18));
  return atomicUnits.toString();
}

export async function getCertificationPriceUsd(): Promise<number> {
  const totalCount = await getTotalCertificationCount();
  return getPriceForCount(totalCount);
}

export async function getCertificationPriceEgld(): Promise<{
  priceUsd: number;
  priceEgld: string;
  egldUsdRate: number;
}> {
  const egldUsdRate = await getEgldUsdPrice();
  const priceUsd = await getCertificationPriceUsd();
  const priceEgld = usdToEgld(priceUsd, egldUsdRate);
  
  return {
    priceUsd,
    priceEgld,
    egldUsdRate,
  };
}

export async function getPricingInfo(): Promise<{
  current_price_usd: number;
  current_tier: { min: number; max: number | null; price_usd: number };
  total_certifications: number;
  tiers: Array<{ min: number; max: number | null; price_usd: number }>;
  next_tier: { min: number; max: number | null; price_usd: number } | null;
  certifications_until_next_tier: number | null;
}> {
  const totalCount = await getTotalCertificationCount();
  const currentPrice = getPriceForCount(totalCount);

  // Find current tier
  let currentTier = PRICING_TIERS[0];
  for (const tier of PRICING_TIERS) {
    if (totalCount >= tier.min && totalCount <= tier.max) {
      currentTier = tier;
      break;
    }
  }

  // Find next tier
  let nextTier = null;
  let certsUntilNext = null;
  for (let i = 0; i < PRICING_TIERS.length; i++) {
    if (PRICING_TIERS[i] === currentTier && i < PRICING_TIERS.length - 1) {
      nextTier = PRICING_TIERS[i + 1];
      certsUntilNext = nextTier.min - totalCount;
      break;
    }
  }

  return {
    current_price_usd: currentPrice,
    current_tier: {
      min: currentTier.min,
      max: currentTier.max === Infinity ? null : currentTier.max,
      price_usd: currentTier.priceUsd,
    },
    total_certifications: totalCount,
    tiers: PRICING_TIERS.map((tier) => ({
      min: tier.min,
      max: tier.max === Infinity ? null : tier.max,
      price_usd: tier.priceUsd,
    })),
    next_tier: nextTier ? {
      min: nextTier.min,
      max: nextTier.max === Infinity ? null : nextTier.max,
      price_usd: nextTier.priceUsd,
    } : null,
    certifications_until_next_tier: certsUntilNext,
  };
}
