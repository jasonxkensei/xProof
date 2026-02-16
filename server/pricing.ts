import { logger } from "./logger";

const CERTIFICATION_PRICE_USD = 0.05;

let cachedPrice: { egldUsd: number; timestamp: number } | null = null;
const CACHE_DURATION_MS = 5 * 60 * 1000; // 5 minutes cache

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

export function getCertificationPriceUsd(): number {
  return CERTIFICATION_PRICE_USD;
}

export async function getCertificationPriceEgld(): Promise<{
  priceUsd: number;
  priceEgld: string;
  egldUsdRate: number;
}> {
  const egldUsdRate = await getEgldUsdPrice();
  const priceEgld = usdToEgld(CERTIFICATION_PRICE_USD, egldUsdRate);
  
  return {
    priceUsd: CERTIFICATION_PRICE_USD,
    priceEgld,
    egldUsdRate,
  };
}
