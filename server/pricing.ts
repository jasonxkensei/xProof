const CERTIFICATION_PRICE_EUR = 0.03;

let cachedPrice: { egldEur: number; timestamp: number } | null = null;
const CACHE_DURATION_MS = 5 * 60 * 1000; // 5 minutes cache

export async function getEgldEurPrice(): Promise<number> {
  if (cachedPrice && Date.now() - cachedPrice.timestamp < CACHE_DURATION_MS) {
    return cachedPrice.egldEur;
  }

  try {
    const response = await fetch(
      "https://api.coingecko.com/api/v3/simple/price?ids=elrond-erd-2&vs_currencies=eur"
    );
    
    if (!response.ok) {
      throw new Error(`CoinGecko API error: ${response.status}`);
    }

    const data = await response.json();
    const egldEur = data["elrond-erd-2"]?.eur;

    if (!egldEur || typeof egldEur !== "number") {
      throw new Error("Invalid price data from CoinGecko");
    }

    cachedPrice = { egldEur, timestamp: Date.now() };
    console.log(`💰 EGLD/EUR price updated: ${egldEur}€`);
    
    return egldEur;
  } catch (error) {
    console.error("Failed to fetch EGLD price:", error);
    if (cachedPrice) {
      console.log("Using cached EGLD price as fallback");
      return cachedPrice.egldEur;
    }
    return 30; // Fallback price if no cache and API fails
  }
}

export function eurToEgld(eurAmount: number, egldEurPrice: number): string {
  const egldAmount = eurAmount / egldEurPrice;
  const atomicUnits = BigInt(Math.floor(egldAmount * 1e18));
  return atomicUnits.toString();
}

export function getCertificationPriceEur(): number {
  return CERTIFICATION_PRICE_EUR;
}

export async function getCertificationPriceEgld(): Promise<{
  priceEur: number;
  priceEgld: string;
  egldEurRate: number;
}> {
  const egldEurRate = await getEgldEurPrice();
  const priceEgld = eurToEgld(CERTIFICATION_PRICE_EUR, egldEurRate);
  
  return {
    priceEur: CERTIFICATION_PRICE_EUR,
    priceEgld,
    egldEurRate,
  };
}
