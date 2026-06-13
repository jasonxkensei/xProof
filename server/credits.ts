import { createPublicClient, http, parseAbiItem } from "viem";
import { base } from "viem/chains";

// USDC contract on Base mainnet (6 decimals)
const USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" as const;
const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

export interface CreditPackage {
  id: string;
  name: string;
  description: string;
  certs: number;
  price_usdc: string;
  price_usdc_raw: string; // 6 decimal units
  price_per_cert: string;
}

export const CREDIT_PACKAGES: CreditPackage[] = [
  {
    id: "starter",
    name: "Starter",
    description: "100 certifications — ideal for small agents or testing at scale",
    certs: 100,
    price_usdc: "5.00",
    price_usdc_raw: "5000000",
    price_per_cert: "$0.05",
  },
  {
    id: "pro",
    name: "Pro",
    description: "1,000 certifications — for production agents with regular output",
    certs: 1000,
    price_usdc: "40.00",
    price_usdc_raw: "40000000",
    price_per_cert: "$0.04",
  },
  {
    id: "business",
    name: "Business",
    description: "10,000 certifications — high-volume agents, best unit price",
    certs: 10000,
    price_usdc: "300.00",
    price_usdc_raw: "300000000",
    price_per_cert: "$0.03",
  },
];

export function getPackage(id: string): CreditPackage | null {
  return CREDIT_PACKAGES.find((p) => p.id === id) ?? null;
}

// Launch promo: -50% on packs of 1,000+ certs while the network stays in Tier 1 (< 100k total certs).
// Packs below 1,000 certs are excluded — the discount is a volume incentive for committed agents.
const PROMO_TIER1_MAX_CERTS = 100000;

export interface EffectiveCreditPackage extends CreditPackage {
  promo_active: boolean;
  original_price_usdc?: string;
  original_price_per_cert?: string;
}

/**
 * Returns each package with its effective (possibly discounted) price for a given total network cert count.
 * When the network is in Tier 1 (totalCerts < 100k), packs of 1,000+ certs are 50% off.
 */
export function getEffectivePackages(totalCerts: number): EffectiveCreditPackage[] {
  const promoActive = totalCerts < PROMO_TIER1_MAX_CERTS;
  return CREDIT_PACKAGES.map((pkg) => {
    if (promoActive && pkg.certs >= 1000) {
      const rawHalf = (BigInt(pkg.price_usdc_raw) / 2n).toString();
      const usdHalf = (parseFloat(pkg.price_usdc) / 2).toFixed(2);
      const perCertHalf = `$${(parseFloat(pkg.price_usdc) / 2 / pkg.certs).toFixed(4).replace(/\.?0+$/, "")}`;
      return {
        ...pkg,
        price_usdc: usdHalf,
        price_usdc_raw: rawHalf,
        price_per_cert: perCertHalf,
        promo_active: true,
        original_price_usdc: pkg.price_usdc,
        original_price_per_cert: pkg.price_per_cert,
      };
    }
    return { ...pkg, promo_active: false };
  });
}

/**
 * Returns the effective (possibly discounted) version of a single package.
 * Returns null if the id is not found.
 */
export function getEffectivePackage(id: string, totalCerts: number): EffectiveCreditPackage | null {
  return getEffectivePackages(totalCerts).find((p) => p.id === id) ?? null;
}

let _client: ReturnType<typeof createPublicClient> | null = null;
function getBaseClient() {
  if (!_client) {
    const rpcUrl = process.env.BASE_RPC_URL || "https://mainnet.base.org";
    _client = createPublicClient({ chain: base, transport: http(rpcUrl) });
  }
  return _client;
}

/**
 * Verifies a USDC transfer on Base mainnet.
 * Returns { valid, error, txTimestamp } where txTimestamp is the block time of the tx.
 * txTimestamp is used by callers to enforce that the purchase intent predates the payment.
 */
export async function verifyUsdcOnBase(
  txHash: string,
  payTo: string,
  minAmountRaw: string,
  fromAddress?: string,
): Promise<{ valid: boolean; error?: string; txTimestamp?: Date }> {
  try {
    const client = getBaseClient();
    const receipt = await client.getTransactionReceipt({
      hash: txHash as `0x${string}`,
    });

    if (!receipt) return { valid: false, error: "Transaction not found on Base" };
    if (receipt.status !== "success") return { valid: false, error: "Transaction failed or pending" };

    // Fetch block timestamp — required to enforce that tx postdates the purchase intent.
    // If timestamp is unavailable we fail-closed (return invalid) so callers cannot skip
    // the pre-dated-intent check due to a missing timestamp.
    const block = await client.getBlock({ blockNumber: receipt.blockNumber });
    const txTimestamp = new Date(Number(block.timestamp) * 1000);

    const payToLower = payTo.toLowerCase();
    const minAmount = BigInt(minAmountRaw);
    const fromLower = fromAddress ? fromAddress.toLowerCase() : null;

    for (const log of receipt.logs) {
      if (
        log.address.toLowerCase() !== USDC_BASE.toLowerCase() ||
        log.topics[0] !== TRANSFER_TOPIC ||
        log.topics.length < 3
      ) continue;

      // topics[1] is the `from` address (padded to 32 bytes)
      // topics[2] is the `to` address (padded to 32 bytes)
      const fromAddr = "0x" + (log.topics[1] as string).slice(26);
      const toAddr = "0x" + (log.topics[2] as string).slice(26);

      if (toAddr.toLowerCase() !== payToLower) continue;

      // If a sender is required, verify it
      if (fromLower && fromAddr.toLowerCase() !== fromLower) {
        return { valid: false, error: `USDC sender ${fromAddr} does not match expected payer ${fromAddress}` };
      }

      const amount = BigInt(log.data);
      if (amount >= minAmount) return { valid: true, txTimestamp };
    }

    return { valid: false, error: `No USDC transfer to ${payTo} found in tx` };
  } catch (err: any) {
    return { valid: false, error: `Verification error: ${err.message}` };
  }
}
