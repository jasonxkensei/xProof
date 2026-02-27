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
 * Returns true if the tx is confirmed and sent >= minAmount USDC to `payTo`.
 */
export async function verifyUsdcOnBase(
  txHash: string,
  payTo: string,
  minAmountRaw: string,
): Promise<{ valid: boolean; error?: string }> {
  try {
    const client = getBaseClient();
    const receipt = await client.getTransactionReceipt({
      hash: txHash as `0x${string}`,
    });

    if (!receipt) return { valid: false, error: "Transaction not found on Base" };
    if (receipt.status !== "success") return { valid: false, error: "Transaction failed or pending" };

    const payToLower = payTo.toLowerCase();
    const minAmount = BigInt(minAmountRaw);

    for (const log of receipt.logs) {
      if (
        log.address.toLowerCase() !== USDC_BASE.toLowerCase() ||
        log.topics[0] !== TRANSFER_TOPIC ||
        log.topics.length < 3
      ) continue;

      // topics[2] is the `to` address (padded to 32 bytes)
      const toAddr = "0x" + (log.topics[2] as string).slice(26);
      if (toAddr.toLowerCase() !== payToLower) continue;

      const amount = BigInt(log.data);
      if (amount >= minAmount) return { valid: true };
    }

    return { valid: false, error: `No USDC transfer to ${payTo} found in tx` };
  } catch (err: any) {
    return { valid: false, error: `Verification error: ${err.message}` };
  }
}
