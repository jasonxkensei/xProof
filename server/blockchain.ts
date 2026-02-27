import {
  Transaction,
  TransactionComputer,
  Address,
} from "@multiversx/sdk-core";
import { recordTransaction } from "./metrics";
import { logger } from "./logger";

// MultiversX configuration from environment
const PRIVATE_KEY = process.env.MULTIVERSX_PRIVATE_KEY;
const SENDER_ADDRESS = process.env.MULTIVERSX_SENDER_ADDRESS;
const RECEIVER_ADDRESS = process.env.MULTIVERSX_RECEIVER_ADDRESS || process.env.MULTIVERSX_SENDER_ADDRESS;
const GATEWAY_URL = process.env.MULTIVERSX_GATEWAY_URL || "https://gateway.multiversx.com";
const API_URL = process.env.MULTIVERSX_API_URL || "https://api.multiversx.com";
const CHAIN_ID = process.env.MULTIVERSX_CHAIN_ID || "1"; // 1 = mainnet, D = devnet, T = testnet

// Check if MultiversX is properly configured
export function isMultiversXConfigured(): boolean {
  return !!(PRIVATE_KEY && SENDER_ADDRESS);
}

// Get account nonce from MultiversX API
async function getAccountNonce(address: string): Promise<bigint> {
  const response = await fetch(`${API_URL}/accounts/${address}`);
  if (!response.ok) {
    throw new Error(`Failed to fetch account nonce: ${response.statusText}`);
  }
  const data = await response.json();
  return BigInt(data.nonce ?? 0);
}

// Submit signed transaction to MultiversX gateway
async function submitTransaction(tx: Transaction): Promise<{
  txHash: string;
}> {
  const response = await fetch(`${GATEWAY_URL}/transaction/send`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(tx.toSendable()),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Gateway error: ${response.statusText} - ${errorText}`);
  }

  const result = await response.json();
  
  if (result.error) {
    throw new Error(`Transaction error: ${result.error}`);
  }

  if (!result.data?.txHash) {
    throw new Error(`Invalid gateway response: ${JSON.stringify(result)}`);
  }

  return {
    txHash: result.data.txHash,
  };
}

/**
 * Record a file hash on the MultiversX blockchain
 * Creates a transaction with format: "certify:<hash>|filename:<name>|author:<author>"
 */
export async function recordOnBlockchain(
  fileHash: string,
  filename?: string,
  author?: string
): Promise<{
  transactionHash: string;
  transactionUrl: string;
}> {
  // If MultiversX is not configured, return simulation (for development)
  if (!isMultiversXConfigured()) {
    logger.warn("MultiversX not configured, using simulation mode", { component: "blockchain" });
    
    const simulatedHash = `sim_${Date.now()}_${fileHash.substring(0, 8)}`;
    const latency = Math.floor(Math.random() * 200) + 500; // 500-700ms simulation
    recordTransaction(true, latency, "certification");

    return {
      transactionHash: simulatedHash,
      transactionUrl: `https://explorer.multiversx.com/transactions/${simulatedHash}`,
    };
  }

  const txStart = Date.now();
  try {
    const payloadText = `certify:${fileHash}${filename ? `|filename:${filename}` : ""}${author ? `|author:${author}` : ""}`;
    const dataPayload = Buffer.from(payloadText);

    const nonce = await getAccountNonce(SENDER_ADDRESS!);

    const gasLimit = BigInt(50000 + dataPayload.length * 1500);

    const transaction = new Transaction({
      nonce: nonce,
      value: BigInt(0),
      sender: Address.newFromBech32(SENDER_ADDRESS!),
      receiver: Address.newFromBech32(RECEIVER_ADDRESS!),
      gasLimit: gasLimit,
      data: dataPayload,
      chainID: CHAIN_ID,
    });

    const privateKeyHex = PRIVATE_KEY!.replace(/^0x/i, "");
    const privateKeyBuffer = Buffer.from(privateKeyHex, "hex");
    
    const computer = new TransactionComputer();
    const serializedTx = computer.computeBytesForSigning(transaction);
    
    const ed = await import("@noble/ed25519");
    const { sha512 } = await import("@noble/hashes/sha512");
    ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));
    const signature = await ed.signAsync(serializedTx, privateKeyBuffer.slice(0, 32));
    transaction.signature = Buffer.from(signature);

    const result = await submitTransaction(transaction);

    const explorerBaseUrl = CHAIN_ID === "D" 
      ? "https://devnet-explorer.multiversx.com"
      : CHAIN_ID === "T"
      ? "https://testnet-explorer.multiversx.com"
      : "https://explorer.multiversx.com";

    recordTransaction(true, Date.now() - txStart, "certification");

    return {
      transactionHash: result.txHash,
      transactionUrl: `${explorerBaseUrl}/transactions/${result.txHash}`,
    };
  } catch (error: any) {
    recordTransaction(false, Date.now() - txStart, "certification");
    logger.error("MultiversX transaction error", { component: "blockchain", error: error instanceof Error ? error.message : String(error) });
    throw new Error(`Failed to record on blockchain: ${error.message}`);
  }
}

/**
 * Broadcast a signed transaction (from XPortal or other wallet)
 */
export async function broadcastSignedTransaction(signedTx: any): Promise<{
  txHash: string;
  explorerUrl: string;
}> {
  try {
    const response = await fetch(`${GATEWAY_URL}/transaction/send`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(signedTx),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Gateway error: ${response.statusText} - ${errorText}`);
    }

    const result = await response.json();
    
    if (result.error) {
      throw new Error(`Transaction error: ${result.error}`);
    }

    if (!result.data?.txHash) {
      throw new Error(`Invalid gateway response: ${JSON.stringify(result)}`);
    }

    // Build explorer URL based on network
    const explorerBaseUrl = CHAIN_ID === "D" 
      ? "https://devnet-explorer.multiversx.com"
      : CHAIN_ID === "T"
      ? "https://testnet-explorer.multiversx.com"
      : "https://explorer.multiversx.com";

    return {
      txHash: result.data.txHash,
      explorerUrl: `${explorerBaseUrl}/transactions/${result.data.txHash}`,
    };
  } catch (error: any) {
    logger.error("Broadcast error", { component: "blockchain", error: error instanceof Error ? error.message : String(error) });
    throw new Error(`Failed to broadcast transaction: ${error.message}`);
  }
}

/**
 * Verify a transaction exists on the blockchain
 */
export async function verifyTransaction(txHash: string): Promise<{
  success: boolean;
  data?: any;
}> {
  try {
    const response = await fetch(`${API_URL}/transactions/${txHash}?withResults=true`);
    
    if (!response.ok) {
      return { success: false };
    }

    const result = await response.json();
    
    return {
      success: result.status === "success",
      data: result,
    };
  } catch (error) {
    logger.error("Transaction verification error", { component: "blockchain", error: error instanceof Error ? error.message : String(error) });
    return { success: false };
  }
}
