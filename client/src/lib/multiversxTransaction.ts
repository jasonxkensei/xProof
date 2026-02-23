import { Transaction, Address } from "@multiversx/sdk-core";
import { logger } from "@/lib/logger";
import { getAccountProvider } from "@multiversx/sdk-dapp/out/providers/helpers/accountProvider";
import { TransactionManager } from "@multiversx/sdk-dapp/out/managers/TransactionManager";
import { refreshAccount } from "@multiversx/sdk-dapp/out/utils/account/refreshAccount";

export interface MultiversXTransactionResult {
  txHash: string;
  explorerUrl: string;
}

export type TransactionStatusCallback = (status: 'success' | 'failed', txHash: string) => void;

interface TxWatcher {
  callback: TransactionStatusCallback;
  txHash: string;
}

const TX_WATCHERS: TxWatcher[] = [];
const RESOLVED_TX = new Map<string, number>();
const RESOLVED_TTL_MS = 300_000;

function cleanupResolved() {
  const now = Date.now();
  RESOLVED_TX.forEach((ts, hash) => {
    if (now - ts > RESOLVED_TTL_MS) RESOLVED_TX.delete(hash);
  });
}

export function watchTransaction(txHash: string, callback: TransactionStatusCallback): () => void {
  const watcher: TxWatcher = { callback, txHash };
  TX_WATCHERS.push(watcher);
  return () => {
    const idx = TX_WATCHERS.indexOf(watcher);
    if (idx >= 0) TX_WATCHERS.splice(idx, 1);
  };
}

function notifyWatchers(status: 'success' | 'failed', txHash: string) {
  TX_WATCHERS.forEach(w => {
    if (w.txHash === txHash) {
      try { w.callback(status, txHash); } catch (e) { /* ignore */ }
    }
  });
}

function notifyOnce(status: 'success' | 'failed', txHash: string) {
  cleanupResolved();
  if (RESOLVED_TX.has(txHash)) return;
  RESOLVED_TX.set(txHash, Date.now());
  notifyWatchers(status, txHash);
}

const MAINNET_API = "https://api.multiversx.com";
const TX_POLL_INTERVAL_MS = 3000;
const TX_POLL_MAX_ATTEMPTS = 60;

export function pollTransactionStatus(txHash: string): void {
  let attempts = 0;

  const poll = async () => {
    if (RESOLVED_TX.has(txHash)) return;
    attempts++;
    if (attempts > TX_POLL_MAX_ATTEMPTS) {
      logger.log("Transaction polling timed out for:", txHash);
      return;
    }

    try {
      const res = await fetch(`${MAINNET_API}/transactions/${txHash}?fields=status`);
      if (!res.ok) {
        setTimeout(poll, TX_POLL_INTERVAL_MS);
        return;
      }
      const data = await res.json();
      if (data.status === "success") {
        notifyOnce('success', txHash);
        return;
      }
      if (data.status === "fail" || data.status === "invalid") {
        notifyOnce('failed', txHash);
        return;
      }
      setTimeout(poll, TX_POLL_INTERVAL_MS);
    } catch {
      setTimeout(poll, TX_POLL_INTERVAL_MS);
    }
  };

  setTimeout(poll, TX_POLL_INTERVAL_MS);
}

export interface TransactionParams {
  userAddress: string;
  fileHash: string;
  fileName: string;
  authorName?: string;
  receiverAddress?: string;
  valueInAtomicUnits?: string;
}

const MAINNET_EXPLORER = "https://explorer.multiversx.com";
const CHAIN_ID = "1"; // Mainnet
const GAS_PRICE = 1000000000; // 1 Gwei
const SIGNATURE_TIMEOUT_MS = 120000; // 120 seconds for guardian flows

function normalizeForBlockchain(text: string): string {
  return text
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^\x20-\x7E]/g, "_");
}

export async function createCertificationTransaction(params: TransactionParams): Promise<Transaction> {
  const { userAddress, fileHash, fileName, authorName } = params;
  
  // Refresh account to get latest nonce
  await refreshAccount();
  
  // Normalize filename and author for blockchain compatibility (ASCII only)
  const safeFileName = normalizeForBlockchain(fileName);
  const safeAuthorName = authorName ? normalizeForBlockchain(authorName) : undefined;
  
  const payloadText = `xproof:certify:${fileHash}|filename:${safeFileName}${safeAuthorName ? `|author:${safeAuthorName}` : ""}`;
  
  // Get current nonce from SDK store or API
  const { getAccount } = await import('@multiversx/sdk-dapp/out/methods/account/getAccount');
  const account = getAccount();
  const nonce = account?.nonce || 0;
  
  // MultiversX requires minimum 50000 gas + gas per byte of data
  // Add 50000 extra for guardian accounts
  const dataBytes = new TextEncoder().encode(payloadText);
  const gasLimit = 150000 + dataBytes.length * 1500;
  
  const transaction = new Transaction({
    nonce: BigInt(nonce),
    value: BigInt(params.valueInAtomicUnits || "0"),
    sender: Address.newFromBech32(userAddress),
    receiver: Address.newFromBech32(params.receiverAddress || userAddress),
    gasLimit: BigInt(gasLimit),
    gasPrice: BigInt(GAS_PRICE),
    data: dataBytes,
    chainID: CHAIN_ID,
    version: 1, // SDK will upgrade to version 2 if guardian detected
  });
  
  return transaction;
}

async function signWithTimeout(provider: any, transactions: Transaction[]): Promise<any[]> {
  return Promise.race([
    provider.signTransactions(transactions),
    new Promise<never>((_, reject) => 
      setTimeout(() => reject(new Error("SIGNATURE_TIMEOUT")), SIGNATURE_TIMEOUT_MS)
    )
  ]);
}

export async function signAndSendTransaction(transaction: Transaction): Promise<MultiversXTransactionResult> {
  const provider = getAccountProvider();
  
  if (!provider) {
    throw new Error("No wallet provider found. Please connect your wallet first.");
  }
  
  logger.log("🔧 Provider type:", provider.constructor.name);
  logger.log("✍️ Requesting signature from wallet...");
  logger.log("📝 If you have 2FA enabled, complete the verification in your wallet");
  
  try {
    // Initialize provider if needed
    if (typeof provider.init === 'function') {
      await provider.init();
    }
    
    // Sign transactions - SDK handles Guardian/2FA flow automatically
    let signedTransactions: any[];
    try {
      signedTransactions = await signWithTimeout(provider, [transaction]);
    } catch (error: any) {
      if (error.message === "SIGNATURE_TIMEOUT") {
        throw new Error(
          "Signature timeout (2 minutes). If you have 2FA/Guardian enabled on your account, " +
          "the signing window may have closed. Please try again."
        );
      }
      throw error;
    }
    
    if (!signedTransactions || signedTransactions.length === 0) {
      throw new Error("Transaction signing was cancelled or failed");
    }
    
    logger.log("✅ Transaction signed successfully");
    
    // Log for debugging
    logger.log("📋 Signed transactions:", signedTransactions.length);
    
    // Use TransactionManager to send (this is the official SDK approach)
    const txManager = TransactionManager.getInstance();
    
    logger.log("📤 Sending via TransactionManager...");
    const sentTransactions = await txManager.send(signedTransactions);
    
    logger.log("📋 Sent transactions response:", sentTransactions);
    
    // Extract transaction hash
    let txHash = "";
    if (sentTransactions && sentTransactions.length > 0) {
      const sent = sentTransactions[0] as any;
      txHash = sent?.hash || sent?.txHash || "";
      
      // If still no hash, try to get it from the signed transaction
      if (!txHash && signedTransactions[0]) {
        const signedTx = signedTransactions[0] as any;
        // Some providers return the hash after signing
        txHash = signedTx?.hash || signedTx?.txHash || "";
      }
    }
    
    if (!txHash) {
      // Track the transaction session for status updates
      try {
        await txManager.track(sentTransactions, {
          transactionsDisplayInfo: {
            processingMessage: 'Certification in progress...',
            successMessage: 'File certified on blockchain!',
            errorMessage: 'Certification failed'
          }
        });
      } catch (trackError) {
        logger.log("⚠️ Track error (non-fatal):", trackError);
      }
      
      throw new Error(
        "Transaction sent but couldn't retrieve hash. " +
        "Please check your wallet history for the transaction."
      );
    }
    
    logger.log("Transaction sent! Hash:", txHash);
    
    try {
      await txManager.track(sentTransactions, {
        transactionsDisplayInfo: {
          processingMessage: 'Certification in progress...',
          successMessage: 'File certified on blockchain!',
          errorMessage: 'Certification failed'
        },
        onSuccess: async () => {
          logger.log("Transaction confirmed via SDK tracking:", txHash);
          notifyOnce('success', txHash);
        },
        onFail: async () => {
          logger.log("Transaction failed via SDK tracking:", txHash);
          notifyOnce('failed', txHash);
        }
      });
    } catch (trackError) {
      logger.log("SDK track unavailable, using API polling fallback:", trackError);
    }
    
    pollTransactionStatus(txHash);
    
    return {
      txHash,
      explorerUrl: `${MAINNET_EXPLORER}/transactions/${txHash}`,
    };
  } catch (error: any) {
    console.error("Transaction error:", error);
    
    if (error.message?.includes("cancelled") || error.message?.includes("denied")) {
      throw new Error("Transaction was cancelled by user");
    }
    
    throw error;
  }
}

export async function sendCertificationTransaction(params: TransactionParams): Promise<MultiversXTransactionResult> {
  logger.log("🔐 Creating certification transaction for Mainnet...");
  logger.log("📄 File hash:", params.fileHash);
  logger.log("👤 User:", params.userAddress);
  
  const transaction = await createCertificationTransaction(params);
  logger.log("📝 Transaction created, requesting signature from wallet...");
  
  const result = await signAndSendTransaction(transaction);
  logger.log("✅ Transaction sent successfully!");
  logger.log("🔗 Explorer:", result.explorerUrl);
  
  return result;
}
