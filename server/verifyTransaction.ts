import { logger } from "./logger";
import { db } from "./db";
import { certifications } from "@shared/schema";
import { eq } from "drizzle-orm";

const API_URL = process.env.MULTIVERSX_API_URL || "https://api.multiversx.com";

const RETRY_DELAY_MS = 10_000;
const MAX_RETRIES = 3;

export interface VerificationResult {
  verified: boolean;
  error?: string;
  status?: string;
  receiver?: string;
  value?: string;
}

export async function verifyTransactionOnChain(
  txHash: string,
  expectedReceiver: string,
  expectedMinValue: string
): Promise<VerificationResult> {
  try {
    const response = await fetch(`${API_URL}/transactions/${txHash}`);

    if (response.status === 404) {
      return {
        verified: false,
        error: "Transaction not found on blockchain",
      };
    }

    if (!response.ok) {
      logger.error("MultiversX API error during verification", {
        component: "verifyTransaction",
        txHash,
        status: response.status,
      });
      return {
        verified: false,
        error: `Failed to fetch transaction: HTTP ${response.status}`,
      };
    }

    const tx = await response.json();

    if (tx.status === "pending") {
      logger.info("Transaction is still pending on-chain", {
        component: "verifyTransaction",
        txHash,
      });
      return {
        verified: false,
        error: "pending",
        status: "pending",
        receiver: tx.receiver,
        value: tx.value,
      };
    }

    if (tx.status !== "success") {
      return {
        verified: false,
        error: `Transaction status is "${tx.status}", expected "success"`,
        status: tx.status,
        receiver: tx.receiver,
        value: tx.value,
      };
    }

    if (expectedReceiver && tx.receiver?.toLowerCase() !== expectedReceiver.toLowerCase()) {
      return {
        verified: false,
        error: `Transaction receiver mismatch: expected ${expectedReceiver}, got ${tx.receiver}`,
        status: tx.status,
        receiver: tx.receiver,
        value: tx.value,
      };
    }

    const txValue = BigInt(tx.value || "0");
    const expectedValue = BigInt(expectedMinValue || "0");

    if (expectedValue > BigInt(0)) {
      const toleranceValue = (expectedValue * BigInt(98)) / BigInt(100);
      if (txValue < toleranceValue) {
        return {
          verified: false,
          error: `Insufficient payment: expected at least ${toleranceValue.toString()} (with 2% tolerance on ${expectedValue.toString()}), got ${txValue.toString()}`,
          status: tx.status,
          receiver: tx.receiver,
          value: tx.value,
        };
      }
    }

    logger.info("Transaction verified successfully on-chain", {
      component: "verifyTransaction",
      txHash,
      status: tx.status,
      receiver: tx.receiver,
      value: tx.value,
    });

    return {
      verified: true,
      status: tx.status,
      receiver: tx.receiver,
      value: tx.value,
    };
  } catch (error: any) {
    logger.error("Transaction verification error", {
      component: "verifyTransaction",
      txHash,
      error: error.message,
    });
    return {
      verified: false,
      error: `Verification failed: ${error.message}`,
    };
  }
}

export function scheduleVerificationRetry(
  certificationId: string,
  txHash: string,
  expectedReceiver: string,
  expectedMinValue: string
): void {
  let attempt = 0;

  const retry = async () => {
    attempt++;
    logger.info("Background verification retry", {
      component: "verifyTransaction",
      certificationId,
      txHash,
      attempt,
      maxRetries: MAX_RETRIES,
    });

    const result = await verifyTransactionOnChain(txHash, expectedReceiver, expectedMinValue);

    if (result.verified) {
      await db
        .update(certifications)
        .set({ blockchainStatus: "confirmed" })
        .where(eq(certifications.id, certificationId));
      logger.info("Background verification succeeded — certification confirmed", {
        component: "verifyTransaction",
        certificationId,
        txHash,
        attempt,
      });
      return;
    }

    if (result.error === "pending" || result.error === "Transaction not found on blockchain") {
      if (attempt < MAX_RETRIES) {
        setTimeout(retry, RETRY_DELAY_MS);
        return;
      }
    }

    if (attempt >= MAX_RETRIES) {
      const isStillIndexing = result.error === "pending" || result.error === "Transaction not found on blockchain";
      const finalStatus = isStillIndexing ? "pending" : "failed";
      await db
        .update(certifications)
        .set({ blockchainStatus: finalStatus })
        .where(eq(certifications.id, certificationId));
      logger.warn("Background verification exhausted retries", {
        component: "verifyTransaction",
        certificationId,
        txHash,
        attempt,
        finalStatus,
        error: result.error,
      });
      return;
    }

    await db
      .update(certifications)
      .set({ blockchainStatus: "failed" })
      .where(eq(certifications.id, certificationId));
    logger.warn("Background verification failed — certification marked failed", {
      component: "verifyTransaction",
      certificationId,
      txHash,
      attempt,
      error: result.error,
    });
  };

  setTimeout(retry, RETRY_DELAY_MS);
}
