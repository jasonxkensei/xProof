import { db } from "./db";
import { txQueue } from "@shared/schema";
import { eq, and, lte, or, isNull, sql, count } from "drizzle-orm";
import { setMx8004QueueSize } from "./metrics";
import {
  initJob,
  submitProof,
  validationRequest,
  validationResponse,
  appendResponse,
  resetNonce,
} from "./mx8004";

let workerInterval: ReturnType<typeof setInterval> | null = null;

export async function enqueueTx(
  jobType: string,
  jobId: string,
  payload: Record<string, any>
): Promise<void> {
  await db.insert(txQueue).values({
    jobType,
    jobId,
    payload,
    status: "pending",
    attempts: 0,
    maxAttempts: 3,
  });
  console.log(`[TX-Queue] Enqueued job: ${jobType} / ${jobId}`);
}

async function processNextTask(): Promise<void> {
  try {
    const now = new Date();

    const [task] = await db
      .update(txQueue)
      .set({ status: "processing", startedAt: now })
      .where(
        and(
          eq(txQueue.status, "pending"),
          or(isNull(txQueue.nextRetryAt), lte(txQueue.nextRetryAt, now))
        )
      )
      .returning();

    if (!task) return;

    console.log(`[TX-Queue] Processing: ${task.jobType} / ${task.jobId} (attempt ${task.attempts + 1}/${task.maxAttempts})`);

    try {
      await executeTask(task.jobType, task.jobId, task.payload as Record<string, any>);

      await db
        .update(txQueue)
        .set({ status: "completed", completedAt: new Date() })
        .where(eq(txQueue.id, task.id));

      console.log(`[TX-Queue] Completed: ${task.jobType} / ${task.jobId}`);
    } catch (err: any) {
      const newAttempts = task.attempts + 1;
      const errorMessage = err.message || String(err);

      console.error(`[TX-Queue] Failed: ${task.jobType} / ${task.jobId} - ${errorMessage}`);

      resetNonce();

      if (newAttempts >= task.maxAttempts) {
        await db
          .update(txQueue)
          .set({
            status: "failed",
            attempts: newAttempts,
            lastError: errorMessage,
          })
          .where(eq(txQueue.id, task.id));

        console.error(`[TX-Queue] Max attempts reached, marking as failed: ${task.jobId}`);
      } else {
        const backoffSeconds = [10, 30, 90][newAttempts - 1] || 90;
        const nextRetry = new Date(Date.now() + backoffSeconds * 1000);

        await db
          .update(txQueue)
          .set({
            status: "pending",
            attempts: newAttempts,
            lastError: errorMessage,
            nextRetryAt: nextRetry,
          })
          .where(eq(txQueue.id, task.id));

        console.log(`[TX-Queue] Will retry in ${backoffSeconds}s: ${task.jobId}`);
      }
    }

    await updateQueueMetrics();
  } catch (err: any) {
    console.error(`[TX-Queue] Worker error: ${err.message}`);
  }
}

async function executeTask(
  jobType: string,
  jobId: string,
  payload: Record<string, any>
): Promise<void> {
  switch (jobType) {
    case "mx8004_validation_loop": {
      const { certificationId, fileHash, transactionHash, agentNonce, senderAddress } = payload;
      const proof = `hash:${fileHash}|tx:${transactionHash}`;

      console.log(`[TX-Queue] Registering job: ${jobId} for agent nonce ${agentNonce}`);

      const jobTxHash = await initJob(jobId, agentNonce);
      console.log(`[TX-Queue] Job initialized: ${jobTxHash}`);

      const proofTxHash = await submitProof(jobId, proof);
      console.log(`[TX-Queue] Proof submitted: ${proofTxHash}`);

      const crypto = await import("crypto");
      const requestHash = crypto.createHash("sha256").update(proof).digest("hex");
      const requestUri = `https://xproof.app/proof/${certificationId}.json`;

      const valReqTxHash = await validationRequest(jobId, senderAddress, requestUri, requestHash);
      console.log(`[TX-Queue] Validation request: ${valReqTxHash}`);

      const responseUri = `https://xproof.app/proof/${certificationId}`;
      const responseHash = crypto.createHash("sha256").update(`verified:${fileHash}`).digest("hex");
      const valRespTxHash = await validationResponse(requestHash, 100, responseUri, responseHash, "xproof-certification");
      console.log(`[TX-Queue] Validation response (verified): ${valRespTxHash}`);

      const certUrl = `https://xproof.app/api/certificates/${certificationId}.pdf`;
      const appendTxHash = await appendResponse(jobId, certUrl);
      console.log(`[TX-Queue] Response appended: ${appendTxHash}`);
      break;
    }
    default:
      throw new Error(`Unknown job type: ${jobType}`);
  }
}

async function updateQueueMetrics(): Promise<void> {
  try {
    const [result] = await db
      .select({ count: count() })
      .from(txQueue)
      .where(eq(txQueue.status, "pending"));
    setMx8004QueueSize(result.count);
  } catch {
    // ignore metrics errors
  }
}

export async function getTxQueueStats(): Promise<{
  pending: number;
  processing: number;
  completed: number;
  failed: number;
  total: number;
}> {
  const [pendingRow] = await db.select({ count: count() }).from(txQueue).where(eq(txQueue.status, "pending"));
  const [processingRow] = await db.select({ count: count() }).from(txQueue).where(eq(txQueue.status, "processing"));
  const [completedRow] = await db.select({ count: count() }).from(txQueue).where(eq(txQueue.status, "completed"));
  const [failedRow] = await db.select({ count: count() }).from(txQueue).where(eq(txQueue.status, "failed"));
  const [totalRow] = await db.select({ count: count() }).from(txQueue);

  return {
    pending: pendingRow.count,
    processing: processingRow.count,
    completed: completedRow.count,
    failed: failedRow.count,
    total: totalRow.count,
  };
}

export function startTxQueueWorker(): void {
  if (workerInterval) return;
  console.log("[TX-Queue] Worker started (polling every 2s)");
  workerInterval = setInterval(processNextTask, 2000);
}

export function stopTxQueueWorker(): void {
  if (workerInterval) {
    clearInterval(workerInterval);
    workerInterval = null;
    console.log("[TX-Queue] Worker stopped");
  }
}
