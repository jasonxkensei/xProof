import crypto from "crypto";
import { db } from "./db";
import { certifications } from "@shared/schema";
import { eq } from "drizzle-orm";

const MAX_WEBHOOK_ATTEMPTS = 3;
const WEBHOOK_TIMEOUT_MS = 10000; // 10 seconds

interface WebhookPayload {
  event: "proof.certified";
  proof_id: string;
  status: "certified";
  file_hash: string;
  filename: string;
  verify_url: string;
  certificate_url: string;
  proof_json_url: string;
  blockchain: {
    network: string;
    transaction_hash: string | null;
    explorer_url: string | null;
  };
  timestamp: string;
}

/**
 * Generate HMAC-SHA256 signature for webhook payload
 */
function signPayload(payload: string, secret: string): string {
  return crypto.createHmac("sha256", secret).update(payload).digest("hex");
}

/**
 * Deliver a webhook notification to the agent's URL.
 * Called after a certification is recorded on-chain.
 * Uses the API key hash as the HMAC signing secret.
 */
export async function deliverWebhook(
  certificationId: string,
  webhookUrl: string,
  baseUrl: string,
  signingSecret?: string
): Promise<boolean> {
  try {
    // Fetch the certification
    const [cert] = await db
      .select()
      .from(certifications)
      .where(eq(certifications.id, certificationId));

    if (!cert) {
      console.error(`[Webhook] Certification not found: ${certificationId}`);
      return false;
    }

    const payload: WebhookPayload = {
      event: "proof.certified",
      proof_id: cert.id,
      status: "certified",
      file_hash: cert.fileHash,
      filename: cert.fileName,
      verify_url: `${baseUrl}/proof/${cert.id}`,
      certificate_url: `${baseUrl}/api/certificates/${cert.id}.pdf`,
      proof_json_url: `${baseUrl}/proof/${cert.id}.json`,
      blockchain: {
        network: "MultiversX",
        transaction_hash: cert.transactionHash,
        explorer_url: cert.transactionUrl,
      },
      timestamp: cert.createdAt?.toISOString() || new Date().toISOString(),
    };

    const payloadStr = JSON.stringify(payload);
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const webhookSecret = signingSecret || process.env.SESSION_SECRET || "xproof-webhook-secret";
    const signature = signPayload(timestamp + "." + payloadStr, webhookSecret);

    await db
      .update(certifications)
      .set({
        webhookStatus: "pending",
        webhookAttempts: (cert.webhookAttempts || 0) + 1,
        webhookLastAttempt: new Date(),
      })
      .where(eq(certifications.id, certificationId));

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), WEBHOOK_TIMEOUT_MS);

    try {
      const response = await fetch(webhookUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-xProof-Signature": signature,
          "X-xProof-Timestamp": timestamp,
          "X-xProof-Event": "proof.certified",
          "X-xProof-Delivery": certificationId,
          "User-Agent": "xProof-Webhook/1.0",
        },
        body: payloadStr,
        signal: controller.signal,
      });

      clearTimeout(timeout);

      if (response.ok || (response.status >= 200 && response.status < 300)) {
        await db
          .update(certifications)
          .set({ webhookStatus: "delivered" })
          .where(eq(certifications.id, certificationId));
        
        console.log(`[Webhook] Delivered to ${webhookUrl} for cert ${certificationId} (status: ${response.status})`);
        return true;
      } else {
        console.warn(`[Webhook] Failed delivery to ${webhookUrl}: HTTP ${response.status}`);
        await markWebhookFailed(certificationId);
        return false;
      }
    } catch (fetchError: any) {
      clearTimeout(timeout);
      console.warn(`[Webhook] Network error to ${webhookUrl}: ${fetchError.message}`);
      await markWebhookFailed(certificationId);
      return false;
    }
  } catch (error) {
    console.error(`[Webhook] Error delivering for ${certificationId}:`, error);
    return false;
  }
}

async function markWebhookFailed(certificationId: string) {
  const [cert] = await db
    .select()
    .from(certifications)
    .where(eq(certifications.id, certificationId));
  
  if (!cert) return;
  
  const status = (cert.webhookAttempts || 0) >= MAX_WEBHOOK_ATTEMPTS ? "failed" : "pending";
  await db
    .update(certifications)
    .set({ webhookStatus: status })
    .where(eq(certifications.id, certificationId));
}

/**
 * Schedule webhook delivery with retry logic.
 * First attempt is immediate, retries are delayed with exponential backoff.
 */
export function scheduleWebhookDelivery(
  certificationId: string,
  webhookUrl: string,
  baseUrl: string,
  signingSecret?: string
): void {
  deliverWebhook(certificationId, webhookUrl, baseUrl, signingSecret).then(async (success) => {
    if (!success) {
      for (let attempt = 1; attempt < MAX_WEBHOOK_ATTEMPTS; attempt++) {
        const delay = Math.pow(2, attempt) * 5000; // 10s, 20s
        await new Promise((resolve) => setTimeout(resolve, delay));
        
        const [cert] = await db
          .select()
          .from(certifications)
          .where(eq(certifications.id, certificationId));
        
        if (cert?.webhookStatus === "delivered" || cert?.webhookStatus === "failed") {
          break;
        }
        
        if ((cert?.webhookAttempts || 0) >= MAX_WEBHOOK_ATTEMPTS) {
          await db.update(certifications)
            .set({ webhookStatus: "failed" })
            .where(eq(certifications.id, certificationId));
          break;
        }
        
        const retrySuccess = await deliverWebhook(certificationId, webhookUrl, baseUrl, signingSecret);
        if (retrySuccess) break;
      }
    }
  });
}

/**
 * Validate a webhook URL (basic security checks)
 */
export function isValidWebhookUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:") {
      return false;
    }
    const hostname = parsed.hostname.toLowerCase();
    if (
      hostname === "localhost" ||
      hostname === "127.0.0.1" ||
      hostname === "0.0.0.0" ||
      hostname.startsWith("10.") ||
      hostname.startsWith("192.168.") ||
      hostname.startsWith("172.") ||
      hostname === "169.254.169.254" ||
      hostname.endsWith(".internal")
    ) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}
