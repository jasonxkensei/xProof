import { logger } from "./logger";
import { db } from "./db";
import { txQueue } from "@shared/schema";
import { eq, and, gte, count, sql } from "drizzle-orm";

interface AlertConfig {
  failureThreshold: number;
  cooldownMinutes: number;
  windowMinutes: number;
  webhookUrl: string | null;
}

type ErrorCategory = "nonce" | "gateway_timeout" | "contract_revert" | "unknown";

interface AlertPayload {
  alert: "tx_queue_failure_spike";
  severity: "warning" | "critical";
  timestamp: string;
  window_minutes: number;
  total_failures: number;
  threshold: number;
  breakdown: Record<ErrorCategory, number>;
  recent_errors: Array<{ jobId: string; jobType: string; error: string; category: ErrorCategory }>;
}

const config: AlertConfig = {
  failureThreshold: parseInt(process.env.TX_ALERT_THRESHOLD || "5", 10),
  cooldownMinutes: parseInt(process.env.TX_ALERT_COOLDOWN_MINUTES || "30", 10),
  windowMinutes: parseInt(process.env.TX_ALERT_WINDOW_MINUTES || "15", 10),
  webhookUrl: process.env.TX_ALERT_WEBHOOK_URL || null,
};

let lastAlertSentAt: number = 0;

function categorizeError(errorMessage: string): ErrorCategory {
  const lower = errorMessage.toLowerCase();
  if (lower.includes("nonce") || lower.includes("invalid nonce") || lower.includes("nonce too low") || lower.includes("nonce mismatch")) {
    return "nonce";
  }
  if (lower.includes("timeout") || lower.includes("gateway") || lower.includes("econnrefused") || lower.includes("enotfound") || lower.includes("502") || lower.includes("503") || lower.includes("504")) {
    return "gateway_timeout";
  }
  if (lower.includes("revert") || lower.includes("execution failed") || lower.includes("contract error") || lower.includes("out of gas") || lower.includes("insufficient")) {
    return "contract_revert";
  }
  return "unknown";
}

export async function checkAndAlert(): Promise<void> {
  if (!config.webhookUrl) return;

  const now = Date.now();
  const cooldownMs = config.cooldownMinutes * 60 * 1000;
  if (now - lastAlertSentAt < cooldownMs) return;

  try {
    const windowStart = new Date(now - config.windowMinutes * 60 * 1000);

    const failedTasks = await db
      .select({
        jobId: txQueue.jobId,
        jobType: txQueue.jobType,
        lastError: txQueue.lastError,
      })
      .from(txQueue)
      .where(
        and(
          eq(txQueue.status, "failed"),
          gte(txQueue.completedAt, windowStart)
        )
      );

    // Also count tasks that failed recently but got retried (status pending with errors)
    const recentRetries = await db
      .select({
        jobId: txQueue.jobId,
        jobType: txQueue.jobType,
        lastError: txQueue.lastError,
      })
      .from(txQueue)
      .where(
        and(
          eq(txQueue.status, "pending"),
          gte(txQueue.nextRetryAt, windowStart),
          sql`last_error IS NOT NULL`
        )
      );

    const allFailures = [...failedTasks, ...recentRetries];
    const totalFailures = allFailures.length;

    if (totalFailures < config.failureThreshold) return;

    const breakdown: Record<ErrorCategory, number> = {
      nonce: 0,
      gateway_timeout: 0,
      contract_revert: 0,
      unknown: 0,
    };

    const recentErrors: AlertPayload["recent_errors"] = [];

    for (const task of allFailures) {
      const category = categorizeError(task.lastError || "");
      breakdown[category]++;
      if (recentErrors.length < 5) {
        recentErrors.push({
          jobId: task.jobId,
          jobType: task.jobType,
          error: (task.lastError || "").slice(0, 200),
          category,
        });
      }
    }

    const severity: "warning" | "critical" = totalFailures >= config.failureThreshold * 2 ? "critical" : "warning";

    const payload: AlertPayload = {
      alert: "tx_queue_failure_spike",
      severity,
      timestamp: new Date().toISOString(),
      window_minutes: config.windowMinutes,
      total_failures: totalFailures,
      threshold: config.failureThreshold,
      breakdown,
      recent_errors: recentErrors,
    };

    await sendAlertWebhook(payload);
    lastAlertSentAt = now;

    logger.warn("TX queue alert sent", {
      component: "tx-alerts",
      severity,
      totalFailures,
      breakdown,
    });
  } catch (err: any) {
    logger.error("Failed to check/send tx queue alert", {
      component: "tx-alerts",
      error: err.message,
    });
  }
}

async function sendAlertWebhook(payload: AlertPayload): Promise<void> {
  if (!config.webhookUrl) return;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);

  try {
    const response = await fetch(config.webhookUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-xProof-Alert": "tx_queue_failure_spike",
        "User-Agent": "xProof-Alert/1.0",
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });

    clearTimeout(timeout);

    if (!response.ok) {
      logger.error("Alert webhook delivery failed", {
        component: "tx-alerts",
        status: response.status,
        url: config.webhookUrl,
      });
    }
  } catch (err: any) {
    clearTimeout(timeout);
    logger.error("Alert webhook network error", {
      component: "tx-alerts",
      error: err.message,
    });
  }
}

export function getAlertConfig(): { threshold: number; cooldownMinutes: number; windowMinutes: number; configured: boolean; lastAlertAt: string | null } {
  return {
    threshold: config.failureThreshold,
    cooldownMinutes: config.cooldownMinutes,
    windowMinutes: config.windowMinutes,
    configured: !!config.webhookUrl,
    lastAlertAt: lastAlertSentAt > 0 ? new Date(lastAlertSentAt).toISOString() : null,
  };
}
