const startTime = Date.now();

interface TransactionRecord {
  timestamp: number;
  success: boolean;
  latencyMs: number;
  type: "certification" | "mx8004";
}

const recentTransactions: TransactionRecord[] = [];
const MAX_RECORDS = 1000;

let totalCertifications = 0;
let totalFailed = 0;
let totalRetries = 0;
let mx8004QueueSize = 0;

export function recordTransaction(success: boolean, latencyMs: number, type: "certification" | "mx8004" = "certification") {
  recentTransactions.push({ timestamp: Date.now(), success, latencyMs, type });
  if (recentTransactions.length > MAX_RECORDS) {
    recentTransactions.shift();
  }
  if (success) {
    totalCertifications++;
  } else {
    totalFailed++;
  }
}

export function recordRetry() {
  totalRetries++;
}

export function setMx8004QueueSize(size: number) {
  mx8004QueueSize = size;
}

export function getMetrics() {
  const now = Date.now();
  const certTxs = recentTransactions.filter(t => t.type === "certification");
  const successTxs = certTxs.filter(t => t.success);
  const failedTxs = certTxs.filter(t => !t.success);

  const lastSuccess = successTxs.length > 0 ? successTxs[successTxs.length - 1] : null;
  const lastFailed = failedTxs.length > 0 ? failedTxs[failedTxs.length - 1] : null;

  const avgLatency = successTxs.length > 0
    ? Math.round(successTxs.reduce((sum, t) => sum + t.latencyMs, 0) / successTxs.length)
    : null;

  return {
    uptime_seconds: Math.floor((now - startTime) / 1000),
    start_time: new Date(startTime).toISOString(),
    transactions: {
      total_recorded: certTxs.length,
      total_success: totalCertifications,
      total_failed: totalFailed,
      total_retries: totalRetries,
      avg_latency_ms: avgLatency,
      last_success_at: lastSuccess ? new Date(lastSuccess.timestamp).toISOString() : null,
      last_failed_at: lastFailed ? new Date(lastFailed.timestamp).toISOString() : null,
    },
    mx8004: {
      queue_size: mx8004QueueSize,
    },
  };
}

export function getUptimeSeconds(): number {
  return Math.floor((Date.now() - startTime) / 1000);
}
