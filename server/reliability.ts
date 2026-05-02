import { type Request, type Response, type NextFunction } from "express";
import rateLimit from "express-rate-limit";
import { pool } from "./db";
import { getMetrics, getLatencyPercentiles } from "./metrics";
import { isMX8004Configured } from "./mx8004";
import { isMultiversXConfigured } from "./blockchain";
import { execSync } from "child_process";
import { logger } from "./logger";
import { getClientIp } from "./routes/helpers";

// SECURITY: All IP-based rate limiters MUST key on getClientIp() rather than
// the express-rate-limit default (which uses `req.ip`). Under
// `app.set('trust proxy', 1)` (server/index.ts) Express's `req.ip` returns
// the LEFTMOST entry of `X-Forwarded-For` when the chain is single-hop, and
// that entry is fully attacker-controlled — letting a single source defeat
// any per-IP cap by rotating XFF values. getClientIp() returns the rightmost
// XFF entry instead, which Replit's edge proxy appends with the real client
// address. See server/routes/helpers.ts for the full rationale.
const ipKeyGenerator = (req: Request) => getClientIp(req);

export const globalRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: ipKeyGenerator,
  message: { error: "TOO_MANY_REQUESTS", message: "Too many requests, please try again later" },
  skip: (req) => {
    return req.path === "/api/acp/health";
  },
});

export const healthRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: ipKeyGenerator,
  message: { error: "TOO_MANY_REQUESTS", message: "Too many health check requests, please try again later" },
});

export const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: ipKeyGenerator,
  message: { error: "TOO_MANY_REQUESTS", message: "Too many authentication attempts, please try again later" },
});

export const paymentRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: ipKeyGenerator,
  message: { error: "TOO_MANY_REQUESTS", message: "Too many payment requests, please try again later" },
});

export const apiKeyCreationRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: ipKeyGenerator,
  message: { error: "TOO_MANY_REQUESTS", message: "Too many API key operations, please try again later" },
});

export const attestationIssuanceRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: any) => (req.walletAddress as string) ?? "unknown",
  skip: (req: any) => !req.walletAddress,
  message: { error: "TOO_MANY_REQUESTS", message: "Attestation rate limit exceeded: max 20 per hour per issuer" },
});

export const publicReadRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: ipKeyGenerator,
  message: { error: "TOO_MANY_REQUESTS", message: "Too many requests, please try again later" },
});

export const publicSearchRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: ipKeyGenerator,
  message: { error: "TOO_MANY_REQUESTS", message: "Too many search requests, please try again later" },
});

export const publicCompareRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: ipKeyGenerator,
  message: { error: "TOO_MANY_REQUESTS", message: "Too many comparison requests, please try again later" },
});

let commitSha = "unknown";
try {
  commitSha = execSync("git rev-parse --short HEAD 2>/dev/null").toString().trim() || "unknown";
} catch {}

const deployTimestamp = new Date().toISOString();

const HEALTH_CACHE_TTL_MS = 10_000;
let healthCache: { body: object; status: number; cachedAt: number } | null = null;

export async function healthCheck(_req: Request, res: Response) {
  if (healthCache && Date.now() - healthCache.cachedAt < HEALTH_CACHE_TTL_MS) {
    return res.status(healthCache.status).json(healthCache.body);
  }

  const checks: Record<string, { status: string; latency_ms?: number; error?: string; details?: any }> = {};

  const dbStart = Date.now();
  try {
    await pool.query("SELECT 1");
    checks.database = { status: "ok", latency_ms: Date.now() - dbStart };
  } catch (error) {
    checks.database = { 
      status: "down", 
      latency_ms: Date.now() - dbStart,
      error: error instanceof Error ? error.message : "Connection failed" 
    };
  }

  const gatewayUrl = process.env.MULTIVERSX_GATEWAY_URL || "https://gateway.multiversx.com";
  const gwStart = Date.now();
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    const gwResponse = await fetch(`${gatewayUrl}/network/config`, { signal: controller.signal });
    clearTimeout(timeout);
    checks.blockchain_gateway = {
      status: gwResponse.ok ? "ok" : "degraded",
      latency_ms: Date.now() - gwStart,
      details: { url: gatewayUrl, configured: isMultiversXConfigured() },
    };
  } catch (error) {
    checks.blockchain_gateway = {
      status: "down",
      latency_ms: Date.now() - gwStart,
      error: error instanceof Error ? error.message : "Unreachable",
      details: { url: gatewayUrl, configured: isMultiversXConfigured() },
    };
  }

  checks.mx8004 = {
    status: isMX8004Configured() ? "ok" : "not_configured",
    details: { configured: isMX8004Configured() },
  };

  const metrics = getMetrics();

  const statuses = Object.values(checks).map(c => c.status);
  const overallStatus = statuses.includes("down") ? "degraded" : statuses.every(s => s === "ok" || s === "not_configured") ? "healthy" : "degraded";

  const latencyPercentiles = getLatencyPercentiles();
  const failureRate = metrics.transactions.total_failed > 0 
    ? Math.round((metrics.transactions.total_failed / (metrics.transactions.total_success + metrics.transactions.total_failed)) * 10000) / 100
    : 0;

  const httpStatus = overallStatus === "healthy" ? 200 : 503;
  const body = {
    status: overallStatus,
    service: "xproof",
    version: "1.0.0",
    commit: commitSha,
    deployed_at: deployTimestamp,
    uptime_seconds: metrics.uptime_seconds,
    timestamp: new Date().toISOString(),
    checks,
    blockchain_latency: {
      avg_ms: metrics.transactions.avg_latency_ms,
      p95_ms: latencyPercentiles.p95_ms,
      queue_depth: metrics.mx8004.queue_size,
      failure_rate: failureRate,
    },
    transactions: metrics.transactions,
    mx8004_queue: metrics.mx8004,
  };

  healthCache = { body, status: httpStatus, cachedAt: Date.now() };

  res.status(httpStatus).json(body);
}

export function requestTimeout(timeoutMs: number = 30000) {
  return (req: Request, res: Response, next: NextFunction) => {
    const timer = setTimeout(() => {
      if (!res.headersSent) {
        res.status(408).json({ error: "REQUEST_TIMEOUT", message: "Request timed out" });
      }
    }, timeoutMs);

    res.on("finish", () => clearTimeout(timer));
    res.on("close", () => clearTimeout(timer));

    next();
  };
}

export function setupGracefulShutdown(server: import("http").Server) {
  let isShuttingDown = false;

  const shutdown = (signal: string) => {
    if (isShuttingDown) return;
    isShuttingDown = true;
    logger.info("Graceful shutdown initiated", { component: "reliability", signal });

    server.close(() => {
      logger.info("HTTP server closed", { component: "reliability" });
      pool.end().then(() => {
        logger.info("Database pool closed", { component: "reliability" });
        process.exit(0);
      }).catch(() => {
        process.exit(1);
      });
    });

    setTimeout(() => {
      logger.error("Graceful shutdown timed out, forcing exit", { component: "reliability" });
      process.exit(1);
    }, 10000);
  };

  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}

export function setupProcessErrorHandlers() {
  process.on("uncaughtException", (error) => {
    logger.error("Uncaught exception", { component: "reliability", error: error instanceof Error ? error.message : String(error) });
  });

  process.on("unhandledRejection", (reason) => {
    logger.error("Unhandled rejection", { component: "reliability", reason: reason instanceof Error ? reason.message : String(reason) });
  });
}
