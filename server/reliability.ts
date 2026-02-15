import { type Request, type Response, type NextFunction } from "express";
import rateLimit from "express-rate-limit";
import { pool } from "./db";
import { getMetrics } from "./metrics";
import { isMX8004Configured } from "./mx8004";
import { isMultiversXConfigured } from "./blockchain";
import { execSync } from "child_process";

export const globalRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "TOO_MANY_REQUESTS", message: "Too many requests, please try again later" },
  skip: (req) => {
    return req.path === "/health" || req.path === "/api/health" || req.path === "/api/acp/health";
  },
});

export const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "TOO_MANY_REQUESTS", message: "Too many authentication attempts, please try again later" },
});

export const paymentRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "TOO_MANY_REQUESTS", message: "Too many payment requests, please try again later" },
});

export const apiKeyCreationRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "TOO_MANY_REQUESTS", message: "Too many API key operations, please try again later" },
});

let commitSha = "unknown";
try {
  commitSha = execSync("git rev-parse --short HEAD 2>/dev/null").toString().trim() || "unknown";
} catch {}

const deployTimestamp = new Date().toISOString();

export async function healthCheck(_req: Request, res: Response) {
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

  res.status(overallStatus === "healthy" ? 200 : 503).json({
    status: overallStatus,
    service: "xproof",
    version: "1.0.0",
    commit: commitSha,
    deployed_at: deployTimestamp,
    uptime_seconds: metrics.uptime_seconds,
    timestamp: new Date().toISOString(),
    checks,
    transactions: metrics.transactions,
    mx8004_queue: metrics.mx8004,
  });
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
    console.log(`[xproof] ${signal} received, shutting down gracefully...`);

    server.close(() => {
      console.log("[xproof] HTTP server closed");
      pool.end().then(() => {
        console.log("[xproof] Database pool closed");
        process.exit(0);
      }).catch(() => {
        process.exit(1);
      });
    });

    setTimeout(() => {
      console.error("[xproof] Graceful shutdown timed out, forcing exit");
      process.exit(1);
    }, 10000);
  };

  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}

export function setupProcessErrorHandlers() {
  process.on("uncaughtException", (error) => {
    console.error("[xproof] Uncaught exception:", error);
  });

  process.on("unhandledRejection", (reason) => {
    console.error("[xproof] Unhandled rejection:", reason);
  });
}
