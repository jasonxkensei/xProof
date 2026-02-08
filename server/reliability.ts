import { type Request, type Response, type NextFunction } from "express";
import rateLimit from "express-rate-limit";
import { pool } from "./db";

export const globalRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "TOO_MANY_REQUESTS", message: "Too many requests, please try again later" },
  keyGenerator: (req) => req.ip || "unknown",
  skip: (req) => {
    return req.path === "/health" || req.path === "/api/acp/health";
  },
});

export const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "TOO_MANY_REQUESTS", message: "Too many authentication attempts, please try again later" },
  keyGenerator: (req) => req.ip || "unknown",
});

export const paymentRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "TOO_MANY_REQUESTS", message: "Too many payment requests, please try again later" },
  keyGenerator: (req) => req.ip || "unknown",
});

let serverStartTime = Date.now();

export async function healthCheck(_req: Request, res: Response) {
  const checks: Record<string, { status: string; latency?: number; error?: string }> = {};

  const dbStart = Date.now();
  try {
    await pool.query("SELECT 1");
    checks.database = { status: "healthy", latency: Date.now() - dbStart };
  } catch (error) {
    checks.database = { 
      status: "unhealthy", 
      latency: Date.now() - dbStart,
      error: error instanceof Error ? error.message : "Connection failed" 
    };
  }

  const allHealthy = Object.values(checks).every(c => c.status === "healthy");
  const uptimeSeconds = Math.floor((Date.now() - serverStartTime) / 1000);

  res.status(allHealthy ? 200 : 503).json({
    status: allHealthy ? "healthy" : "degraded",
    service: "xproof",
    version: "1.0.0",
    uptime: uptimeSeconds,
    timestamp: new Date().toISOString(),
    checks,
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
