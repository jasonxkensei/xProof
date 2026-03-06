import express, { type Request, Response, NextFunction } from "express";
import { registerRoutes } from "./routes";
import { setupVite, serveStatic, log } from "./vite";
import { prerenderMiddleware } from "./prerender";
import { 
  globalRateLimiter, 
  healthCheck, 
  requestTimeout, 
  setupGracefulShutdown, 
  setupProcessErrorHandlers 
} from "./reliability";
import { startTxQueueWorker } from "./txQueue";
import { computeTrustScoreByWallet } from "./trust";
import { pool, db } from "./db";
import { users } from "@shared/schema";
import { eq } from "drizzle-orm";
import { requestIdMiddleware, logger } from "./logger";

setupProcessErrorHandlers();

const app = express();

// Trust proxy for production (Replit uses reverse proxy)
app.set('trust proxy', 1);

// Custom CSP header to allow MultiversX SDK to work properly
// The SDK uses some dynamic code that requires 'unsafe-eval'
const CSP_HEADER = 
  "default-src 'self'; " +
  "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://fonts.googleapis.com; " +
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
  "font-src 'self' https://fonts.gstatic.com; " +
  "img-src 'self' data: blob: https:; " +
  "connect-src 'self' https://api.multiversx.com https://gateway.multiversx.com https://devnet-gateway.multiversx.com https://testnet-gateway.multiversx.com https://*.multiversx.com wss://relay.walletconnect.com https://*.walletconnect.com https://*.walletconnect.org https://explorer-api.walletconnect.com https://verify.walletconnect.com https://verify.walletconnect.org; " +
  "frame-src 'self' https://wallet.multiversx.com https://devnet-wallet.multiversx.com https://testnet-wallet.multiversx.com; " +
  "worker-src 'self' blob:;";

app.use((req, res, next) => {
  // Set CSP for all responses (will be overridden by static file handler in dev)
  res.setHeader('Content-Security-Policy', CSP_HEADER);
  next();
});

// Skip JSON parsing for webhooks to preserve raw body for signature verification
app.use((req, res, next) => {
  if (req.path.startsWith('/api/webhooks/')) {
    next();
  } else {
    express.json()(req, res, next);
  }
});

app.use(express.urlencoded({ extended: false }));

app.get("/health", healthCheck);
app.get("/api/health", healthCheck);

app.use("/api", globalRateLimiter);
app.use("/api", requestTimeout(30000));

app.use(requestIdMiddleware);

app.use((req, res, next) => {
  const start = Date.now();
  const path = req.path;
  let capturedJsonResponse: Record<string, any> | undefined = undefined;

  const originalResJson = res.json;
  res.json = function (bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };

  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path.startsWith("/api")) {
      let logLine = `${req.method} ${path} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }

      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "…";
      }

      log(logLine);
    }
  });

  next();
});

(async () => {
  const server = await registerRoutes(app);

  app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";

    logger.error(`Error ${status}: ${message}`, { stack: err.stack });

    if (!res.headersSent) {
      res.status(status).json({ message });
    }
  });

  // Pre-render for crawlers (before SPA catch-all)
  app.use(prerenderMiddleware());

  // importantly only setup vite in development and after
  // setting up all the other routes so the catch-all route
  // doesn't interfere with the other routes
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }

  // ALWAYS serve the app on the port specified in the environment variable PORT
  // Other ports are firewalled. Default to 5000 if not specified.
  // this serves both the API and the client.
  // It is the only port that is not firewalled.
  const port = parseInt(process.env.PORT || '5000', 10);
  async function runDailyMaintenance() {
    try {
      const publicAgents = await db
        .select({ walletAddress: users.walletAddress })
        .from(users)
        .where(eq(users.isPublicProfile, true));
      let snapshots = 0;
      const agentScores: Array<{ wallet: string; score: number; level: string; certTotal: number; activeAttestations: number }> = [];
      for (const row of publicAgents) {
        try {
          const trust = await computeTrustScoreByWallet(row.walletAddress);
          if (trust) {
            agentScores.push({ wallet: row.walletAddress, score: trust.score, level: trust.level, certTotal: trust.certTotal, activeAttestations: trust.activeAttestations ?? 0 });
          }
        } catch {}
      }
      agentScores.sort((a, b) => b.score - a.score);
      for (let i = 0; i < agentScores.length; i++) {
        const a = agentScores[i];
        try {
          await pool.query(
            `INSERT INTO trust_score_snapshots (wallet_address, score, level, cert_total, active_attestations, rank, snapshot_date)
             VALUES ($1, $2, $3, $4, $5, $6, CURRENT_DATE)
             ON CONFLICT (wallet_address, snapshot_date) DO UPDATE SET
               score = EXCLUDED.score,
               level = EXCLUDED.level,
               cert_total = EXCLUDED.cert_total,
               active_attestations = EXCLUDED.active_attestations,
               rank = EXCLUDED.rank`,
            [a.wallet, a.score, a.level, a.certTotal, a.activeAttestations, i + 1]
          );
          snapshots++;
        } catch {}
      }

      const expiring = await pool.query(
        `SELECT id, subject_wallet, domain, standard, expires_at
         FROM attestations
         WHERE status = 'active'
           AND expires_at IS NOT NULL
           AND expires_at BETWEEN NOW() AND NOW() + INTERVAL '30 days'
           AND expiry_notified_at IS NULL`
      );
      for (const att of expiring.rows) {
        logger.warn("Attestation expiring soon", {
          component: "maintenance",
          attestationId: att.id,
          domain: att.domain,
          expiresAt: att.expires_at,
        });
        await pool.query(
          `UPDATE attestations SET expiry_notified_at = NOW() WHERE id = $1`,
          [att.id]
        );
      }

      if (snapshots > 0 || expiring.rows.length > 0) {
        logger.info("Daily maintenance complete", {
          component: "maintenance",
          snapshots,
          expiryNotifications: expiring.rows.length,
        });
      }
    } catch (err: any) {
      logger.error("Daily maintenance error", { component: "maintenance", error: err.message });
    }
  }

  server.listen({
    port,
    host: "0.0.0.0",
    reusePort: true,
  }, () => {
    log(`serving on port ${port}`);
    startTxQueueWorker();
    runDailyMaintenance();
    setInterval(runDailyMaintenance, 24 * 60 * 60 * 1000);
  });

  setupGracefulShutdown(server);
})();
