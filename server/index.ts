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
  "connect-src 'self' https://api.multiversx.com https://gateway.multiversx.com https://devnet-gateway.multiversx.com https://testnet-gateway.multiversx.com wss://relay.walletconnect.com https://*.walletconnect.com https://*.walletconnect.org https://explorer-api.walletconnect.com https://verify.walletconnect.com https://verify.walletconnect.org; " +
  "frame-src 'self' https://wallet.multiversx.com https://devnet-wallet.multiversx.com https://testnet-wallet.multiversx.com; " +
  "worker-src 'self' blob:;";

app.use((req, res, next) => {
  // Set CSP for all responses (will be overridden by static file handler in dev)
  res.setHeader('Content-Security-Policy', CSP_HEADER);
  next();
});

// Skip JSON parsing for webhooks to preserve raw body for signature verification
app.use((req, res, next) => {
  if (req.path.startsWith('/api/webhooks/') || req.path === '/api/stripe/webhook') {
    next();
  } else {
    express.json()(req, res, next);
  }
});

// Stripe webhook route - needs raw body for signature verification
app.post(
  '/api/stripe/webhook',
  express.raw({ type: 'application/json' }),
  async (req, res) => {
    const signature = req.headers['stripe-signature'];
    if (!signature) {
      return res.status(400).json({ error: 'Missing stripe-signature' });
    }
    try {
      const sig = Array.isArray(signature) ? signature[0] : signature;
      const { getStripeSync } = await import('./stripeClient');
      const sync = await getStripeSync();
      await sync.processWebhook(req.body as Buffer, sig);
      res.status(200).json({ received: true });
    } catch (error: any) {
      logger.withRequest(req).error('Stripe webhook error', { error: error.message });
      res.status(400).json({ error: 'Webhook processing error' });
    }
  }
);

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

  // Initialize Stripe (non-blocking - don't prevent server startup)
  (async () => {
    try {
      const { runMigrations } = await import('stripe-replit-sync');
      const { getStripeSync } = await import('./stripeClient');
      
      const databaseUrl = process.env.DATABASE_URL;
      if (!databaseUrl) {
        logger.warn('DATABASE_URL not set, skipping Stripe init');
        return;
      }

      logger.info('Initializing Stripe schema...');
      await runMigrations({ databaseUrl });
      
      const stripeSync = await getStripeSync();
      
      const replitDomains = process.env.REPLIT_DOMAINS?.split(',')[0];
      if (replitDomains) {
        const webhookBaseUrl = `https://${replitDomains}`;
        await stripeSync.findOrCreateManagedWebhook(`${webhookBaseUrl}/api/stripe/webhook`);
        logger.info('Stripe webhook configured');
      }
      
      stripeSync.syncBackfill()
        .then(() => logger.info('Stripe data synced'))
        .catch((err: any) => logger.error('Stripe sync error', { error: err.message }));
        
      logger.info('Stripe initialized');
    } catch (error: any) {
      logger.warn('Stripe initialization failed (non-critical)', { error: error.message });
    }
  })();

  // ALWAYS serve the app on the port specified in the environment variable PORT
  // Other ports are firewalled. Default to 5000 if not specified.
  // this serves both the API and the client.
  // It is the only port that is not firewalled.
  const port = parseInt(process.env.PORT || '5000', 10);
  server.listen({
    port,
    host: "0.0.0.0",
    reusePort: true,
  }, () => {
    log(`serving on port ${port}`);
    startTxQueueWorker();
  });

  setupGracefulShutdown(server);
})();
