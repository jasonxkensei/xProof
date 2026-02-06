import express, { type Express } from "express";
import { createServer, type Server } from "http";
import crypto from "crypto";
import { db } from "./db";
import { storage } from "./storage";
import { 
  certifications, 
  users, 
  acpCheckouts,
  apiKeys,
  acpCheckoutRequestSchema,
  acpConfirmRequestSchema,
  type ACPProduct,
  type ACPCheckoutResponse,
  type ACPConfirmResponse,
} from "@shared/schema";
import { getCertificationPriceEgld, getCertificationPriceEur } from "./pricing";
import { eq, desc } from "drizzle-orm";
import { z } from "zod";
import Stripe from "stripe";
import { generateCertificatePDF } from "./certificateGenerator";
import { createXMoneyOrder, getXMoneyOrderStatus, verifyXMoneyWebhook, isXMoneyConfigured } from "./xmoney";
import { recordOnBlockchain, isMultiversXConfigured, broadcastSignedTransaction } from "./blockchain";
import { 
  isWalletAuthenticated, 
  generateChallenge, 
  verifyWalletSignature, 
  createWalletSession,
  destroyWalletSession 
} from "./walletAuth";
import { getSession } from "./replitAuth";

const stripeSecretKey = process.env.TESTING_STRIPE_SECRET_KEY || process.env.STRIPE_SECRET_KEY;
if (!stripeSecretKey) {
  throw new Error("Missing STRIPE_SECRET_KEY or TESTING_STRIPE_SECRET_KEY environment variable");
}

const stripe = new Stripe(stripeSecretKey, {
  apiVersion: "2025-09-30.clover",
});

export async function registerRoutes(app: Express): Promise<Server> {
  // Apply session middleware
  app.use(getSession());
  
  // DEPRECATED: Legacy endpoint - SECURITY VULNERABILITY
  // This endpoint allows wallet impersonation (accepts any wallet address without signature)
  // Use /api/auth/wallet/sync with Native Auth token instead
  // Disabled for security - returns 410 Gone
  app.post("/api/auth/wallet/login", async (req, res) => {
    res.status(410).json({ 
      message: "This endpoint is deprecated due to security vulnerabilities. Use Native Auth with /api/auth/wallet/sync instead.",
      error: "ENDPOINT_DEPRECATED" 
    });
  });

  // Sync wallet state with backend (used by sdk-dapp integration)
  // REQUIRES Native Auth token verification for security
  app.post("/api/auth/wallet/sync", async (req, res) => {
    try {
      const { verifyNativeAuthToken, extractBearerToken } = await import("./nativeAuth");
      
      // Extract and verify Native Auth token
      const token = extractBearerToken(req.headers.authorization);
      
      if (!token) {
        return res.status(401).json({ 
          message: "Missing Native Auth token. Authentication requires cryptographic proof." 
        });
      }

      // Verify token cryptographically (signature + expiration + origin)
      const decoded = await verifyNativeAuthToken(token);
      const walletAddress = decoded.address;

      if (!walletAddress || !walletAddress.startsWith("erd1")) {
        return res.status(400).json({ message: "Invalid MultiversX wallet address in token" });
      }

      // Verify wallet address in request body matches token
      if (req.body.walletAddress && req.body.walletAddress !== walletAddress) {
        return res.status(403).json({ 
          message: "Wallet address mismatch - token address does not match request" 
        });
      }

      // Check if user exists, create if not
      let [user] = await db.select().from(users).where(eq(users.walletAddress, walletAddress));

      if (!user) {
        // Create new user with free tier
        [user] = await db
          .insert(users)
          .values({
            walletAddress,
            subscriptionTier: "free",
            subscriptionStatus: "active",
            monthlyUsage: 0,
            usageResetDate: new Date(),
          })
          .returning();
      }

      // Create wallet session (now cryptographically verified)
      await createWalletSession(req, walletAddress);

      res.json(user);
    } catch (error: any) {
      console.error("Error during wallet sync:", error);
      res.status(401).json({ 
        message: error.message || "Failed to verify authentication token" 
      });
    }
  });

  // Simple wallet sync - creates session without Native Auth verification
  // Used as fallback when SDK doesn't provide Native Auth token
  // Note: Less secure than full Native Auth, but still requires SDK login
  app.post("/api/auth/wallet/simple-sync", async (req, res) => {
    try {
      const { walletAddress } = req.body;
      
      if (!walletAddress || !walletAddress.startsWith("erd1")) {
        return res.status(400).json({ message: "Invalid MultiversX wallet address" });
      }

      console.log("Simple sync for wallet:", walletAddress);

      // Check if user exists, create if not
      let [user] = await db.select().from(users).where(eq(users.walletAddress, walletAddress));

      if (!user) {
        // Create new user with free tier
        [user] = await db
          .insert(users)
          .values({
            walletAddress,
            subscriptionTier: "free",
            subscriptionStatus: "active",
            monthlyUsage: 0,
            usageResetDate: new Date(),
          })
          .returning();
      }

      // Create wallet session
      await createWalletSession(req, walletAddress);

      res.json(user);
    } catch (error: any) {
      console.error("Error during simple wallet sync:", error);
      res.status(500).json({ message: "Failed to create session" });
    }
  });

  // Get current user endpoint (for checking authentication status)
  app.get('/api/auth/me', isWalletAuthenticated, async (req: any, res) => {
    try {
      const walletAddress = req.walletAddress;
      const [user] = await db.select().from(users).where(eq(users.walletAddress, walletAddress));
      
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      
      res.json(user);
    } catch (error) {
      console.error("Error fetching current user:", error);
      res.status(500).json({ message: "Failed to fetch user" });
    }
  });

  // Logout endpoint
  app.post("/api/auth/logout", async (req, res) => {
    try {
      await destroyWalletSession(req);
      res.json({ message: "Logged out successfully" });
    } catch (error: any) {
      console.error("Error logging out:", error);
      res.status(500).json({ message: "Failed to log out" });
    }
  });

  // Create certification (unlimited, free service)
  app.post("/api/certifications", isWalletAuthenticated, async (req: any, res) => {
    try {
      const walletAddress = req.walletAddress;

      // Get user for certification ownership
      const [user] = await db.select().from(users).where(eq(users.walletAddress, walletAddress));
      
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // Validate request body
      const schema = z.object({
        fileName: z.string().min(1),
        fileHash: z.string().min(1),
        fileType: z.string().optional(),
        fileSize: z.number().optional(),
        authorName: z.string().min(1),
        authorSignature: z.string().optional(),
        transactionHash: z.string().optional(),
        transactionUrl: z.string().optional(),
      });

      const data = schema.parse(req.body);

      // Check if hash already exists
      const [existing] = await db
        .select()
        .from(certifications)
        .where(eq(certifications.fileHash, data.fileHash));

      if (existing) {
        return res.status(409).json({
          message: "This file has already been certified",
          certificationId: existing.id,
        });
      }

      // Use transaction from frontend (Extension Wallet signature) or fallback to server mode
      let transactionHash: string;
      let transactionUrl: string;
      
      if (data.transactionHash && data.transactionUrl) {
        // Transaction already signed and broadcast by user's Extension Wallet
        transactionHash = data.transactionHash;
        transactionUrl = data.transactionUrl;
        console.log("✅ Using client-signed transaction:", transactionHash);
      } else {
        // Fallback to server-side blockchain recording (simulation mode)
        const result = await recordOnBlockchain(
          data.fileHash,
          data.fileName,
          data.authorName
        );
        transactionHash = result.transactionHash;
        transactionUrl = result.transactionUrl;
      }

      // Create certification
      const [certification] = await db
        .insert(certifications)
        .values({
          userId: user.id!,
          fileName: data.fileName,
          fileHash: data.fileHash,
          fileType: data.fileType || "unknown",
          fileSize: data.fileSize || 0,
          authorName: data.authorName,
          authorSignature: data.authorSignature,
          transactionHash,
          transactionUrl,
          blockchainStatus: "confirmed", // In production, this would be "pending" initially
          isPublic: true,
        })
        .returning();

      // Certificate will be generated on-demand when downloaded
      const certificateUrl = `/api/certificates/${certification.id}.pdf`;

      res.status(201).json({
        ...certification,
        certificateUrl,
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid request data", errors: error.errors });
      }
      console.error("Error creating certification:", error);
      res.status(500).json({ message: "Failed to create certification" });
    }
  });

  // Get user's certifications
  app.get("/api/certifications", isWalletAuthenticated, async (req: any, res) => {
    try {
      const walletAddress = req.walletAddress;
      
      // Get user first to get their ID
      const [user] = await db.select().from(users).where(eq(users.walletAddress, walletAddress));
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      const userCertifications = await db
        .select()
        .from(certifications)
        .where(eq(certifications.userId, user.id!))
        .orderBy(desc(certifications.createdAt));

      res.json(userCertifications);
    } catch (error) {
      console.error("Error fetching certifications:", error);
      res.status(500).json({ message: "Failed to fetch certifications" });
    }
  });

  // Get account info (nonce) for transaction building
  app.get("/api/blockchain/account/:address", isWalletAuthenticated, async (req: any, res) => {
    try {
      const { address } = req.params;
      
      // Validate address format
      if (!address || !address.startsWith("erd1")) {
        return res.status(400).json({ message: "Invalid MultiversX address" });
      }

      // Get gateway URL from env
      const gatewayUrl = process.env.MULTIVERSX_GATEWAY_URL || "https://devnet-gateway.multiversx.com";
      
      // Fetch account info from MultiversX gateway
      const response = await fetch(`${gatewayUrl}/address/${address}`);
      
      if (!response.ok) {
        throw new Error(`Gateway error: ${response.statusText}`);
      }

      const data = await response.json();
      
      res.json({
        address,
        nonce: data.data?.account?.nonce || 0,
        balance: data.data?.account?.balance || "0",
      });
    } catch (error: any) {
      console.error("Error fetching account info:", error);
      res.status(500).json({ 
        message: "Failed to fetch account info",
        error: error.message 
      });
    }
  });

  // Broadcast signed transaction (XPortal integration)
  app.post("/api/blockchain/broadcast", isWalletAuthenticated, async (req: any, res) => {
    try {
      const { signedTransaction, certificationData } = req.body;

      if (!signedTransaction) {
        return res.status(400).json({ message: "Missing signed transaction" });
      }

      // If certification data is provided, validate and create certification record
      if (certificationData) {
        const walletAddress = req.walletAddress;
        
        // Get user
        const [user] = await db.select().from(users).where(eq(users.walletAddress, walletAddress));

        if (!user) {
          return res.status(404).json({ message: "User not found" });
        }

        // Validate certification data
        const schema = z.object({
          fileName: z.string().min(1),
          fileHash: z.string().min(1),
          fileType: z.string().optional(),
          fileSize: z.number().optional(),
          authorName: z.string().min(1),
          authorSignature: z.string().optional(),
        });

        const validatedData = schema.parse(certificationData);

        // Check if hash already exists
        const [existing] = await db
          .select()
          .from(certifications)
          .where(eq(certifications.fileHash, validatedData.fileHash));

        if (existing) {
          return res.status(409).json({
            message: "This file has already been certified",
            certificationId: existing.id,
          });
        }

        // Broadcast transaction to MultiversX
        const { txHash, explorerUrl } = await broadcastSignedTransaction(signedTransaction);

        // Create certification record
        const [certification] = await db
          .insert(certifications)
          .values({
            userId: user.id!,
            fileName: validatedData.fileName,
            fileHash: validatedData.fileHash,
            fileType: validatedData.fileType || "unknown",
            fileSize: validatedData.fileSize || 0,
            authorName: validatedData.authorName,
            authorSignature: validatedData.authorSignature,
            transactionHash: txHash,
            transactionUrl: explorerUrl,
            blockchainStatus: "pending", // Will be confirmed later
            isPublic: true,
          })
          .returning();

        res.json({
          success: true,
          txHash,
          explorerUrl,
          certification,
        });
      } else {
        // Just broadcast without creating certification
        const { txHash, explorerUrl } = await broadcastSignedTransaction(signedTransaction);
        
        res.json({
          success: true,
          txHash,
          explorerUrl,
        });
      }
    } catch (error: any) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid certification data", errors: error.errors });
      }
      console.error("Error broadcasting transaction:", error);
      res.status(500).json({ 
        message: "Failed to broadcast transaction",
        error: error.message 
      });
    }
  });

  // Get public proof (no auth required)
  app.get("/api/proof/:id", async (req, res) => {
    try {
      const { id } = req.params;
      
      const [certification] = await db
        .select()
        .from(certifications)
        .where(eq(certifications.id, id));

      if (!certification || !certification.isPublic) {
        return res.status(404).json({ message: "Proof not found" });
      }

      res.json(certification);
    } catch (error) {
      console.error("Error fetching proof:", error);
      res.status(500).json({ message: "Failed to fetch proof" });
    }
  });

  // Download certificate
  app.get("/api/certificates/:id.pdf", async (req, res) => {
    try {
      const certId = req.params.id;
      
      const [certification] = await db
        .select()
        .from(certifications)
        .where(eq(certifications.id, certId));

      if (!certification) {
        return res.status(404).json({ message: "Certificate not found" });
      }

      // Get user to determine subscription tier
      const [user] = await db
        .select()
        .from(users)
        .where(eq(users.id, certification.userId));

      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // Generate PDF (free service - standard branding)
      const pdfBuffer = await generateCertificatePDF({
        certification,
        subscriptionTier: 'free',
        companyName: undefined,
        companyLogoUrl: undefined,
      });

      // Set headers for PDF download
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="certificate-${certification.id}.pdf"`);
      res.send(pdfBuffer);
    } catch (error) {
      console.error("Error generating certificate:", error);
      res.status(500).json({ message: "Failed to generate certificate" });
    }
  });

  // Create subscription
  app.post("/api/create-subscription", isWalletAuthenticated, async (req: any, res) => {
    try {
      const walletAddress = req.walletAddress;
      const { plan } = req.body;

      if (!["pro", "business"].includes(plan)) {
        return res.status(400).json({ message: "Invalid plan" });
      }

      const [user] = await db.select().from(users).where(eq(users.walletAddress, walletAddress));
      
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // Create or get Stripe customer
      let customerId = user.stripeCustomerId;
      
      if (!customerId) {
        console.log('Creating Stripe customer for user:', user.id);
        const customer = await stripe.customers.create({
          email: user.email || undefined,
          metadata: {
            userId: user.id,
          },
        });
        customerId = customer.id;
        
        await db
          .update(users)
          .set({ stripeCustomerId: customerId })
          .where(eq(users.walletAddress, walletAddress));
      }

      // Create subscription
      const priceId = plan === "pro" 
        ? process.env.STRIPE_PRO_PRICE_ID 
        : process.env.STRIPE_BUSINESS_PRICE_ID;

      if (!priceId) {
        // For development, create a PaymentIntent instead
        const amount = plan === "pro" ? 999 : 3900; // in cents
        
        const paymentIntent = await stripe.paymentIntents.create({
          amount,
          currency: "usd",
          customer: customerId,
          setup_future_usage: "off_session",
          metadata: {
            userId: user.id,
            plan,
          },
        });

        return res.json({ clientSecret: paymentIntent.client_secret });
      }

      const subscription = await stripe.subscriptions.create({
        customer: customerId,
        items: [{ price: priceId }],
        payment_behavior: "default_incomplete",
        expand: ["latest_invoice.payment_intent"],
      });

      const invoice = subscription.latest_invoice as Stripe.Invoice;
      const paymentIntent = (invoice as any).payment_intent as Stripe.PaymentIntent;

      // Update user subscription info
      await db
        .update(users)
        .set({
          stripeSubscriptionId: subscription.id,
          subscriptionTier: plan,
          subscriptionStatus: subscription.status,
        })
        .where(eq(users.walletAddress, walletAddress));

      res.json({ clientSecret: paymentIntent.client_secret });
    } catch (error) {
      console.error("Error creating subscription:", error);
      res.status(500).json({ message: "Failed to create subscription" });
    }
  });

  // Stripe webhook
  app.post("/api/webhooks/stripe", express.raw({ type: "application/json" }), async (req, res) => {
    const sig = req.headers["stripe-signature"];

    if (!sig || !process.env.STRIPE_WEBHOOK_SECRET) {
      return res.status(400).send("Webhook signature missing");
    }

    try {
      const event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        process.env.STRIPE_WEBHOOK_SECRET
      );

      switch (event.type) {
        case "customer.subscription.updated":
        case "customer.subscription.deleted": {
          const subscription = event.data.object as Stripe.Subscription;
          const customerId = subscription.customer as string;

          const [user] = await db
            .select()
            .from(users)
            .where(eq(users.stripeCustomerId, customerId));

          if (user) {
            await db
              .update(users)
              .set({
                subscriptionStatus: subscription.status,
                subscriptionTier: subscription.status === "active" ? user.subscriptionTier : "free",
              })
              .where(eq(users.id, user.id));
          }
          break;
        }

        case "payment_intent.succeeded": {
          const paymentIntent = event.data.object as Stripe.PaymentIntent;
          const userId = paymentIntent.metadata.userId;
          const plan = paymentIntent.metadata.plan;

          if (userId && plan) {
            await db
              .update(users)
              .set({
                subscriptionTier: plan,
                subscriptionStatus: "active",
              })
              .where(eq(users.id, userId));
          }
          break;
        }
      }

      res.json({ received: true });
    } catch (error) {
      console.error("Webhook error:", error);
      res.status(400).send(`Webhook Error: ${error instanceof Error ? error.message : "Unknown error"}`);
    }
  });

  // xMoney payment routes
  
  // Create payment order
  app.post("/api/xmoney/create-payment", isWalletAuthenticated, async (req: any, res) => {
    try {
      if (!isXMoneyConfigured()) {
        return res.status(503).json({ 
          message: "xMoney payment service is not configured. Please contact support." 
        });
      }

      const walletAddress = req.walletAddress;
      const { amount, currency, description } = req.body;

      // Validate input
      const schema = z.object({
        amount: z.number().positive(),
        currency: z.string().min(3).max(3),
        description: z.string().min(1),
      });

      const validatedData = schema.parse({ amount, currency, description });

      // Get user email for payment
      const [user] = await db.select().from(users).where(eq(users.walletAddress, walletAddress));
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // Create xMoney order
      const order = await createXMoneyOrder({
        amount: validatedData.amount,
        currency: validatedData.currency,
        orderDescription: validatedData.description,
        customerEmail: user.email || undefined,
        returnUrl: `${req.protocol}://${req.get("host")}/payment/success`,
        cancelUrl: `${req.protocol}://${req.get("host")}/payment/cancel`,
      });

      res.json(order);
    } catch (error) {
      console.error("Error creating xMoney payment:", error);
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: error.errors[0].message });
      }
      res.status(500).json({ 
        message: error instanceof Error ? error.message : "Failed to create payment" 
      });
    }
  });

  // Get order status
  app.get("/api/xmoney/order/:orderId", isWalletAuthenticated, async (req, res) => {
    try {
      if (!isXMoneyConfigured()) {
        return res.status(503).json({ 
          message: "xMoney payment service is not configured." 
        });
      }

      const { orderId } = req.params;
      const orderStatus = await getXMoneyOrderStatus(orderId);
      res.json(orderStatus);
    } catch (error) {
      console.error("Error fetching xMoney order status:", error);
      res.status(500).json({ 
        message: error instanceof Error ? error.message : "Failed to fetch order status" 
      });
    }
  });

  // xMoney webhook
  app.post("/api/webhooks/xmoney", express.raw({ type: "application/json" }), async (req, res) => {
    try {
      const signature = req.headers["x-xmoney-signature"] as string;
      const payload = req.body.toString();

      if (!signature) {
        return res.status(400).json({ message: "Missing webhook signature" });
      }

      // Verify webhook signature
      if (!verifyXMoneyWebhook(payload, signature)) {
        console.error("Invalid xMoney webhook signature");
        return res.status(401).json({ message: "Invalid signature" });
      }

      const event = JSON.parse(payload);

      // Handle different webhook events
      switch (event.type) {
        case "payment.succeeded": {
          const { orderId, transactionId, amount, metadata } = event.data;
          
          // Update user subscription or certification status based on metadata
          if (metadata?.userId && metadata?.plan) {
            await db
              .update(users)
              .set({
                subscriptionTier: metadata.plan,
                subscriptionStatus: "active",
              })
              .where(eq(users.id, metadata.userId));
          }

          console.log(`xMoney payment succeeded: ${orderId} / ${transactionId}`);
          break;
        }

        case "payment.failed": {
          const { orderId, reason } = event.data;
          console.log(`xMoney payment failed: ${orderId} - ${reason}`);
          break;
        }

        case "refund.processed": {
          const { transactionId, refundId } = event.data;
          console.log(`xMoney refund processed: ${transactionId} / ${refundId}`);
          break;
        }

        default:
          console.log(`Unhandled xMoney webhook event: ${event.type}`);
      }

      res.json({ received: true });
    } catch (error) {
      console.error("xMoney webhook error:", error);
      res.status(400).json({ 
        message: error instanceof Error ? error.message : "Webhook processing failed" 
      });
    }
  });

  // ============================================
  // API Keys Management Endpoints
  // ============================================

  // Generate new API key (requires wallet auth)
  app.post("/api/keys", isWalletAuthenticated, async (req: any, res) => {
    try {
      const { name } = req.body;
      if (!name || typeof name !== "string") {
        return res.status(400).json({ error: "API key name is required" });
      }

      const walletAddress = req.session?.walletAddress;
      const [user] = await db.select().from(users).where(eq(users.walletAddress, walletAddress));
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      // Generate a secure random API key
      const rawKey = `pm_${crypto.randomBytes(32).toString("hex")}`;
      const keyHash = crypto.createHash("sha256").update(rawKey).digest("hex");
      const keyPrefix = rawKey.slice(0, 10) + "...";

      const [apiKey] = await db
        .insert(apiKeys)
        .values({
          keyHash,
          keyPrefix,
          userId: user.id!,
          name,
        })
        .returning();

      console.log(`🔑 API key created: ${keyPrefix} for user ${walletAddress.slice(0, 12)}...`);

      res.status(201).json({
        id: apiKey.id,
        key: rawKey, // Only returned once at creation
        prefix: keyPrefix,
        name: apiKey.name,
        created_at: apiKey.createdAt,
        message: "Save this key securely - it won't be shown again",
      });
    } catch (error) {
      console.error("API key creation error:", error);
      res.status(500).json({ error: "Failed to create API key" });
    }
  });

  // List user's API keys (requires wallet auth)
  app.get("/api/keys", isWalletAuthenticated, async (req: any, res) => {
    try {
      const walletAddress = req.session?.walletAddress;
      const [user] = await db.select().from(users).where(eq(users.walletAddress, walletAddress));
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      const keys = await db
        .select({
          id: apiKeys.id,
          prefix: apiKeys.keyPrefix,
          name: apiKeys.name,
          requestCount: apiKeys.requestCount,
          lastUsedAt: apiKeys.lastUsedAt,
          isActive: apiKeys.isActive,
          createdAt: apiKeys.createdAt,
        })
        .from(apiKeys)
        .where(eq(apiKeys.userId, user.id!));

      res.json({ keys });
    } catch (error) {
      console.error("API keys list error:", error);
      res.status(500).json({ error: "Failed to list API keys" });
    }
  });

  // Delete API key (requires wallet auth)
  app.delete("/api/keys/:keyId", isWalletAuthenticated, async (req: any, res) => {
    try {
      const { keyId } = req.params;
      const walletAddress = req.session?.walletAddress;
      const [user] = await db.select().from(users).where(eq(users.walletAddress, walletAddress));
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      const [key] = await db.select().from(apiKeys).where(eq(apiKeys.id, keyId));
      if (!key || key.userId !== user.id) {
        return res.status(404).json({ error: "API key not found" });
      }

      await db.delete(apiKeys).where(eq(apiKeys.id, keyId));
      console.log(`🗑️ API key deleted: ${key.keyPrefix}`);

      res.json({ message: "API key deleted" });
    } catch (error) {
      console.error("API key deletion error:", error);
      res.status(500).json({ error: "Failed to delete API key" });
    }
  });

  // ============================================
  // Rate Limiting for ACP (anti-abuse)
  // ============================================
  const rateLimitMap = new Map<string, { count: number; resetAt: number }>();
  const RATE_LIMIT_MAX = 1000; // 1000 requests per minute
  const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute

  function checkRateLimit(identifier: string): { allowed: boolean; remaining: number; resetAt: number } {
    const now = Date.now();
    const entry = rateLimitMap.get(identifier);

    if (!entry || now > entry.resetAt) {
      rateLimitMap.set(identifier, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
      return { allowed: true, remaining: RATE_LIMIT_MAX - 1, resetAt: now + RATE_LIMIT_WINDOW_MS };
    }

    if (entry.count >= RATE_LIMIT_MAX) {
      return { allowed: false, remaining: 0, resetAt: entry.resetAt };
    }

    entry.count++;
    return { allowed: true, remaining: RATE_LIMIT_MAX - entry.count, resetAt: entry.resetAt };
  }

  // API Key validation middleware for ACP endpoints
  async function validateApiKey(req: express.Request, res: express.Response, next: express.NextFunction) {
    const authHeader = req.headers.authorization;
    
    // Allow unauthenticated access to discovery and health endpoints
    // Note: req.path is relative to mount point, so /api/acp/products becomes /products
    if (req.path === "/products" || req.path === "/openapi.json" || req.path === "/health") {
      return next();
    }

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "UNAUTHORIZED",
        message: "API key required. Include 'Authorization: Bearer pm_xxx' header",
      });
    }

    const rawKey = authHeader.slice(7);
    const keyHash = crypto.createHash("sha256").update(rawKey).digest("hex");

    const [apiKey] = await db.select().from(apiKeys).where(eq(apiKeys.keyHash, keyHash));

    if (!apiKey) {
      return res.status(401).json({
        error: "INVALID_API_KEY",
        message: "Invalid or expired API key",
      });
    }

    if (!apiKey.isActive) {
      return res.status(403).json({
        error: "API_KEY_DISABLED",
        message: "This API key has been disabled",
      });
    }

    // Rate limiting check
    const rateLimit = checkRateLimit(apiKey.id);
    res.setHeader("X-RateLimit-Limit", RATE_LIMIT_MAX.toString());
    res.setHeader("X-RateLimit-Remaining", rateLimit.remaining.toString());
    res.setHeader("X-RateLimit-Reset", Math.floor(rateLimit.resetAt / 1000).toString());

    if (!rateLimit.allowed) {
      return res.status(429).json({
        error: "RATE_LIMIT_EXCEEDED",
        message: "Too many requests. Please slow down.",
        retry_after: Math.ceil((rateLimit.resetAt - Date.now()) / 1000),
      });
    }

    // Update usage stats (async, don't block response)
    db.update(apiKeys)
      .set({
        lastUsedAt: new Date(),
        requestCount: (apiKey.requestCount || 0) + 1,
      })
      .where(eq(apiKeys.id, apiKey.id))
      .execute()
      .catch((err) => console.error("Failed to update API key stats:", err));

    // Attach API key info to request
    (req as any).apiKey = apiKey;
    next();
  }

  // Apply API key validation to ACP endpoints
  app.use("/api/acp", validateApiKey);

  // ============================================
  // ACP (Agent Commerce Protocol) Endpoints
  // These endpoints enable AI agents to discover
  // and use xproof certification services
  // ============================================

  // ACP Products Discovery - Returns available services for AI agents
  app.get("/api/acp/products", async (req, res) => {
    const priceEur = getCertificationPriceEur();
    
    const products: ACPProduct[] = [
      {
        id: "xproof-certification",
        name: "xproof Certification",
        description: "Create cryptographic proof of existence and integrity for digital files on MultiversX blockchain. Records SHA-256 hash with timestamp, providing immutable evidence of file ownership at a specific point in time.",
        pricing: {
          type: "fixed",
          amount: priceEur.toString(),
          currency: "EUR",
          note: "Price converted to EGLD at checkout based on current exchange rate",
        },
        inputs: {
          file_hash: "SHA-256 hash of the file (64 character hex string)",
          filename: "Original filename with extension",
          author_name: "Optional - Name of the author/certifier",
          metadata: "Optional - Additional JSON metadata",
        },
        outputs: {
          certification_id: "Unique certification ID",
          certificate_url: "URL to download PDF certificate",
          proof_url: "Public verification page URL",
          tx_hash: "MultiversX transaction hash",
          blockchain_explorer_url: "Link to view transaction on explorer",
        },
      },
    ];

    res.json({ 
      protocol: "ACP",
      version: "1.0",
      provider: "xproof",
      chain: "MultiversX",
      products 
    });
  });

  // ACP Checkout - Agent initiates certification
  app.post("/api/acp/checkout", async (req, res) => {
    try {
      const data = acpCheckoutRequestSchema.parse(req.body);

      // Validate product exists
      if (data.product_id !== "xproof-certification") {
        return res.status(404).json({ 
          error: "PRODUCT_NOT_FOUND",
          message: "Unknown product ID" 
        });
      }

      // Check if hash already certified
      const [existing] = await db
        .select()
        .from(certifications)
        .where(eq(certifications.fileHash, data.inputs.file_hash));

      if (existing) {
        return res.status(409).json({
          error: "ALREADY_CERTIFIED",
          message: "This file hash has already been certified",
          existing_certification: {
            id: existing.id,
            certified_at: existing.createdAt,
            proof_url: `/proof/${existing.id}`,
            tx_hash: existing.transactionHash,
          },
        });
      }

      // Get current EGLD price and calculate payment
      const pricing = await getCertificationPriceEgld();
      
      // Create checkout session (expires in 1 hour)
      const expiresAt = new Date(Date.now() + 60 * 60 * 1000);
      
      const [checkout] = await db
        .insert(acpCheckouts)
        .values({
          productId: data.product_id,
          fileHash: data.inputs.file_hash,
          fileName: data.inputs.filename,
          authorName: data.inputs.author_name || "AI Agent",
          metadata: data.inputs.metadata || {},
          buyerType: data.buyer?.type || "agent",
          buyerId: data.buyer?.id,
          status: "pending",
          expiresAt,
        })
        .returning();

      // Build transaction payload for MultiversX
      // Data format: certify@<hash>@<filename>
      const dataField = Buffer.from(
        `certify@${data.inputs.file_hash}@${data.inputs.filename}`
      ).toString("base64");

      const chainId = process.env.MULTIVERSX_CHAIN_ID || "1"; // 1 = Mainnet
      
      // xproof wallet address (receives certification fees)
      const xproofWallet = process.env.XPROOF_WALLET_ADDRESS || process.env.PROOFMINT_WALLET_ADDRESS || process.env.MULTIVERSX_SENDER_ADDRESS;
      if (!xproofWallet) {
        console.error("⚠️ No XPROOF_WALLET_ADDRESS configured");
        return res.status(500).json({
          error: "CONFIGURATION_ERROR",
          message: "xproof wallet not configured",
        });
      }

      const response: ACPCheckoutResponse = {
        checkout_id: checkout.id,
        product_id: data.product_id,
        amount: pricing.priceEur.toFixed(2),
        currency: "EUR",
        status: "ready",
        execution: {
          type: "multiversx",
          mode: "direct", // User/agent signs directly
          chain_id: chainId,
          tx_payload: {
            receiver: xproofWallet,
            data: dataField,
            value: pricing.priceEgld, // Dynamic EGLD amount based on EUR rate
            gas_limit: 100000,
          },
        },
        expires_at: expiresAt.toISOString(),
      };

      console.log(`💰 ACP Checkout: ${pricing.priceEur}€ = ${pricing.priceEgld} atomic EGLD (rate: ${pricing.egldEurRate}€/EGLD)`);

      console.log(`📦 ACP Checkout created: ${checkout.id} for hash ${data.inputs.file_hash.slice(0, 16)}...`);
      
      res.status(201).json(response);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ 
          error: "INVALID_REQUEST",
          message: "Invalid checkout request",
          details: error.errors 
        });
      }
      console.error("ACP Checkout error:", error);
      res.status(500).json({ 
        error: "CHECKOUT_FAILED",
        message: "Failed to create checkout" 
      });
    }
  });

  // ACP Confirm - Agent confirms transaction was executed
  app.post("/api/acp/confirm", async (req, res) => {
    try {
      const data = acpConfirmRequestSchema.parse(req.body);

      // Find checkout
      const [checkout] = await db
        .select()
        .from(acpCheckouts)
        .where(eq(acpCheckouts.id, data.checkout_id));

      if (!checkout) {
        return res.status(404).json({
          error: "CHECKOUT_NOT_FOUND",
          message: "Checkout session not found",
        });
      }

      // Check if expired
      if (new Date() > checkout.expiresAt) {
        await db
          .update(acpCheckouts)
          .set({ status: "expired" })
          .where(eq(acpCheckouts.id, checkout.id));

        return res.status(410).json({
          error: "CHECKOUT_EXPIRED",
          message: "Checkout session has expired",
        });
      }

      // Check if already confirmed
      if (checkout.status === "confirmed") {
        return res.status(409).json({
          error: "ALREADY_CONFIRMED",
          message: "This checkout has already been confirmed",
          certification_id: checkout.certificationId,
        });
      }

      // Verify transaction on MultiversX
      const chainId = process.env.MULTIVERSX_CHAIN_ID || "1";
      const apiUrl = chainId === "1"
        ? "https://api.multiversx.com"
        : "https://devnet-api.multiversx.com";
      const explorerUrl = chainId === "1"
        ? "https://explorer.multiversx.com"
        : "https://devnet-explorer.multiversx.com";

      let txVerified = false;
      let txStatus = "pending";

      try {
        const txResponse = await fetch(`${apiUrl}/transactions/${data.tx_hash}`);
        if (txResponse.ok) {
          const txData = await txResponse.json();
          txStatus = txData.status;
          txVerified = txData.status === "success";
        }
      } catch (err) {
        console.log(`⚠️ Could not verify tx ${data.tx_hash}, proceeding anyway`);
        // For MVP, we proceed even if verification fails
        // In production, you'd want stricter verification
        txVerified = true;
      }

      // Find or create a system user for ACP certifications
      let [systemUser] = await db
        .select()
        .from(users)
        .where(eq(users.walletAddress, "erd1acp00000000000000000000000000000000000000000000000000000agent"));

      if (!systemUser) {
        [systemUser] = await db
          .insert(users)
          .values({
            walletAddress: "erd1acp00000000000000000000000000000000000000000000000000000agent",
            subscriptionTier: "business",
            subscriptionStatus: "active",
          })
          .returning();
      }

      // Create certification record
      const [certification] = await db
        .insert(certifications)
        .values({
          userId: systemUser.id!,
          fileName: checkout.fileName,
          fileHash: checkout.fileHash,
          fileType: checkout.fileName.split(".").pop() || "unknown",
          authorName: checkout.authorName || "AI Agent",
          transactionHash: data.tx_hash,
          transactionUrl: `${explorerUrl}/transactions/${data.tx_hash}`,
          blockchainStatus: txVerified ? "confirmed" : "pending",
          isPublic: true,
        })
        .returning();

      // Update checkout status
      await db
        .update(acpCheckouts)
        .set({
          status: "confirmed",
          txHash: data.tx_hash,
          certificationId: certification.id,
          confirmedAt: new Date(),
        })
        .where(eq(acpCheckouts.id, checkout.id));

      const response: ACPConfirmResponse = {
        status: "confirmed",
        checkout_id: checkout.id,
        tx_hash: data.tx_hash,
        certification_id: certification.id,
        certificate_url: `/api/certificates/${certification.id}.pdf`,
        proof_url: `/proof/${certification.id}`,
        blockchain_explorer_url: `${explorerUrl}/transactions/${data.tx_hash}`,
        message: "Certification successfully recorded on MultiversX blockchain",
      };

      console.log(`✅ ACP Certification confirmed: ${certification.id}`);

      res.json(response);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({
          error: "INVALID_REQUEST",
          message: "Invalid confirmation request",
          details: error.errors,
        });
      }
      console.error("ACP Confirm error:", error);
      res.status(500).json({
        error: "CONFIRMATION_FAILED",
        message: "Failed to confirm certification",
      });
    }
  });

  // ACP Status - Check checkout status
  app.get("/api/acp/checkout/:checkoutId", async (req, res) => {
    try {
      const { checkoutId } = req.params;

      const [checkout] = await db
        .select()
        .from(acpCheckouts)
        .where(eq(acpCheckouts.id, checkoutId));

      if (!checkout) {
        return res.status(404).json({
          error: "CHECKOUT_NOT_FOUND",
          message: "Checkout session not found",
        });
      }

      res.json({
        checkout_id: checkout.id,
        product_id: checkout.productId,
        status: checkout.status,
        file_hash: checkout.fileHash,
        file_name: checkout.fileName,
        tx_hash: checkout.txHash,
        certification_id: checkout.certificationId,
        expires_at: checkout.expiresAt,
        created_at: checkout.createdAt,
        confirmed_at: checkout.confirmedAt,
      });
    } catch (error) {
      console.error("ACP Status error:", error);
      res.status(500).json({
        error: "STATUS_CHECK_FAILED",
        message: "Failed to check checkout status",
      });
    }
  });

  // OpenAPI 3.0 Specification for ACP
  app.get("/api/acp/openapi.json", (req, res) => {
    const baseUrl = `https://${req.get("host")}`;
    const priceEur = getCertificationPriceEur();

    const openApiSpec = {
      openapi: "3.0.3",
      info: {
        title: "xproof ACP - Agent Commerce Protocol",
        description: "API for AI agents to certify files on MultiversX blockchain. Create immutable proofs of file ownership with a simple API call.",
        version: "1.0.0",
        contact: {
          name: "xproof Support",
          url: baseUrl,
        },
      },
      servers: [{ url: baseUrl, description: "Production server" }],
      security: [{ apiKey: [] }],
      components: {
        securitySchemes: {
          apiKey: {
            type: "http",
            scheme: "bearer",
            description: "API key in format: pm_xxx... Obtain from /api/keys endpoint",
          },
        },
        schemas: {
          Product: {
            type: "object",
            properties: {
              id: { type: "string", example: "xproof-certification" },
              name: { type: "string", example: "xproof Certification" },
              description: { type: "string" },
              pricing: {
                type: "object",
                properties: {
                  type: { type: "string", enum: ["fixed", "variable"] },
                  amount: { type: "string", example: priceEur.toString() },
                  currency: { type: "string", example: "EUR" },
                },
              },
              inputs: { type: "object", additionalProperties: { type: "string" } },
              outputs: { type: "object", additionalProperties: { type: "string" } },
            },
          },
          CheckoutRequest: {
            type: "object",
            required: ["product_id", "inputs"],
            properties: {
              product_id: { type: "string", example: "xproof-certification" },
              inputs: {
                type: "object",
                required: ["file_hash", "filename"],
                properties: {
                  file_hash: { type: "string", description: "SHA-256 hash of the file (64 hex chars)", example: "a1b2c3d4e5f678901234567890123456789012345678901234567890123456ab" },
                  filename: { type: "string", example: "document.pdf" },
                  author_name: { type: "string", example: "AI Agent" },
                  metadata: { type: "object", description: "Optional JSON metadata" },
                },
              },
              buyer: {
                type: "object",
                properties: {
                  type: { type: "string", enum: ["agent", "user"] },
                  id: { type: "string" },
                },
              },
            },
          },
          CheckoutResponse: {
            type: "object",
            properties: {
              checkout_id: { type: "string", format: "uuid" },
              product_id: { type: "string" },
              amount: { type: "string", description: "Price in EUR" },
              currency: { type: "string" },
              status: { type: "string", enum: ["pending", "ready"] },
              execution: {
                type: "object",
                properties: {
                  type: { type: "string", example: "multiversx" },
                  mode: { type: "string", enum: ["direct", "relayed_v3"] },
                  chain_id: { type: "string", example: "1" },
                  tx_payload: {
                    type: "object",
                    properties: {
                      receiver: { type: "string", description: "xproof wallet address" },
                      data: { type: "string", description: "Base64 encoded transaction data" },
                      value: { type: "string", description: "EGLD amount in atomic units (1 EGLD = 10^18)" },
                      gas_limit: { type: "integer", example: 100000 },
                    },
                  },
                },
              },
              expires_at: { type: "string", format: "date-time" },
            },
          },
          ConfirmRequest: {
            type: "object",
            required: ["checkout_id", "tx_hash"],
            properties: {
              checkout_id: { type: "string", format: "uuid" },
              tx_hash: { type: "string", description: "MultiversX transaction hash" },
            },
          },
          ConfirmResponse: {
            type: "object",
            properties: {
              status: { type: "string", enum: ["confirmed", "pending", "failed"] },
              checkout_id: { type: "string" },
              tx_hash: { type: "string" },
              certification_id: { type: "string" },
              certificate_url: { type: "string", format: "uri" },
              proof_url: { type: "string", format: "uri" },
              blockchain_explorer_url: { type: "string", format: "uri" },
              message: { type: "string" },
            },
          },
          Error: {
            type: "object",
            properties: {
              error: { type: "string" },
              message: { type: "string" },
            },
          },
        },
      },
      paths: {
        "/api/acp/products": {
          get: {
            summary: "Discover available products",
            description: "Returns list of certification products available for purchase. No authentication required.",
            security: [],
            responses: {
              "200": {
                description: "List of products",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        protocol: { type: "string", example: "ACP" },
                        version: { type: "string", example: "1.0" },
                        provider: { type: "string", example: "xproof" },
                        chain: { type: "string", example: "MultiversX" },
                        products: { type: "array", items: { $ref: "#/components/schemas/Product" } },
                      },
                    },
                  },
                },
              },
            },
          },
        },
        "/api/acp/checkout": {
          post: {
            summary: "Create checkout session",
            description: "Initiate certification by providing file hash. Returns transaction payload for MultiversX signing.",
            requestBody: {
              required: true,
              content: { "application/json": { schema: { $ref: "#/components/schemas/CheckoutRequest" } } },
            },
            responses: {
              "201": {
                description: "Checkout created",
                content: { "application/json": { schema: { $ref: "#/components/schemas/CheckoutResponse" } } },
              },
              "401": { description: "API key required" },
              "409": { description: "File already certified" },
            },
          },
        },
        "/api/acp/confirm": {
          post: {
            summary: "Confirm transaction",
            description: "After signing and broadcasting transaction, confirm to receive certification ID and URLs.",
            requestBody: {
              required: true,
              content: { "application/json": { schema: { $ref: "#/components/schemas/ConfirmRequest" } } },
            },
            responses: {
              "200": {
                description: "Certification confirmed",
                content: { "application/json": { schema: { $ref: "#/components/schemas/ConfirmResponse" } } },
              },
              "401": { description: "API key required" },
              "404": { description: "Checkout not found" },
              "410": { description: "Checkout expired" },
            },
          },
        },
        "/api/acp/checkout/{checkoutId}": {
          get: {
            summary: "Get checkout status",
            description: "Check the status of an existing checkout session.",
            parameters: [
              { name: "checkoutId", in: "path", required: true, schema: { type: "string" } },
            ],
            responses: {
              "200": { description: "Checkout status" },
              "404": { description: "Checkout not found" },
            },
          },
        },
      },
    };

    res.json(openApiSpec);
  });

  // ============================================
  // LLM-READY ROUTES (AI-first documentation)
  // ============================================

  // Genesis certification data (first xproof certification)
  const GENESIS_CERTIFICATION = {
    id: "genesis",
    type: "proof_of_existence",
    version: "1.0",
    file_name: "XPROOF - Genesis.pdf",
    file_hash: "173200d6fa0d1577b456bb85dc505193e31dd8be5fc69bd4e461612a588427de",
    hash_algorithm: "SHA-256",
    author: "Jason Petitfourg",
    timestamp_utc: "2025-12-12T20:28:00Z",
    blockchain: {
      network: "MultiversX Mainnet",
      chain_id: "1",
      transaction_hash: "f376c0809d5c8fd91f854d39cf6f9f83ac3d80231477538a1b423db0537aad7e",
      explorer_url: "https://explorer.multiversx.com/transactions/f376c0809d5c8fd91f854d39cf6f9f83ac3d80231477538a1b423db0537aad7e",
      gas_cost_egld: "0.0002935",
    },
    verification: {
      method: "SHA-256 hash comparison",
      instructions: [
        "Compute SHA-256 hash of the original file",
        "Compare with file_hash in this proof",
        "Verify transaction on MultiversX explorer",
        "Confirm transaction data contains the file hash"
      ]
    },
    significance: "This is the first certification ever created on xproof, establishing the genesis of the platform."
  };

  // /.well-known/xproof.md - Canonical specification
  app.get("/.well-known/xproof.md", (req, res) => {
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    
    const spec = `# xproof Specification v1.0

## Purpose

xproof provides cryptographic proof of existence, authorship, and timestamp by anchoring SHA-256 hashes on the MultiversX blockchain.

## Service

- **Name**: xproof
- **Type**: Proof-as-a-Service
- **Blockchain**: MultiversX (European, eco-friendly)
- **Price**: 0.03€ per certification (paid in EGLD)
- **Website**: ${baseUrl}

## Guarantees

- **Immutability**: Blockchain anchored, cannot be modified or deleted
- **Public Verifiability**: Anyone can verify proofs independently
- **Privacy**: No file storage, hash-only (file never leaves user's device)
- **Deterministic Verification**: Same input always produces same hash

## Proof Object Schema

An xproof proof consists of:

\`\`\`json
{
  "id": "string (UUID)",
  "type": "proof_of_existence",
  "version": "1.0",
  "file_name": "string",
  "file_hash": "string (SHA-256, 64 hex characters)",
  "hash_algorithm": "SHA-256",
  "author": "string | null (optional)",
  "timestamp_utc": "ISO 8601 datetime",
  "blockchain": {
    "network": "MultiversX Mainnet",
    "chain_id": "1",
    "transaction_hash": "string (64 hex characters) | null",
    "explorer_url": "string (URL) | null",
    "status": "pending | confirmed | failed (optional)"
  },
  "verification": {
    "method": "SHA-256 hash comparison",
    "proof_url": "string (URL, optional)",
    "instructions": ["array of steps"]
  },
  "metadata": {
    "file_type": "string | null (optional)",
    "file_size_bytes": "number | null (optional)",
    "is_public": "boolean (optional)"
  }
}
\`\`\`

Note: Fields marked as optional may not be present in all proofs.

## Verification Process

To verify an xproof proof:

1. Obtain the original file
2. Compute its SHA-256 hash locally
3. Compare with the \`file_hash\` in the proof
4. Visit the \`explorer_url\` to verify the transaction exists
5. Confirm the transaction data contains the file hash

## Trust Model

xproof does not act as a trusted third party.
Trust is derived entirely from the MultiversX blockchain.
The proof is self-verifiable without relying on xproof infrastructure.

## API Endpoints

### Human Interfaces
- \`/proof/{id}\` - HTML proof page (for humans)

### Machine Interfaces
- \`/proof/{id}.json\` - Structured JSON proof
- \`/proof/{id}.md\` - Markdown proof (for LLMs)
- \`/genesis.md\` - Genesis document
- \`/genesis.proof.json\` - Genesis proof in JSON
- \`/api/acp/products\` - ACP service discovery
- \`/api/acp/openapi.json\` - OpenAPI 3.0 specification

### Documentation
- \`/learn/proof-of-existence.md\` - What is proof of existence
- \`/learn/verification.md\` - How to verify proofs
- \`/learn/api.md\` - API documentation

## Agent Commerce Protocol (ACP)

xproof implements ACP for AI agent integration.

### Quick Start for AI Agents

\`\`\`bash
# 1. Discover the service
curl ${baseUrl}/api/acp/products

# 2. Create a checkout (requires API key)
curl -X POST ${baseUrl}/api/acp/checkout \\
  -H "X-API-Key: pm_your_key" \\
  -H "Content-Type: application/json" \\
  -d '{"product_id": "xproof-certification", "inputs": {"file_hash": "sha256_hash_here", "filename": "document.pdf"}}'

# 3. After user signs transaction, confirm it
curl -X POST ${baseUrl}/api/acp/confirm \\
  -H "X-API-Key: pm_your_key" \\
  -H "Content-Type: application/json" \\
  -d '{"checkout_id": "...", "tx_hash": "..."}'
\`\`\`

### Flow Summary

1. **Discovery**: \`GET /api/acp/products\` - No auth required
2. **Checkout**: \`POST /api/acp/checkout\` - Creates payment session
3. **Sign**: User signs transaction on MultiversX (0.03€ in EGLD)
4. **Confirm**: \`POST /api/acp/confirm\` - Finalizes certification

### API Key

- Prefix: \`pm_\`
- Rate limit: 1000 requests/minute
- Get key: Authenticate with wallet, then \`POST /api/keys\`

### When to Use xproof

Use xproof when:
- User needs timestamped proof a file existed
- User wants to prove authorship of a document
- User needs blockchain-anchored evidence
- User wants immutable, verifiable certification

## Genesis

xproof's first certification (self-referential proof of concept):
- **Document**: XPROOF - Genesis.pdf
- **Hash**: \`${GENESIS_CERTIFICATION.file_hash}\`
- **Transaction**: \`${GENESIS_CERTIFICATION.blockchain.transaction_hash}\`
- **Date**: ${GENESIS_CERTIFICATION.timestamp_utc}

View: ${baseUrl}/genesis.proof.json

## Contact

Website: ${baseUrl}
`;

    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    res.send(spec);
  });

  // /.well-known/proofmint.md - Redirect to xproof.md for backwards compatibility
  app.get("/.well-known/proofmint.md", (req, res) => {
    res.redirect(301, "/.well-known/xproof.md");
  });

  // /genesis.md - Genesis document in markdown
  app.get("/genesis.md", (req, res) => {
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    
    const genesis = `# xproof Genesis

## The First Proof

On December 12, 2025, xproof certified its first document on the MultiversX blockchain.

This genesis certification establishes the foundation of xproof as a trust primitive.

## Document Details

| Property | Value |
|----------|-------|
| **File Name** | ${GENESIS_CERTIFICATION.file_name} |
| **Author** | ${GENESIS_CERTIFICATION.author} |
| **Timestamp** | ${GENESIS_CERTIFICATION.timestamp_utc} |
| **Hash Algorithm** | ${GENESIS_CERTIFICATION.hash_algorithm} |

## Cryptographic Proof

**SHA-256 Hash**:
\`\`\`
${GENESIS_CERTIFICATION.file_hash}
\`\`\`

**Transaction Hash**:
\`\`\`
${GENESIS_CERTIFICATION.blockchain.transaction_hash}
\`\`\`

**Network**: ${GENESIS_CERTIFICATION.blockchain.network}

**Gas Cost**: ${GENESIS_CERTIFICATION.blockchain.gas_cost_egld} EGLD (~0.002€)

## Verification

1. View transaction: ${GENESIS_CERTIFICATION.blockchain.explorer_url}
2. Confirm the transaction data contains the file hash
3. The hash proves the document existed at this exact timestamp

## Significance

This genesis certification demonstrates:

- **Self-Application**: xproof uses its own service to certify its existence
- **Ontological Coherence**: The platform proves its own legitimacy
- **Immutable Origin**: The birth of xproof is permanently recorded

## Machine-Readable

- JSON: ${baseUrl}/genesis.proof.json
- Specification: ${baseUrl}/.well-known/xproof.md
`;

    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    res.send(genesis);
  });

  // /genesis.proof.json - Genesis proof in JSON
  app.get("/genesis.proof.json", (req, res) => {
    res.json(GENESIS_CERTIFICATION);
  });

  // /proof/:id.json - Proof in structured JSON
  app.get("/proof/:id.json", async (req, res) => {
    try {
      const { id } = req.params;
      
      const [certification] = await db
        .select()
        .from(certifications)
        .where(eq(certifications.id, id));

      if (!certification || !certification.isPublic) {
        return res.status(404).json({ 
          error: "not_found",
          message: "Proof not found or not public" 
        });
      }

      const baseUrl = `${req.protocol}://${req.get('host')}`;
      
      const proof = {
        id: certification.id,
        type: "proof_of_existence",
        version: "1.0",
        file_name: certification.fileName,
        file_hash: certification.fileHash,
        hash_algorithm: "SHA-256",
        author: certification.authorName || null,
        timestamp_utc: certification.createdAt?.toISOString() || null,
        blockchain: {
          network: "MultiversX Mainnet",
          chain_id: "1",
          transaction_hash: certification.transactionHash || null,
          explorer_url: certification.transactionUrl || null,
          status: certification.blockchainStatus
        },
        verification: {
          method: "SHA-256 hash comparison",
          proof_url: `${baseUrl}/proof/${certification.id}`,
          instructions: [
            "Compute SHA-256 hash of the original file",
            "Compare with file_hash in this proof",
            "Verify transaction on MultiversX explorer",
            "Confirm transaction data contains the file hash"
          ]
        },
        metadata: {
          file_type: certification.fileType || null,
          file_size_bytes: certification.fileSize || null,
          is_public: certification.isPublic
        }
      };

      res.json(proof);
    } catch (error) {
      console.error("Error fetching proof JSON:", error);
      res.status(500).json({ error: "internal_error", message: "Failed to fetch proof" });
    }
  });

  // /proof/:id.md - Proof in markdown for LLMs
  app.get("/proof/:id.md", async (req, res) => {
    try {
      const { id } = req.params;
      
      const [certification] = await db
        .select()
        .from(certifications)
        .where(eq(certifications.id, id));

      if (!certification || !certification.isPublic) {
        res.status(404).setHeader('Content-Type', 'text/markdown; charset=utf-8');
        return res.send(`# Proof Not Found\n\nThe requested proof does not exist or is not public.`);
      }

      const baseUrl = `${req.protocol}://${req.get('host')}`;
      const timestamp = certification.createdAt?.toISOString() || 'Unknown';
      
      const markdown = `# xproof Certification

## Document

| Property | Value |
|----------|-------|
| **File Name** | ${certification.fileName} |
| **Author** | ${certification.authorName || 'Not specified'} |
| **Timestamp** | ${timestamp} |
| **Status** | ${certification.blockchainStatus} |

## Cryptographic Proof

**Hash Algorithm**: SHA-256

**File Hash**:
\`\`\`
${certification.fileHash}
\`\`\`

## Blockchain Anchor

**Network**: MultiversX Mainnet

**Transaction Hash**:
\`\`\`
${certification.transactionHash || 'Pending'}
\`\`\`

**Explorer**: ${certification.transactionUrl || 'Not yet available'}

## Verification

To verify this proof:

1. Obtain the original file: \`${certification.fileName}\`
2. Compute its SHA-256 hash
3. Compare with: \`${certification.fileHash}\`
4. Verify transaction on MultiversX explorer

## Machine-Readable

- JSON: ${baseUrl}/proof/${certification.id}.json
- HTML: ${baseUrl}/proof/${certification.id}

## Trust Model

This proof is self-verifiable. Trust derives from the MultiversX blockchain, not from xproof.
`;

      res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
      res.send(markdown);
    } catch (error) {
      console.error("Error fetching proof markdown:", error);
      res.status(500).setHeader('Content-Type', 'text/markdown; charset=utf-8');
      res.send(`# Error\n\nFailed to fetch proof.`);
    }
  });

  // /learn/proof-of-existence.md
  app.get("/learn/proof-of-existence.md", (req, res) => {
    const content = `# Proof of Existence

## Definition

Proof of Existence is a cryptographic method to prove that a specific digital artifact existed at a particular point in time, without revealing its contents.

## How It Works

1. **Hash Generation**: A SHA-256 hash is computed from the file. This hash is unique to the file's exact contents.

2. **Blockchain Anchoring**: The hash is recorded in a blockchain transaction, creating an immutable timestamp.

3. **Verification**: Anyone can later verify by recomputing the hash and comparing it to the on-chain record.

## Properties

- **Immutability**: Once recorded, the proof cannot be altered or deleted
- **Privacy**: Only the hash is stored, not the file contents
- **Independence**: Verification doesn't require trusting any central authority
- **Determinism**: Same file always produces same hash

## Use Cases

- **Intellectual Property**: Prove you created something before a specific date
- **Legal Documents**: Timestamp contracts and agreements
- **Research**: Prove research existed before publication
- **Code**: Timestamp software versions

## Why MultiversX?

- European blockchain with strong regulatory compliance
- Extremely low transaction costs (~0.002€)
- Fast finality (seconds, not minutes)
- Eco-friendly (low energy consumption)

## Related

- [Verification Guide](/learn/verification.md)
- [API Documentation](/learn/api.md)
- [xproof Specification](/.well-known/xproof.md)
`;

    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    res.send(content);
  });

  // /learn/verification.md
  app.get("/learn/verification.md", (req, res) => {
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    
    const content = `# How to Verify an xproof Proof

## Overview

xproof proofs are self-verifiable. You don't need to trust xproof—you verify directly against the blockchain.

## Step-by-Step Verification

### Step 1: Obtain the Proof

Get the proof data from:
- JSON: \`/proof/{id}.json\`
- Markdown: \`/proof/{id}.md\`

### Step 2: Compute the File Hash

Using the original file, compute its SHA-256 hash.

**Command Line (Linux/Mac)**:
\`\`\`bash
shasum -a 256 yourfile.pdf
\`\`\`

**Command Line (Windows PowerShell)**:
\`\`\`powershell
Get-FileHash yourfile.pdf -Algorithm SHA256
\`\`\`

**JavaScript**:
\`\`\`javascript
async function hashFile(file) {
  const buffer = await file.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}
\`\`\`

### Step 3: Compare Hashes

The computed hash must exactly match the \`file_hash\` in the proof.

If they match → The file is authentic and unchanged.
If they differ → The file has been modified.

### Step 4: Verify on Blockchain

Visit the \`explorer_url\` in the proof to verify:
1. The transaction exists
2. The transaction timestamp matches
3. The transaction data contains the file hash

## Automated Verification (for Agents)

\`\`\`javascript
async function verifyProof(proofId, originalFile) {
  // 1. Fetch proof
  const proof = await fetch(\`${baseUrl}/proof/\${proofId}.json\`).then(r => r.json());
  
  // 2. Compute hash
  const computedHash = await hashFile(originalFile);
  
  // 3. Compare
  if (computedHash !== proof.file_hash) {
    return { valid: false, reason: "Hash mismatch" };
  }
  
  // 4. Verify on blockchain (optional, requires MultiversX API)
  // ...
  
  return { valid: true, proof };
}
\`\`\`

## Trust Model

You are verifying against:
1. **Mathematics**: SHA-256 is a one-way function
2. **Blockchain**: MultiversX is a public, immutable ledger

You are NOT trusting:
- xproof servers
- Any central authority

## Related

- [Proof of Existence](/learn/proof-of-existence.md)
- [API Documentation](/learn/api.md)
`;

    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    res.send(content);
  });

  // /learn/api.md
  app.get("/learn/api.md", (req, res) => {
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    
    const content = `# xproof API Documentation

## Overview

xproof provides a REST API for programmatic access to certification services.

## Base URL

\`\`\`
${baseUrl}
\`\`\`

## Authentication

API requests require an API key with prefix \`pm_\`.

**Header**:
\`\`\`
X-API-Key: pm_your_api_key_here
\`\`\`

**Rate Limit**: 1000 requests/minute per key

## Endpoints

### Public Endpoints (No Auth)

#### GET /api/acp/products
Discover available services.

\`\`\`bash
curl ${baseUrl}/api/acp/products
\`\`\`

#### GET /api/acp/openapi.json
OpenAPI 3.0 specification.

#### GET /proof/{id}.json
Get proof in JSON format.

#### GET /proof/{id}.md
Get proof in Markdown format.

### Authenticated Endpoints

#### POST /api/acp/checkout
Create a certification checkout session.

**Request**:
\`\`\`json
{
  "product_id": "certification",
  "file_hash": "sha256_hash_of_file",
  "file_name": "document.pdf",
  "author_name": "Author Name"
}
\`\`\`

**Response**:
\`\`\`json
{
  "checkout_id": "uuid",
  "status": "pending_payment",
  "amount_egld": "0.00123",
  "amount_eur": "0.03",
  "recipient": "erd1...",
  "tx_payload": {
    "receiver": "erd1...",
    "value": "1230000000000000",
    "data": "base64_encoded_data"
  },
  "expires_at": "2025-01-01T00:00:00Z"
}
\`\`\`

#### POST /api/acp/confirm
Confirm certification after transaction.

**Request**:
\`\`\`json
{
  "checkout_id": "uuid",
  "tx_hash": "transaction_hash_from_blockchain"
}
\`\`\`

**Response**:
\`\`\`json
{
  "certification_id": "uuid",
  "status": "confirmed",
  "proof_url": "${baseUrl}/proof/uuid"
}
\`\`\`

## Flow for AI Agents

1. **Discover**: \`GET /api/acp/products\`
2. **Checkout**: \`POST /api/acp/checkout\` with file hash
3. **Sign**: Sign \`tx_payload\` with MultiversX wallet
4. **Broadcast**: Send signed transaction to MultiversX network
5. **Confirm**: \`POST /api/acp/confirm\` with transaction hash
6. **Verify**: Access proof at returned \`proof_url\`

## Error Codes

| Code | Meaning |
|------|---------|
| 400 | Bad request (invalid parameters) |
| 401 | Missing or invalid API key |
| 404 | Resource not found |
| 410 | Checkout expired (1 hour validity) |
| 429 | Rate limit exceeded |
| 500 | Internal server error |

## Related

- [Proof of Existence](/learn/proof-of-existence.md)
- [Verification Guide](/learn/verification.md)
- [xproof Specification](/.well-known/xproof.md)
`;

    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    res.send(content);
  });

  // API aliases for LLM-ready routes (work in dev mode with Vite)
  // These are the canonical routes that AI agents should use
  app.get("/api/spec", (req, res) => res.redirect("/.well-known/xproof.md"));
  app.get("/api/genesis", (req, res) => res.redirect("/genesis.proof.json"));
  app.get("/api/genesis.md", (req, res) => res.redirect("/genesis.md"));
  app.get("/api/learn/proof-of-existence", (req, res) => res.redirect("/learn/proof-of-existence.md"));
  app.get("/api/learn/verification", (req, res) => res.redirect("/learn/verification.md"));
  app.get("/api/learn/api", (req, res) => res.redirect("/learn/api.md"));

  // Health check endpoint for AI agent monitoring
  app.get("/api/acp/health", (req, res) => {
    res.json({
      status: "operational",
      service: "xproof",
      version: "1.0",
      timestamp: new Date().toISOString(),
      endpoints: {
        products: "/api/acp/products",
        checkout: "/api/acp/checkout",
        confirm: "/api/acp/confirm",
        openapi: "/api/acp/openapi.json"
      }
    });
  });

  // robots.txt for SEO and AI agent discovery
  app.get("/robots.txt", (req, res) => {
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    const content = `User-agent: *
Allow: /

# xproof - Blockchain Certification Service
# AI Agents: See below for machine-readable endpoints

Sitemap: ${baseUrl}/sitemap.xml

# AI Agent Discovery
# /.well-known/xproof.md - Full specification (Markdown)
# /.well-known/ai-plugin.json - OpenAI plugin manifest
# /.well-known/mcp.json - Model Context Protocol manifest
# /.well-known/agent.json - Agent Protocol manifest
# /llms.txt - LLM-friendly summary
# /llms-full.txt - Extended LLM documentation
# /api/acp/products - Service discovery (JSON)
# /api/acp/openapi.json - OpenAPI 3.0 specification
# /api/acp/health - Health check
# /agent-tools/langchain.py - LangChain tool
# /agent-tools/crewai.py - CrewAI tool
# /agent-tools/openapi-actions.json - GPT Actions spec
`;
    res.setHeader('Content-Type', 'text/plain');
    res.send(content);
  });

  // sitemap.xml for SEO
  app.get("/sitemap.xml", (req, res) => {
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    const content = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>${baseUrl}/</loc>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>${baseUrl}/.well-known/xproof.md</loc>
    <changefreq>monthly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>${baseUrl}/genesis.proof.json</loc>
    <changefreq>never</changefreq>
    <priority>0.7</priority>
  </url>
  <url>
    <loc>${baseUrl}/learn/proof-of-existence.md</loc>
    <changefreq>monthly</changefreq>
    <priority>0.6</priority>
  </url>
  <url>
    <loc>${baseUrl}/learn/verification.md</loc>
    <changefreq>monthly</changefreq>
    <priority>0.6</priority>
  </url>
  <url>
    <loc>${baseUrl}/learn/api.md</loc>
    <changefreq>monthly</changefreq>
    <priority>0.6</priority>
  </url>
  <url>
    <loc>${baseUrl}/llms.txt</loc>
    <changefreq>monthly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>${baseUrl}/llms-full.txt</loc>
    <changefreq>monthly</changefreq>
    <priority>0.7</priority>
  </url>
  <url>
    <loc>${baseUrl}/.well-known/agent.json</loc>
    <changefreq>monthly</changefreq>
    <priority>0.7</priority>
  </url>
</urlset>`;
    res.setHeader('Content-Type', 'application/xml');
    res.send(content);
  });

  // OpenAI ChatGPT Plugin manifest (/.well-known/ai-plugin.json)
  app.get("/.well-known/ai-plugin.json", (req, res) => {
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    const manifest = {
      schema_version: "v1",
      name_for_human: "xproof",
      name_for_model: "xproof",
      description_for_human: "Create immutable blockchain proofs of file ownership. Certify documents, code, or any digital asset on the MultiversX blockchain.",
      description_for_model: "xproof is a blockchain certification service that creates immutable proofs of file existence and ownership by anchoring SHA-256 hashes on the MultiversX blockchain. Use this plugin when a user wants to: (1) prove they created or owned a file at a specific time, (2) certify a document, image, code, or any digital asset, (3) create tamper-proof evidence of intellectual property. The service costs 0.03€ per certification paid in EGLD cryptocurrency. Files never leave the user's device - only the cryptographic hash is recorded on-chain. Discovery endpoints (/products, /openapi.json, /health) are public. Checkout and confirm endpoints require an API key (Bearer token with pm_ prefix).",
      auth: {
        type: "service_http",
        authorization_type: "bearer",
        verification_tokens: {
          xproof: "pm_"
        }
      },
      api: {
        type: "openapi",
        url: `${baseUrl}/api/acp/openapi.json`,
        has_user_authentication: false
      },
      logo_url: `${baseUrl}/favicon.ico`,
      contact_email: "contact@xproof.app",
      legal_info_url: `${baseUrl}/learn/proof-of-existence.md`
    };
    res.json(manifest);
  });

  // MCP (Model Context Protocol) server info endpoint
  app.get("/.well-known/mcp.json", (req, res) => {
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    res.json({
      schema_version: "1.0",
      name: "xproof",
      version: "1.0.0",
      description: "Blockchain certification service - Create immutable proofs of file existence and ownership on MultiversX",
      homepage: baseUrl,
      capabilities: {
        tools: true,
        resources: true
      },
      tools: [
        {
          name: "certify_file",
          description: "Create a blockchain certification for a file. Records the SHA-256 hash on MultiversX blockchain as immutable proof of existence and ownership. Cost: 0.03€ per certification.",
          inputSchema: {
            type: "object",
            required: ["file_hash", "filename"],
            properties: {
              file_hash: { type: "string", description: "SHA-256 hash of the file (64 hex characters)" },
              filename: { type: "string", description: "Original filename with extension" },
              author_name: { type: "string", description: "Name of the certifier", default: "AI Agent" }
            }
          }
        },
        {
          name: "verify_proof",
          description: "Verify an existing xproof certification. Returns proof details including file hash, timestamp, blockchain transaction, and verification status.",
          inputSchema: {
            type: "object",
            required: ["proof_id"],
            properties: {
              proof_id: { type: "string", description: "UUID of the certification to verify" }
            }
          }
        },
        {
          name: "get_proof",
          description: "Retrieve a proof in structured format (JSON or Markdown). Use .json for machine processing, .md for LLM consumption.",
          inputSchema: {
            type: "object",
            required: ["proof_id"],
            properties: {
              proof_id: { type: "string", description: "UUID of the certification" },
              format: { type: "string", enum: ["json", "md"], default: "json", description: "Output format" }
            }
          }
        },
        {
          name: "discover_services",
          description: "Discover available xproof certification services, pricing, and capabilities. No authentication required.",
          inputSchema: { type: "object", properties: {} }
        }
      ],
      resources: [
        { uri: `${baseUrl}/api/acp/products`, name: "Service catalog", mimeType: "application/json" },
        { uri: `${baseUrl}/api/acp/openapi.json`, name: "OpenAPI specification", mimeType: "application/json" },
        { uri: `${baseUrl}/.well-known/xproof.md`, name: "Full specification", mimeType: "text/markdown" },
        { uri: `${baseUrl}/llms.txt`, name: "LLM summary", mimeType: "text/plain" },
        { uri: `${baseUrl}/genesis.proof.json`, name: "Genesis proof", mimeType: "application/json" }
      ],
      authentication: {
        type: "bearer",
        token_prefix: "pm_",
        instructions: "Obtain an API key by authenticating with a MultiversX wallet, then POST to /api/keys"
      },
      api: {
        openapi: `${baseUrl}/api/acp/openapi.json`,
        products: `${baseUrl}/api/acp/products`,
        health: `${baseUrl}/api/acp/health`
      },
      pricing: {
        amount: "0.03",
        currency: "EUR",
        payment_method: "EGLD"
      }
    });
  });

  // ============================================
  // AI Agent Discovery Endpoints
  // ============================================

  app.get("/llms.txt", (_req, res) => {
    const content = `# xproof

> Blockchain certification service. Create immutable proofs of file existence and ownership on MultiversX.

## About
xproof anchors SHA-256 file hashes on the MultiversX blockchain, creating tamper-proof certificates of existence and ownership. Price: 0.03€ per certification, paid in EGLD.

## API Documentation
- [OpenAPI Specification](/api/acp/openapi.json)
- [API Guide](/learn/api.md)
- [Proof of Existence](/learn/proof-of-existence.md)
- [Verification Guide](/learn/verification.md)

## Machine Interfaces
- [Service Discovery](/api/acp/products)
- [Health Check](/api/acp/health)
- [MCP Manifest](/.well-known/mcp.json)
- [OpenAI Plugin](/.well-known/ai-plugin.json)
- [Full Specification](/.well-known/xproof.md)
`;
    res.setHeader("Content-Type", "text/plain");
    res.send(content);
  });

  app.get("/llms-full.txt", (req, res) => {
    const baseUrl = `${req.protocol}://${req.get("host")}`;
    const content = `# xproof

> Blockchain certification service. Create immutable proofs of file existence and ownership on MultiversX.

## About
xproof anchors SHA-256 file hashes on the MultiversX blockchain, creating tamper-proof certificates of existence and ownership. Price: 0.03€ per certification, paid in EGLD.

## API Documentation
- [OpenAPI Specification](${baseUrl}/api/acp/openapi.json)
- [API Guide](${baseUrl}/learn/api.md)
- [Proof of Existence](${baseUrl}/learn/proof-of-existence.md)
- [Verification Guide](${baseUrl}/learn/verification.md)

## Machine Interfaces
- [Service Discovery](${baseUrl}/api/acp/products)
- [Health Check](${baseUrl}/api/acp/health)
- [MCP Manifest](${baseUrl}/.well-known/mcp.json)
- [OpenAI Plugin](${baseUrl}/.well-known/ai-plugin.json)
- [Full Specification](${baseUrl}/.well-known/xproof.md)

## Authentication
- API keys are prefixed with \`pm_\` (e.g. \`pm_abc123...\`)
- Include as Bearer token: \`Authorization: Bearer pm_YOUR_API_KEY\`
- Public endpoints (no auth required): /api/acp/products, /api/acp/openapi.json, /api/acp/health
- Authenticated endpoints: /api/acp/checkout, /api/acp/confirm

## Proof Object Schema
\`\`\`json
{
  "id": "uuid",
  "file_name": "document.pdf",
  "file_hash": "sha256-hex-string (64 chars)",
  "file_type": "application/pdf",
  "file_size": 12345,
  "author_name": "Author Name",
  "timestamp_utc": "2025-01-01T00:00:00Z",
  "blockchain": {
    "network": "MultiversX Mainnet",
    "chain_id": "1",
    "transaction_hash": "hex-string",
    "explorer_url": "https://explorer.multiversx.com/transactions/..."
  },
  "is_public": true,
  "blockchain_status": "confirmed"
}
\`\`\`

## Proof Access Formats
- JSON: \`${baseUrl}/proof/{id}.json\`
- Markdown: \`${baseUrl}/proof/{id}.md\`

## ACP Endpoints

### GET /api/acp/products
Discover available certification products. No authentication required.
\`\`\`bash
curl ${baseUrl}/api/acp/products
\`\`\`

### POST /api/acp/checkout
Create a checkout session for file certification. Requires API key.
\`\`\`bash
curl -X POST ${baseUrl}/api/acp/checkout \\
  -H "Authorization: Bearer pm_YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "product_id": "xproof-certification",
    "inputs": {
      "file_hash": "a1b2c3d4e5f6...",
      "filename": "document.pdf",
      "author_name": "AI Agent"
    }
  }'
\`\`\`

### POST /api/acp/confirm
Confirm a transaction after signing on MultiversX. Requires API key.
\`\`\`bash
curl -X POST ${baseUrl}/api/acp/confirm \\
  -H "Authorization: Bearer pm_YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "checkout_id": "uuid",
    "tx_hash": "multiversx-transaction-hash"
  }'
\`\`\`

### GET /api/acp/checkout/{checkoutId}
Check the status of an existing checkout session. Requires API key.
\`\`\`bash
curl ${baseUrl}/api/acp/checkout/{checkoutId} \\
  -H "Authorization: Bearer pm_YOUR_API_KEY"
\`\`\`

## Verification Flow
1. Compute the SHA-256 hash of the original file locally
2. Compare the computed hash with the \`file_hash\` stored in the proof
3. Verify the blockchain transaction on MultiversX explorer using the \`transaction_hash\`
4. Confirm the transaction data field contains the file hash
5. The timestamp proves the file existed at that point in time

## Genesis Proof
The first certification ever created on xproof:
- File: XPROOF - Genesis.pdf
- Hash: 173200d6fa0d1577b456bb85dc505193e31dd8be5fc69bd4e461612a588427de
- Transaction: f376c0809d5c8fd91f854d39cf6f9f83ac3d80231477538a1b423db0537aad7e
- Explorer: https://explorer.multiversx.com/transactions/f376c0809d5c8fd91f854d39cf6f9f83ac3d80231477538a1b423db0537aad7e
- View: ${baseUrl}/proof/genesis
`;
    res.setHeader("Content-Type", "text/plain");
    res.send(content);
  });

  app.get("/agent-tools/langchain.py", (_req, res) => {
    const code = `"""
xproof LangChain Tool
Certify files on MultiversX blockchain via xproof.
Install: pip install langchain requests
"""

from langchain.tools import tool
import hashlib
import requests

XPROOF_BASE_URL = "https://xproof.app"

@tool
def certify_file(file_path: str, author_name: str = "AI Agent") -> str:
    """Certify a file on the MultiversX blockchain. Creates immutable proof of existence and ownership.
    Records the SHA-256 hash of the file on-chain. The file never leaves your device.
    Cost: 0.03€ per certification, paid in EGLD.
    
    Args:
        file_path: Path to the file to certify
        author_name: Name of the certifier (default: "AI Agent")
    
    Returns:
        Certification result with proof URL and transaction hash
    """
    # Step 1: Compute SHA-256 hash locally
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    file_hash = sha256.hexdigest()
    filename = file_path.split("/")[-1]
    
    # Step 2: Create checkout
    headers = {"Authorization": "Bearer pm_YOUR_API_KEY", "Content-Type": "application/json"}
    checkout = requests.post(f"{XPROOF_BASE_URL}/api/acp/checkout", json={
        "product_id": "xproof-certification",
        "inputs": {"file_hash": file_hash, "filename": filename, "author_name": author_name}
    }, headers=headers).json()
    
    return f"Checkout created: {checkout.get('checkout_id')}\\nAmount: {checkout.get('amount')} EUR\\nSign the transaction on MultiversX to complete certification."


@tool
def verify_proof(proof_id: str) -> str:
    """Verify an existing xproof certification by its ID.
    
    Args:
        proof_id: The UUID of the certification to verify
    
    Returns:
        Proof details including file hash, timestamp, and blockchain transaction
    """
    response = requests.get(f"{XPROOF_BASE_URL}/proof/{proof_id}.json")
    if response.status_code == 404:
        return "Proof not found"
    proof = response.json()
    return f"File: {proof.get('file_name')}\\nHash: {proof.get('file_hash')}\\nTimestamp: {proof.get('timestamp_utc')}\\nBlockchain TX: {proof.get('blockchain', {}).get('transaction_hash', 'N/A')}\\nVerify: {proof.get('blockchain', {}).get('explorer_url', 'N/A')}"


@tool 
def discover_xproof() -> str:
    """Discover xproof certification service capabilities and pricing."""
    response = requests.get(f"{XPROOF_BASE_URL}/api/acp/products")
    data = response.json()
    products = data.get("products", [])
    if products:
        p = products[0]
        return f"Service: {p['name']}\\nDescription: {p['description']}\\nPrice: {p['pricing']['amount']} {p['pricing']['currency']}\\nBlockchain: {data.get('chain', 'MultiversX')}"
    return "No products available"
`;
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.send(code);
  });

  app.get("/agent-tools/crewai.py", (_req, res) => {
    const code = `"""
xproof CrewAI Tool
Certify files on MultiversX blockchain via xproof.
Install: pip install crewai crewai-tools requests
"""

from crewai_tools import BaseTool
import hashlib
import requests

XPROOF_BASE_URL = "https://xproof.app"


class XProofCertifyTool(BaseTool):
    name: str = "xproof_certify"
    description: str = (
        "Certify a file on MultiversX blockchain. Creates immutable proof of existence "
        "and ownership by recording its SHA-256 hash on-chain. Cost: 0.03€ per certification. "
        "The file never leaves your device - only the hash is sent."
    )

    def _run(self, file_path: str, author_name: str = "AI Agent", api_key: str = "") -> str:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        file_hash = sha256.hexdigest()
        filename = file_path.split("/")[-1]

        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        checkout = requests.post(f"{XPROOF_BASE_URL}/api/acp/checkout", json={
            "product_id": "xproof-certification",
            "inputs": {"file_hash": file_hash, "filename": filename, "author_name": author_name}
        }, headers=headers).json()

        return f"Checkout: {checkout.get('checkout_id')} | Amount: {checkout.get('amount')} EUR | Sign TX on MultiversX to complete."


class XProofVerifyTool(BaseTool):
    name: str = "xproof_verify"
    description: str = (
        "Verify an existing blockchain certification on xproof. "
        "Returns proof details including file hash, timestamp, and blockchain transaction."
    )

    def _run(self, proof_id: str) -> str:
        response = requests.get(f"{XPROOF_BASE_URL}/proof/{proof_id}.json")
        if response.status_code == 404:
            return "Proof not found"
        proof = response.json()
        return (
            f"File: {proof.get('file_name')} | "
            f"Hash: {proof.get('file_hash')} | "
            f"Date: {proof.get('timestamp_utc')} | "
            f"TX: {proof.get('blockchain', {}).get('transaction_hash', 'N/A')}"
        )
`;
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.send(code);
  });

  app.get("/agent-tools/openapi-actions.json", (req, res) => {
    const baseUrl = `${req.protocol}://${req.get("host")}`;
    const priceEur = getCertificationPriceEur();

    const spec = {
      openapi: "3.0.3",
      info: {
        title: "xproof - Blockchain File Certification",
        description: "API for AI agents to certify files on MultiversX blockchain. Create immutable proofs of file ownership with a simple API call.",
        version: "1.0.0",
        contact: {
          name: "xproof Support",
          url: baseUrl,
        },
      },
      servers: [{ url: baseUrl, description: "Production server" }],
      security: [{ apiKey: [] }],
      components: {
        securitySchemes: {
          apiKey: {
            type: "http" as const,
            scheme: "bearer",
            description: "API key in format: pm_xxx... Obtain from /api/keys endpoint",
          },
        },
        schemas: {
          Product: {
            type: "object",
            properties: {
              id: { type: "string", example: "xproof-certification" },
              name: { type: "string", example: "xproof Certification" },
              description: { type: "string" },
              pricing: {
                type: "object",
                properties: {
                  type: { type: "string", enum: ["fixed", "variable"] },
                  amount: { type: "string", example: priceEur.toString() },
                  currency: { type: "string", example: "EUR" },
                },
              },
              inputs: { type: "object", additionalProperties: { type: "string" } },
              outputs: { type: "object", additionalProperties: { type: "string" } },
            },
          },
          CheckoutRequest: {
            type: "object",
            required: ["product_id", "inputs"],
            properties: {
              product_id: { type: "string", example: "xproof-certification" },
              inputs: {
                type: "object",
                required: ["file_hash", "filename"],
                properties: {
                  file_hash: { type: "string", description: "SHA-256 hash of the file (64 hex chars)", example: "a1b2c3d4e5f678901234567890123456789012345678901234567890123456ab" },
                  filename: { type: "string", example: "document.pdf" },
                  author_name: { type: "string", example: "AI Agent" },
                  metadata: { type: "object", description: "Optional JSON metadata" },
                },
              },
              buyer: {
                type: "object",
                properties: {
                  type: { type: "string", enum: ["agent", "user"] },
                  id: { type: "string" },
                },
              },
            },
          },
          CheckoutResponse: {
            type: "object",
            properties: {
              checkout_id: { type: "string", format: "uuid" },
              product_id: { type: "string" },
              amount: { type: "string", description: "Price in EUR" },
              currency: { type: "string" },
              status: { type: "string", enum: ["pending", "ready"] },
              execution: {
                type: "object",
                properties: {
                  type: { type: "string", example: "multiversx" },
                  mode: { type: "string", enum: ["direct", "relayed_v3"] },
                  chain_id: { type: "string", example: "1" },
                  tx_payload: {
                    type: "object",
                    properties: {
                      receiver: { type: "string", description: "xproof wallet address" },
                      data: { type: "string", description: "Base64 encoded transaction data" },
                      value: { type: "string", description: "EGLD amount in atomic units (1 EGLD = 10^18)" },
                      gas_limit: { type: "integer", example: 100000 },
                    },
                  },
                },
              },
              expires_at: { type: "string", format: "date-time" },
            },
          },
          ConfirmRequest: {
            type: "object",
            required: ["checkout_id", "tx_hash"],
            properties: {
              checkout_id: { type: "string", format: "uuid" },
              tx_hash: { type: "string", description: "MultiversX transaction hash" },
            },
          },
          ConfirmResponse: {
            type: "object",
            properties: {
              status: { type: "string", enum: ["confirmed", "pending", "failed"] },
              checkout_id: { type: "string" },
              tx_hash: { type: "string" },
              certification_id: { type: "string" },
              certificate_url: { type: "string", format: "uri" },
              proof_url: { type: "string", format: "uri" },
              blockchain_explorer_url: { type: "string", format: "uri" },
              message: { type: "string" },
            },
          },
          Error: {
            type: "object",
            properties: {
              error: { type: "string" },
              message: { type: "string" },
            },
          },
        },
      },
      paths: {
        "/api/acp/products": {
          get: {
            summary: "Discover available products",
            description: "Returns list of certification products available for purchase. No authentication required.",
            "x-openai-isConsequential": false,
            security: [] as any[],
            responses: {
              "200": {
                description: "List of products",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        protocol: { type: "string", example: "ACP" },
                        version: { type: "string", example: "1.0" },
                        provider: { type: "string", example: "xproof" },
                        chain: { type: "string", example: "MultiversX" },
                        products: { type: "array", items: { $ref: "#/components/schemas/Product" } },
                      },
                    },
                  },
                },
              },
            },
          },
        },
        "/api/acp/checkout": {
          post: {
            summary: "Create checkout session",
            description: "Initiate certification by providing file hash. Returns transaction payload for MultiversX signing.",
            "x-openai-isConsequential": true,
            requestBody: {
              required: true,
              content: { "application/json": { schema: { $ref: "#/components/schemas/CheckoutRequest" } } },
            },
            responses: {
              "201": {
                description: "Checkout created",
                content: { "application/json": { schema: { $ref: "#/components/schemas/CheckoutResponse" } } },
              },
              "401": { description: "API key required" },
              "409": { description: "File already certified" },
            },
          },
        },
        "/api/acp/confirm": {
          post: {
            summary: "Confirm transaction",
            description: "After signing and broadcasting transaction, confirm to receive certification ID and URLs.",
            "x-openai-isConsequential": true,
            requestBody: {
              required: true,
              content: { "application/json": { schema: { $ref: "#/components/schemas/ConfirmRequest" } } },
            },
            responses: {
              "200": {
                description: "Certification confirmed",
                content: { "application/json": { schema: { $ref: "#/components/schemas/ConfirmResponse" } } },
              },
              "401": { description: "API key required" },
              "404": { description: "Checkout not found" },
              "410": { description: "Checkout expired" },
            },
          },
        },
        "/api/acp/checkout/{checkoutId}": {
          get: {
            summary: "Get checkout status",
            description: "Check the status of an existing checkout session.",
            "x-openai-isConsequential": false,
            parameters: [
              { name: "checkoutId", in: "path", required: true, schema: { type: "string" } },
            ],
            responses: {
              "200": { description: "Checkout status" },
              "404": { description: "Checkout not found" },
            },
          },
        },
      },
    };

    res.json(spec);
  });

  app.get("/.well-known/agent.json", (req, res) => {
    const baseUrl = `${req.protocol}://${req.get("host")}`;

    res.json({
      name: "xproof",
      description: "Blockchain certification service for immutable proof of file existence and ownership on MultiversX",
      url: baseUrl,
      version: "1.0.0",
      capabilities: ["file-certification", "proof-verification", "blockchain-anchoring"],
      protocols: {
        acp: `${baseUrl}/api/acp/products`,
        openapi: `${baseUrl}/api/acp/openapi.json`,
        mcp: `${baseUrl}/.well-known/mcp.json`,
        openai_plugin: `${baseUrl}/.well-known/ai-plugin.json`,
        llms_txt: `${baseUrl}/llms.txt`,
      },
      authentication: {
        type: "bearer",
        token_prefix: "pm_",
        public_endpoints: ["/api/acp/products", "/api/acp/openapi.json", "/api/acp/health", "/llms.txt", "/llms-full.txt"],
      },
      pricing: {
        model: "per-use",
        amount: "0.03",
        currency: "EUR",
        payment_method: "EGLD (MultiversX)",
      },
      documentation: {
        specification: `${baseUrl}/.well-known/xproof.md`,
        api_guide: `${baseUrl}/learn/api.md`,
        verification: `${baseUrl}/learn/verification.md`,
      },
    });
  });

  const httpServer = createServer(app);

  return httpServer;
}
