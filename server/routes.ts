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
    
    // Allow unauthenticated access to /products and /openapi.json (discovery)
    // Note: req.path is relative to mount point, so /api/acp/products becomes /products
    if (req.path === "/products" || req.path === "/openapi.json") {
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
  // and use ProofMint certification services
  // ============================================

  // ACP Products Discovery - Returns available services for AI agents
  app.get("/api/acp/products", async (req, res) => {
    const priceEur = getCertificationPriceEur();
    
    const products: ACPProduct[] = [
      {
        id: "proofmint-certification",
        name: "ProofMint Certification",
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
      provider: "ProofMint",
      chain: "MultiversX",
      products 
    });
  });

  // ACP Checkout - Agent initiates certification
  app.post("/api/acp/checkout", async (req, res) => {
    try {
      const data = acpCheckoutRequestSchema.parse(req.body);

      // Validate product exists
      if (data.product_id !== "proofmint-certification") {
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
      
      // ProofMint wallet address (receives certification fees)
      const proofmintWallet = process.env.PROOFMINT_WALLET_ADDRESS || process.env.MULTIVERSX_SENDER_ADDRESS;
      if (!proofmintWallet) {
        console.error("⚠️ No PROOFMINT_WALLET_ADDRESS configured");
        return res.status(500).json({
          error: "CONFIGURATION_ERROR",
          message: "ProofMint wallet not configured",
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
            receiver: proofmintWallet,
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
        title: "ProofMint ACP - Agent Commerce Protocol",
        description: "API for AI agents to certify files on MultiversX blockchain. Create immutable proofs of file ownership with a simple API call.",
        version: "1.0.0",
        contact: {
          name: "ProofMint Support",
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
              id: { type: "string", example: "proofmint-certification" },
              name: { type: "string", example: "ProofMint Certification" },
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
              product_id: { type: "string", example: "proofmint-certification" },
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
                      receiver: { type: "string", description: "ProofMint wallet address" },
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
                        provider: { type: "string", example: "ProofMint" },
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

  const httpServer = createServer(app);

  return httpServer;
}
