import express, { type Express } from "express";
import { createServer, type Server } from "http";
import { db } from "./db";
import { storage } from "./storage";
import { certifications, users, SUBSCRIPTION_TIERS } from "@shared/schema";
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
  
  // DEPRECATED: Insecure webhook-based login (no proper signature verification)
  // This endpoint is disabled for security reasons. Use /api/auth/verify instead.
  app.post("/api/auth/wallet/login", async (req, res) => {
    console.warn("⚠️  Attempt to use deprecated insecure auth endpoint");
    return res.status(410).json({ 
      message: "This authentication method is deprecated for security reasons. Please use the secure signature-based authentication via /api/auth/challenge and /api/auth/verify.",
      error: "INSECURE_AUTH_METHOD_DISABLED"
    });
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

  // Generate authentication challenge for wallet
  app.post("/api/auth/challenge", (req, res) => {
    try {
      const { walletAddress } = req.body;

      if (!walletAddress || !walletAddress.startsWith("erd1")) {
        return res.status(400).json({ message: "Invalid MultiversX wallet address" });
      }

      const nonce = generateChallenge(walletAddress);
      const message = `ProofMint Login\n\nSign this message to authenticate.\n\nNonce: ${nonce}`;
      
      res.json({ nonce, message });
    } catch (error: any) {
      console.error("Error generating challenge:", error);
      res.status(500).json({ message: "Failed to generate challenge" });
    }
  });

  // Verify wallet signature and create session
  app.post("/api/auth/verify", async (req, res) => {
    try {
      const { walletAddress, signature, nonce } = req.body;

      if (!walletAddress || !signature || !nonce) {
        return res.status(400).json({ message: "Missing required fields" });
      }

      // Verify signature
      const isValid = verifyWalletSignature(walletAddress, signature, nonce);
      
      if (!isValid) {
        return res.status(401).json({ message: "Invalid signature" });
      }

      // Check if user exists, create if not
      let [user] = await db.select().from(users).where(eq(users.walletAddress, walletAddress));

      if (!user) {
        // Create new user
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

      res.json({ user, message: "Authentication successful" });
    } catch (error: any) {
      console.error("Error verifying signature:", error);
      res.status(500).json({ message: "Failed to verify signature" });
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

  // Get current user endpoint
  app.get('/api/auth/user', isWalletAuthenticated, async (req: any, res) => {
    try {
      const walletAddress = req.walletAddress;
      const [user] = await db.select().from(users).where(eq(users.walletAddress, walletAddress));
      
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      
      res.json(user);
    } catch (error) {
      console.error("Error fetching user:", error);
      res.status(500).json({ message: "Failed to fetch user" });
    }
  });

  // Update user branding (Business tier only)
  app.patch('/api/user/branding', isWalletAuthenticated, async (req: any, res) => {
    try {
      const walletAddress = req.walletAddress;
      const { companyName, companyLogoUrl } = req.body;

      // Get user to check subscription tier
      const [user] = await db.select().from(users).where(eq(users.walletAddress, walletAddress));
      
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // Check if user has Business tier
      if (user.subscriptionTier !== 'business') {
        return res.status(403).json({ 
          message: "Custom branding is only available for Business tier. Please upgrade your subscription.",
          requiredTier: "business",
          currentTier: user.subscriptionTier
        });
      }

      // Validate input
      const schema = z.object({
        companyName: z.string().min(1).max(100),
        companyLogoUrl: z.string().url().optional().or(z.literal("")),
      });

      const validatedData = schema.parse({ companyName, companyLogoUrl });

      // Update user branding
      await db
        .update(users)
        .set({
          companyName: validatedData.companyName,
          companyLogoUrl: validatedData.companyLogoUrl || null,
        })
        .where(eq(users.walletAddress, walletAddress));

      res.json({ message: "Branding updated successfully" });
    } catch (error) {
      console.error("Error updating branding:", error);
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: error.errors[0].message });
      }
      res.status(500).json({ message: "Failed to update branding" });
    }
  });

  // Create certification
  app.post("/api/certifications", isWalletAuthenticated, async (req: any, res) => {
    try {
      const walletAddress = req.walletAddress;

      // Get user to check subscription limits
      const [user] = await db.select().from(users).where(eq(users.walletAddress, walletAddress));
      
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // Check if usage needs to be reset (monthly)
      const now = new Date();
      const resetDate = new Date(user.usageResetDate!);
      if (now.getMonth() !== resetDate.getMonth() || now.getFullYear() !== resetDate.getFullYear()) {
        // Reset monthly usage
        await db
          .update(users)
          .set({ monthlyUsage: 0, usageResetDate: now })
          .where(eq(users.walletAddress, walletAddress));
        user.monthlyUsage = 0;
      }

      // Check subscription limits
      const tier = user.subscriptionTier as keyof typeof SUBSCRIPTION_TIERS;
      const limit = SUBSCRIPTION_TIERS[tier].monthlyLimit;
      
      if ((user.monthlyUsage || 0) >= limit) {
        return res.status(403).json({
          message: `Monthly limit reached. Upgrade your plan to certify more files.`,
          limit,
          usage: user.monthlyUsage,
        });
      }

      // Validate request body
      const schema = z.object({
        fileName: z.string().min(1),
        fileHash: z.string().min(1),
        fileType: z.string().optional(),
        fileSize: z.number().optional(),
        authorName: z.string().min(1),
        authorSignature: z.string().optional(),
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

      // Record on blockchain with file metadata
      const { transactionHash, transactionUrl } = await recordOnBlockchain(
        data.fileHash,
        data.fileName,
        data.authorName
      );

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

      // Increment monthly usage
      await db
        .update(users)
        .set({ monthlyUsage: (user.monthlyUsage || 0) + 1 })
        .where(eq(users.walletAddress, walletAddress));

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
        
        // Get user to check subscription limits
        const [user] = await db.select().from(users).where(eq(users.walletAddress, walletAddress));

        if (!user) {
          return res.status(404).json({ message: "User not found" });
        }

        // Check if usage needs to be reset (monthly)
        const now = new Date();
        const resetDate = new Date(user.usageResetDate!);
        if (now.getMonth() !== resetDate.getMonth() || now.getFullYear() !== resetDate.getFullYear()) {
          // Reset monthly usage
          await db
            .update(users)
            .set({ monthlyUsage: 0, usageResetDate: now })
            .where(eq(users.walletAddress, walletAddress));
          user.monthlyUsage = 0;
        }

        // Check subscription limits
        const tier = user.subscriptionTier as keyof typeof SUBSCRIPTION_TIERS;
        const limit = SUBSCRIPTION_TIERS[tier].monthlyLimit;
        
        if ((user.monthlyUsage || 0) >= limit) {
          return res.status(403).json({
            message: `Monthly limit reached. Upgrade your plan to certify more files.`,
            limit,
            usage: user.monthlyUsage,
          });
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

        // Increment monthly usage
        await db
          .update(users)
          .set({ monthlyUsage: (user.monthlyUsage || 0) + 1 })
          .where(eq(users.walletAddress, walletAddress));

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

      // Generate PDF
      const pdfBuffer = await generateCertificatePDF({
        certification,
        subscriptionTier: user.subscriptionTier || 'free',
        companyName: user.companyName || undefined,
        companyLogoUrl: user.companyLogoUrl || undefined,
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

  const httpServer = createServer(app);

  return httpServer;
}
