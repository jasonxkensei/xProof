import express, { type Express } from "express";
import { createServer, type Server } from "http";
import { setupAuth, isAuthenticated } from "./replitAuth";
import { db } from "./db";
import { storage } from "./storage";
import { certifications, users, SUBSCRIPTION_TIERS } from "@shared/schema";
import { eq, desc } from "drizzle-orm";
import { z } from "zod";
import Stripe from "stripe";

if (!process.env.STRIPE_SECRET_KEY) {
  throw new Error("Missing STRIPE_SECRET_KEY environment variable");
}

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, {
  apiVersion: "2024-12-18.acacia",
});

// MultiversX blockchain integration
async function recordOnBlockchain(fileHash: string): Promise<{
  transactionHash: string;
  transactionUrl: string;
}> {
  // TODO: Integrate with MultiversX API
  // For now, we'll simulate the blockchain transaction
  // In production, this would call the MultiversX REST API
  
  // Simulated transaction hash (in production, this comes from MultiversX)
  const transactionHash = `tx_${Date.now()}_${fileHash.substring(0, 8)}`;
  const transactionUrl = `https://explorer.multiversx.com/transactions/${transactionHash}`;
  
  return {
    transactionHash,
    transactionUrl,
  };
}

// Certificate generation (placeholder)
async function generateCertificate(certificationId: string): Promise<string> {
  // TODO: Implement PDF certificate generation with QR code
  // For now, return a placeholder URL
  return `/api/certificates/${certificationId}.pdf`;
}

export async function registerRoutes(app: Express): Promise<Server> {
  // Setup authentication first
  await setupAuth(app);

  // Get current user endpoint
  app.get('/api/auth/user', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      res.json(user);
    } catch (error) {
      console.error("Error fetching user:", error);
      res.status(500).json({ message: "Failed to fetch user" });
    }
  });

  // Create certification
  app.post("/api/certifications", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;

      // Get user to check subscription limits
      const [user] = await db.select().from(users).where(eq(users.id, userId));
      
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
          .where(eq(users.id, userId));
        user.monthlyUsage = 0;
      }

      // Check subscription limits
      const tier = user.subscriptionTier as keyof typeof SUBSCRIPTION_TIERS;
      const limit = SUBSCRIPTION_TIERS[tier].monthlyLimit;
      
      if (user.monthlyUsage >= limit) {
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

      // Record on blockchain
      const { transactionHash, transactionUrl } = await recordOnBlockchain(data.fileHash);

      // Create certification
      const [certification] = await db
        .insert(certifications)
        .values({
          userId,
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

      // Generate certificate
      const certificateUrl = await generateCertificate(certification.id);
      
      await db
        .update(certifications)
        .set({ certificateUrl })
        .where(eq(certifications.id, certification.id));

      // Increment monthly usage
      await db
        .update(users)
        .set({ monthlyUsage: user.monthlyUsage + 1 })
        .where(eq(users.id, userId));

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
  app.get("/api/certifications", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const userCertifications = await db
        .select()
        .from(certifications)
        .where(eq(certifications.userId, userId))
        .orderBy(desc(certifications.createdAt));

      res.json(userCertifications);
    } catch (error) {
      console.error("Error fetching certifications:", error);
      res.status(500).json({ message: "Failed to fetch certifications" });
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

  // Download certificate (placeholder)
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

      // TODO: Generate and serve PDF
      res.status(501).json({ message: "PDF generation not yet implemented" });
    } catch (error) {
      console.error("Error downloading certificate:", error);
      res.status(500).json({ message: "Failed to download certificate" });
    }
  });

  // Create subscription
  app.post("/api/create-subscription", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { plan } = req.body;

      if (!["pro", "business"].includes(plan)) {
        return res.status(400).json({ message: "Invalid plan" });
      }

      const [user] = await db.select().from(users).where(eq(users.id, userId));
      
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // Create or get Stripe customer
      let customerId = user.stripeCustomerId;
      
      if (!customerId) {
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
          .where(eq(users.id, userId));
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
      const paymentIntent = invoice.payment_intent as Stripe.PaymentIntent;

      // Update user subscription info
      await db
        .update(users)
        .set({
          stripeSubscriptionId: subscription.id,
          subscriptionTier: plan,
          subscriptionStatus: subscription.status,
        })
        .where(eq(users.id, userId));

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

  const httpServer = createServer(app);

  return httpServer;
}
