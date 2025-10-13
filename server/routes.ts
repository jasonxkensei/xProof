import express, { type Express } from "express";
import { createServer, type Server } from "http";
import { setupAuth, isAuthenticated } from "./replitAuth";
import { db } from "./db";
import { storage } from "./storage";
import { certifications, users, SUBSCRIPTION_TIERS } from "@shared/schema";
import { eq, desc } from "drizzle-orm";
import { z } from "zod";
import Stripe from "stripe";
import { generateCertificatePDF } from "./certificateGenerator";

const stripeSecretKey = process.env.TESTING_STRIPE_SECRET_KEY || process.env.STRIPE_SECRET_KEY;
if (!stripeSecretKey) {
  throw new Error("Missing STRIPE_SECRET_KEY or TESTING_STRIPE_SECRET_KEY environment variable");
}

const stripe = new Stripe(stripeSecretKey, {
  apiVersion: "2025-09-30.clover",
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

  // Update user branding (Business tier only)
  app.patch('/api/user/branding', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { companyName, companyLogoUrl } = req.body;

      // Get user to check subscription tier
      const [user] = await db.select().from(users).where(eq(users.id, userId));
      
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
        .where(eq(users.id, userId));

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

      // Certificate will be generated on-demand when downloaded
      const certificateUrl = `/api/certificates/${certification.id}.pdf`;

      // Increment monthly usage
      await db
        .update(users)
        .set({ monthlyUsage: (user.monthlyUsage || 0) + 1 })
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
        console.log('Creating Stripe customer for user:', userId);
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
      const paymentIntent = (invoice as any).payment_intent as Stripe.PaymentIntent;

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
