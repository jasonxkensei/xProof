import { type Express } from "express";
import crypto from "crypto";
import { db } from "../db";
import { logger } from "../logger";
import { users } from "@shared/schema";
import { eq } from "drizzle-orm";
import { isWalletAuthenticated, createWalletSession, destroyWalletSession } from "../walletAuth";
import { authRateLimiter } from "../reliability";

export function registerAuthRoutes(app: Express) {
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
  app.post("/api/auth/wallet/sync", authRateLimiter, async (req, res) => {
    try {
      const { verifyNativeAuthToken, extractBearerToken } = await import("../nativeAuth");
      
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
        const regIp = req.headers["x-forwarded-for"]?.toString().split(",")[0]?.trim() || req.ip || "unknown";
        const regIpHash = crypto.createHash("sha256").update(regIp).digest("hex");
        [user] = await db
          .insert(users)
          .values({
            walletAddress,
            subscriptionTier: "free",
            subscriptionStatus: "active",
            monthlyUsage: 0,
            usageResetDate: new Date(),
            registrationIpHash: regIpHash,
          })
          .returning();
      }

      // Create wallet session (now cryptographically verified)
      await createWalletSession(req, walletAddress);

      res.json(user);
    } catch (error: any) {
      logger.withRequest(req).error("Wallet sync failed", { error: error.message });
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

      logger.withRequest(req).info("Simple wallet sync", { walletAddress });

      // Check if user exists, create if not
      let [user] = await db.select().from(users).where(eq(users.walletAddress, walletAddress));

      if (!user) {
        // Create new user with free tier
        const regIp2 = req.headers["x-forwarded-for"]?.toString().split(",")[0]?.trim() || req.ip || "unknown";
        const regIpHash2 = crypto.createHash("sha256").update(regIp2).digest("hex");
        [user] = await db
          .insert(users)
          .values({
            walletAddress,
            subscriptionTier: "free",
            subscriptionStatus: "active",
            monthlyUsage: 0,
            usageResetDate: new Date(),
            registrationIpHash: regIpHash2,
          })
          .returning();
      }

      // Create wallet session
      await createWalletSession(req, walletAddress);

      res.json(user);
    } catch (error: any) {
      logger.withRequest(req).error("Simple wallet sync failed", { error: error.message });
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
      
      // Check if user is admin
      const adminWallets = (process.env.ADMIN_WALLETS || "").split(",").map(w => w.trim()).filter(Boolean);
      const isAdmin = adminWallets.includes(walletAddress || "");
      
      res.json({ ...user, isAdmin });
    } catch (error) {
      logger.withRequest(req).error("Failed to fetch current user");
      res.status(500).json({ message: "Failed to fetch user" });
    }
  });

  // Logout endpoint
  app.post("/api/auth/logout", async (req, res) => {
    try {
      await destroyWalletSession(req);
      res.json({ message: "Logged out successfully" });
    } catch (error: any) {
      logger.withRequest(req).error("Logout failed");
      res.status(500).json({ message: "Failed to log out" });
    }
  });
}
