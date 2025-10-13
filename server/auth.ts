import { type Express, type Request, type Response, type NextFunction } from "express";
import session from "express-session";
import createMemoryStore from "memorystore";
import { db } from "./db";
import { users } from "@shared/schema";
import { eq } from "drizzle-orm";

const MemoryStore = createMemoryStore(session);

// Extend Express User type
declare global {
  namespace Express {
    interface User {
      id: string;
      email?: string | null;
      firstName?: string | null;
      lastName?: string | null;
      profileImageUrl?: string | null;
    }
  }
}

// Simple auth middleware to check if user is authenticated
function isAuthenticated(req: Request): boolean {
  return !!req.session?.userId;
}

// Middleware to require authentication
export function requireAuth(req: Request, res: Response, next: NextFunction) {
  if (!isAuthenticated(req)) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  next();
}

export async function setupAuth(app: Express) {
  // Session middleware
  app.use(
    session({
      store: new MemoryStore({
        checkPeriod: 86400000,
      }),
      secret: process.env.SESSION_SECRET || "your-secret-key",
      resave: false,
      saveUninitialized: false,
      cookie: {
        secure: process.env.NODE_ENV === "production",
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 24 * 7, // 1 week
      },
    })
  );

  // Attach user to request
  app.use(async (req: Request, res: Response, next: NextFunction) => {
    if (req.session?.userId) {
      try {
        const [user] = await db.select().from(users).where(eq(users.id, req.session.userId));
        if (user) {
          req.user = {
            id: user.id,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName,
            profileImageUrl: user.profileImageUrl,
          };
        }
      } catch (error) {
        console.error("Error loading user:", error);
      }
    }
    next();
  });

  // Mock login endpoint (for development)
  // In production, this would be replaced with proper Replit Auth
  app.get("/api/login", async (req, res) => {
    try {
      // Create or get a test user
      const testEmail = "test@proofmint.com";
      let [user] = await db.select().from(users).where(eq(users.email, testEmail));
      
      if (!user) {
        [user] = await db.insert(users).values({
          email: testEmail,
          firstName: "Test",
          lastName: "User",
          subscriptionTier: "free",
          subscriptionStatus: "active",
          monthlyUsage: 0,
        }).returning();
      }

      req.session.userId = user.id;
      res.redirect("/dashboard");
    } catch (error) {
      console.error("Login error:", error);
      res.status(500).json({ message: "Login failed" });
    }
  });

  app.get("/api/auth/callback", (req, res) => {
    res.redirect("/dashboard");
  });

  app.get("/api/logout", (req, res) => {
    req.session.destroy(() => {
      res.redirect("/");
    });
  });

  // Get current user endpoint
  app.get("/api/auth/user", async (req, res) => {
    if (!req.session?.userId) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    try {
      const [user] = await db
        .select()
        .from(users)
        .where(eq(users.id, req.session.userId));

      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      res.json(user);
    } catch (error) {
      res.status(500).json({ message: "Internal server error" });
    }
  });
}

// Extend session type
declare module 'express-session' {
  interface SessionData {
    userId: string;
  }
}
