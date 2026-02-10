import { sql } from 'drizzle-orm';
import {
  index,
  jsonb,
  pgTable,
  timestamp,
  varchar,
  text,
  integer,
  boolean,
} from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";
import { relations } from "drizzle-orm";

// Session storage table (required for Replit Auth)
export const sessions = pgTable(
  "sessions",
  {
    sid: varchar("sid").primaryKey(),
    sess: jsonb("sess").notNull(),
    expire: timestamp("expire").notNull(),
  },
  (table) => [index("IDX_session_expire").on(table.expire)],
);

// User storage table (XPortal wallet-based auth)
export const users = pgTable("users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  walletAddress: varchar("wallet_address").unique().notNull(), // MultiversX wallet address (erd1...)
  email: varchar("email"), // Optional, for notifications
  firstName: varchar("first_name"), // Optional
  lastName: varchar("last_name"), // Optional
  profileImageUrl: varchar("profile_image_url"),
  subscriptionTier: varchar("subscription_tier").default("free"), // free, pro, business
  subscriptionStatus: varchar("subscription_status").default("active"), // active, canceled, past_due
  monthlyUsage: integer("monthly_usage").default(0),
  usageResetDate: timestamp("usage_reset_date").defaultNow(),
  companyName: varchar("company_name"),
  companyLogoUrl: varchar("company_logo_url"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export type UpsertUser = typeof users.$inferInsert;
export type User = typeof users.$inferSelect;

// Certifications table
export const certifications = pgTable("certifications", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").notNull().references(() => users.id, { onDelete: 'cascade' }),
  fileName: text("file_name").notNull(),
  fileHash: text("file_hash").notNull().unique(),
  fileType: varchar("file_type"),
  fileSize: integer("file_size"),
  authorName: text("author_name"),
  authorSignature: text("author_signature"),
  transactionHash: text("transaction_hash"),
  transactionUrl: text("transaction_url"),
  blockchainStatus: varchar("blockchain_status").default("pending"), // pending, confirmed, failed
  certificateUrl: text("certificate_url"),
  isPublic: boolean("is_public").default(true),
  webhookUrl: text("webhook_url"),
  webhookStatus: varchar("webhook_status"),
  webhookLastAttempt: timestamp("webhook_last_attempt"),
  webhookAttempts: integer("webhook_attempts").default(0),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const certificationsRelations = relations(certifications, ({ one }) => ({
  user: one(users, {
    fields: [certifications.userId],
    references: [users.id],
  }),
}));

export const usersRelations = relations(users, ({ many }) => ({
  certifications: many(certifications),
}));

export const insertCertificationSchema = createInsertSchema(certifications).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export type InsertCertification = z.infer<typeof insertCertificationSchema>;
export type Certification = typeof certifications.$inferSelect;

// Subscription tiers configuration (for reference)
export const SUBSCRIPTION_TIERS = {
  free: {
    name: "Free",
    price: 0,
    monthlyLimit: 1,
    features: ["1 certification per month", "xproof watermark on certificates", "Public verification page"],
  },
  pro: {
    name: "Pro",
    price: 9.99,
    monthlyLimit: 20,
    features: ["20 certifications per month", "No watermark", "Priority support", "Custom branding"],
  },
  business: {
    name: "Business",
    price: 39,
    monthlyLimit: 200,
    features: ["200 certifications per month", "No watermark", "API access", "Custom branding", "Dedicated support"],
  },
} as const;

export type SubscriptionTier = keyof typeof SUBSCRIPTION_TIERS;

// ============================================
// ACP (Agent Commerce Protocol) Types
// ============================================

// ACP Product - describes a purchasable service for AI agents
export interface ACPProduct {
  id: string;
  name: string;
  description: string;
  pricing: {
    type: "fixed" | "variable";
    amount: string;
    currency: string;
    note?: string;
  };
  inputs: Record<string, string>;
  outputs: Record<string, string>;
}

// ACP Checkout Request - what an agent sends to start certification
export const acpCheckoutRequestSchema = z.object({
  product_id: z.string(),
  inputs: z.object({
    file_hash: z.string().min(1, "SHA-256 hash is required"),
    filename: z.string().min(1, "Filename is required"),
    author_name: z.string().optional(),
    metadata: z.record(z.any()).optional(),
  }),
  buyer: z.object({
    type: z.enum(["agent", "user"]),
    id: z.string().optional(),
  }).optional(),
});

export type ACPCheckoutRequest = z.infer<typeof acpCheckoutRequestSchema>;

// ACP Checkout Response - transaction payload for agent to execute
export interface ACPCheckoutResponse {
  checkout_id: string;
  product_id: string;
  amount: string;
  currency: string;
  status: "pending" | "ready";
  execution: {
    type: "multiversx";
    mode: "direct" | "relayed_v3";
    chain_id: string;
    tx_payload: {
      receiver: string;
      data: string;
      value: string;
      gas_limit: number;
    };
  };
  expires_at: string;
}

// ACP Confirmation Request - agent confirms transaction was executed
export const acpConfirmRequestSchema = z.object({
  checkout_id: z.string(),
  tx_hash: z.string().min(1, "Transaction hash is required"),
});

export type ACPConfirmRequest = z.infer<typeof acpConfirmRequestSchema>;

// ACP Confirmation Response - includes certificate URL
export interface ACPConfirmResponse {
  status: "confirmed" | "pending" | "failed";
  checkout_id: string;
  tx_hash: string;
  certification_id?: string;
  certificate_url?: string;
  proof_url?: string;
  blockchain_explorer_url?: string;
  message?: string;
}

// ACP Checkouts table for tracking agent checkout sessions
export const acpCheckouts = pgTable("acp_checkouts", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  productId: varchar("product_id").notNull(),
  fileHash: text("file_hash").notNull(),
  fileName: text("file_name").notNull(),
  authorName: text("author_name"),
  metadata: jsonb("metadata"),
  buyerType: varchar("buyer_type").default("agent"),
  buyerId: varchar("buyer_id"),
  status: varchar("status").default("pending"), // pending, confirmed, expired, failed
  txHash: text("tx_hash"),
  certificationId: varchar("certification_id").references(() => certifications.id),
  expiresAt: timestamp("expires_at").notNull(),
  createdAt: timestamp("created_at").defaultNow(),
  confirmedAt: timestamp("confirmed_at"),
});

export type ACPCheckout = typeof acpCheckouts.$inferSelect;
export type InsertACPCheckout = typeof acpCheckouts.$inferInsert;

// API Keys table for agent authentication
export const apiKeys = pgTable("api_keys", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  keyHash: varchar("key_hash").notNull().unique(),
  keyPrefix: varchar("key_prefix").notNull(), // First 8 chars for display (pm_xxx...)
  userId: varchar("user_id").notNull().references(() => users.id, { onDelete: 'cascade' }),
  name: varchar("name").notNull(),
  lastUsedAt: timestamp("last_used_at"),
  requestCount: integer("request_count").default(0),
  isActive: boolean("is_active").default(true),
  createdAt: timestamp("created_at").defaultNow(),
});

export const apiKeysRelations = relations(apiKeys, ({ one }) => ({
  user: one(users, {
    fields: [apiKeys.userId],
    references: [users.id],
  }),
}));

export type ApiKey = typeof apiKeys.$inferSelect;
export type InsertApiKey = typeof apiKeys.$inferInsert;
