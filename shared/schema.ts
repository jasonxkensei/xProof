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

// User storage table (required for Replit Auth)
export const users = pgTable("users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  email: varchar("email").unique(),
  firstName: varchar("first_name"),
  lastName: varchar("last_name"),
  profileImageUrl: varchar("profile_image_url"),
  stripeCustomerId: varchar("stripe_customer_id"),
  stripeSubscriptionId: varchar("stripe_subscription_id"),
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
    features: ["1 certification per month", "ProofMint watermark on certificates", "Public verification page"],
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
