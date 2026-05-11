import { sql } from 'drizzle-orm';
import {
  bigint,
  date,
  index,
  uniqueIndex,
  jsonb,
  pgTable,
  serial,
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
  isTrial: boolean("is_trial").default(false),
  trialQuota: integer("trial_quota").default(0),
  trialUsed: integer("trial_used").default(0),
  creditBalance: integer("credit_balance").default(0),
  agentName: varchar("agent_name"),
  agentDescription: text("agent_description"),
  agentWebsite: varchar("agent_website"),
  agentCategory: varchar("agent_category"),
  isPublicProfile: boolean("is_public_profile").default(false),
  registrationIpHash: varchar("registration_ip_hash", { length: 64 }),
  webhookUrl: text("webhook_url"),
  webhookSecret: varchar("webhook_secret", { length: 128 }),
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
  blockchainLatencyMs: integer("blockchain_latency_ms"),
  authMethod: varchar("auth_method"),
  metadata: jsonb("metadata"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
}, (table) => [
  // Partial unique index: a given on-chain transaction hash can only be used for one
  // certification. NULL transaction_hash is excluded so pending rows (which have no tx yet)
  // do not conflict with each other.
  uniqueIndex("certifications_transaction_hash_unique")
    .on(table.transactionHash)
    .where(sql`transaction_hash IS NOT NULL`),
]);

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

// ============================================
// Attestations table — Domain-specific trust signals
// ============================================
export const attestations = pgTable("attestations", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  subjectWallet: varchar("subject_wallet").notNull(),
  issuerWallet: varchar("issuer_wallet").notNull(),
  issuerName: varchar("issuer_name").notNull(),
  domain: varchar("domain").notNull(),
  standard: varchar("standard").notNull(),
  title: text("title").notNull(),
  description: text("description"),
  expiresAt: timestamp("expires_at"),
  status: varchar("status").default("active"),
  revokedAt: timestamp("revoked_at"),
  expiryNotifiedAt: timestamp("expiry_notified_at"),
  webhookUrl: text("webhook_url"),
  webhookSecret: varchar("webhook_secret", { length: 128 }),
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertAttestationSchema = createInsertSchema(attestations).omit({
  id: true,
  createdAt: true,
  revokedAt: true,
  status: true,
});
export type InsertAttestation = z.infer<typeof insertAttestationSchema>;
export type Attestation = typeof attestations.$inferSelect;

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
  checkout_requirements?: {
    payer_wallet: string;
    payer_wallet_signature: string;
    message_format: string;
    message_format_example: string;
    signing_algorithm: string;
  };
}

// Max user-controlled string lengths that are embedded in the on-chain
// transaction data field. These bound the server-paid gas (BigInt(50_000 +
// dataPayload.length * 1500)) so a single trial-key holder cannot force the
// service to sign and broadcast oversized MultiversX transactions. See the
// matching cap in server/blockchain.ts:recordOnBlockchain — that one is the
// authoritative defense-in-depth that holds even if a future caller bypasses
// schema validation.
export const MAX_ONCHAIN_FILENAME_LEN = 255;   // POSIX NAME_MAX
export const MAX_ONCHAIN_AUTHOR_LEN = 128;

// ACP Checkout Request - what an agent sends to start certification
export const acpCheckoutRequestSchema = z.object({
  product_id: z.string(),
  inputs: z.object({
    file_hash: z.string().min(1, "SHA-256 hash is required"),
    filename: z.string().min(1, "Filename is required").max(MAX_ONCHAIN_FILENAME_LEN, `Filename must be at most ${MAX_ONCHAIN_FILENAME_LEN} characters`),
    author_name: z.string().max(MAX_ONCHAIN_AUTHOR_LEN, `author_name must be at most ${MAX_ONCHAIN_AUTHOR_LEN} characters`).optional(),
    metadata: z.record(z.any()).optional(),
  }),
  buyer: z.object({
    type: z.enum(["agent", "user"]),
    id: z.string().optional(),
  }).optional(),
  // MultiversX wallet address (erd1...) that will send the EGLD payment.
  // Required for non-admin checkouts to cryptographically bind the payment sender
  // to this checkout and prevent tx hijacking by a competing actor.
  payer_wallet: z.string().optional(),
  // Ed25519 signature (hex) proving the caller controls payer_wallet.
  // Sign the deterministic message "xproof-acp-checkout:<product_id>:<file_hash>:<payer_wallet>"
  // with the private key corresponding to payer_wallet's public key.
  payer_wallet_signature: z.string().optional(),
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
  tx_hash: z.string().min(64, "Transaction hash must be 64 hex characters").max(64, "Transaction hash must be 64 hex characters").regex(/^[0-9a-fA-F]+$/, "Transaction hash must contain only hex characters"),
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
  userId: varchar("user_id").references(() => users.id), // internal user who created the checkout
  status: varchar("status").default("pending"), // pending, confirmed, expired, failed
  // Payment invariants captured at checkout time — verified at confirm time
  expectedReceiver: text("expected_receiver"),  // xproof wallet at checkout creation
  expectedValue: text("expected_value"),        // EGLD amount in atomic units (or "0" for admin)
  expectedData: text("expected_data"),          // base64 data field: certify@<hash>@<filename>
  txHash: text("tx_hash").unique(),             // unique: prevents replay of same tx across checkouts
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
  previousKeyHash: varchar("previous_key_hash"),
  previousKeyExpiresAt: timestamp("previous_key_expires_at"),
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

export const txQueue = pgTable("tx_queue", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  jobType: varchar("job_type").notNull(),
  jobId: varchar("job_id").notNull(),
  status: varchar("status").default("pending").notNull(),
  payload: jsonb("payload").notNull(),
  attempts: integer("attempts").default(0).notNull(),
  maxAttempts: integer("max_attempts").default(3).notNull(),
  lastError: text("last_error"),
  nextRetryAt: timestamp("next_retry_at"),
  startedAt: timestamp("started_at"),
  completedAt: timestamp("completed_at"),
  createdAt: timestamp("created_at").defaultNow(),
});

export type TxQueueItem = typeof txQueue.$inferSelect;
export type InsertTxQueueItem = typeof txQueue.$inferInsert;

export const visits = pgTable("visits", {
  id: serial("id").primaryKey(),
  ipHash: varchar("ip_hash", { length: 64 }).notNull(),
  userAgent: text("user_agent"),
  isAgent: boolean("is_agent").default(false).notNull(),
  path: varchar("path", { length: 512 }).notNull(),
  utmSource: varchar("utm_source", { length: 128 }),
  utmMedium: varchar("utm_medium", { length: 128 }),
  utmContent: varchar("utm_content", { length: 256 }),
  // Privacy: only the referer hostname is stored, never the full URL or query string.
  referrerHost: varchar("referrer_host", { length: 128 }),
  createdAt: timestamp("created_at").defaultNow(),
});

// Credit purchases — tracks prepaid certification credits for API key users
export const creditPurchases = pgTable("credit_purchases", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").notNull().references(() => users.id, { onDelete: 'cascade' }),
  packageId: varchar("package_id").notNull(),
  txHash: varchar("tx_hash").notNull().unique(), // Base transaction hash (prevents double-claim)
  creditsAdded: integer("credits_added").notNull(),
  priceUsdc: varchar("price_usdc").notNull(),
  network: varchar("network").default("eip155:8453"), // Base mainnet
  createdAt: timestamp("created_at").defaultNow(),
});

export type CreditPurchase = typeof creditPurchases.$inferSelect;
export type InsertCreditPurchase = typeof creditPurchases.$inferInsert;

// Credit purchase intents — binds a /credits/purchase call to the initiating user
// Prevents another account from claiming the same Base tx hash via /credits/confirm.
export const creditPurchaseIntents = pgTable("credit_purchase_intents", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  packageId: varchar("package_id").notNull(),
  intentToken: varchar("intent_token").notNull().unique(),
  // EVM wallet that will originate the Base USDC transfer — verified as tx sender at confirm time
  payerAddress: varchar("payer_address").notNull(),
  expiresAt: timestamp("expires_at").notNull(),
  createdAt: timestamp("created_at").defaultNow(),
});

export type CreditPurchaseIntent = typeof creditPurchaseIntents.$inferSelect;

// agent_violations — records structural anomalies detected during investigate_proof.
// type: "fault" (irrefutable, auto-confirmed) | "breach" (ambiguous, admin-confirmed)
// status: "proposed" (public immediately) → "confirmed" (score penalty applied) | "rejected"
// proofId: nullable — some violations may not have a single associated proof (future: session-level)
// reason: human-readable anomaly description (extension beyond spec; used in public API + profile UI)
export const agentViolations = pgTable("agent_violations", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  walletAddress: varchar("wallet_address").notNull(),
  proofId: varchar("proof_id"),
  type: varchar("type").notNull(),
  status: varchar("status").default("proposed").notNull(),
  reason: text("reason"),
  autoConfirmed: boolean("auto_confirmed").default(false),
  detectedAt: timestamp("detected_at").defaultNow(),
  confirmedAt: timestamp("confirmed_at"),
  notes: text("notes"),
});

export const insertAgentViolationSchema = createInsertSchema(agentViolations).omit({
  id: true,
  detectedAt: true,
  confirmedAt: true,
});
export type InsertAgentViolation = z.infer<typeof insertAgentViolationSchema>;
export type AgentViolation = typeof agentViolations.$inferSelect;

// Raw-SQL tables — registered here so drizzle-kit push does not try to drop them.
// These tables are managed exclusively via raw SQL in server/nonce.ts and server/trust.ts.
export const walletNonces = pgTable("wallet_nonces", {
  address: text("address").primaryKey(),
  nonce: bigint("nonce", { mode: "number" }).notNull().default(0),
});

export const trustScoreSnapshots = pgTable("trust_score_snapshots", {
  id: serial("id").primaryKey(),
  walletAddress: text("wallet_address").notNull(),
  score: integer("score").notNull().default(0),
  level: text("level").notNull().default("Newcomer"),
  certTotal: integer("cert_total").notNull().default(0),
  activeAttestations: integer("active_attestations").notNull().default(0),
  snapshotDate: date("snapshot_date").notNull().default(sql`CURRENT_DATE`),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  rank: integer("rank"),
});
