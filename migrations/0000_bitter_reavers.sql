CREATE TABLE "acp_checkouts" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"product_id" varchar NOT NULL,
	"file_hash" text NOT NULL,
	"file_name" text NOT NULL,
	"author_name" text,
	"metadata" jsonb,
	"buyer_type" varchar DEFAULT 'agent',
	"buyer_id" varchar,
	"status" varchar DEFAULT 'pending',
	"tx_hash" text,
	"certification_id" varchar,
	"expires_at" timestamp NOT NULL,
	"created_at" timestamp DEFAULT now(),
	"confirmed_at" timestamp
);
--> statement-breakpoint
CREATE TABLE "certifications" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" varchar NOT NULL,
	"file_name" text NOT NULL,
	"file_hash" text NOT NULL,
	"file_type" varchar,
	"file_size" integer,
	"author_name" text,
	"author_signature" text,
	"transaction_hash" text,
	"transaction_url" text,
	"blockchain_status" varchar DEFAULT 'pending',
	"certificate_url" text,
	"is_public" boolean DEFAULT true,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	CONSTRAINT "certifications_file_hash_unique" UNIQUE("file_hash")
);
--> statement-breakpoint
CREATE TABLE "sessions" (
	"sid" varchar PRIMARY KEY NOT NULL,
	"sess" jsonb NOT NULL,
	"expire" timestamp NOT NULL
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"wallet_address" varchar NOT NULL,
	"email" varchar,
	"first_name" varchar,
	"last_name" varchar,
	"profile_image_url" varchar,
	"stripe_customer_id" varchar,
	"stripe_subscription_id" varchar,
	"subscription_tier" varchar DEFAULT 'free',
	"subscription_status" varchar DEFAULT 'active',
	"monthly_usage" integer DEFAULT 0,
	"usage_reset_date" timestamp DEFAULT now(),
	"company_name" varchar,
	"company_logo_url" varchar,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	CONSTRAINT "users_wallet_address_unique" UNIQUE("wallet_address")
);
--> statement-breakpoint
ALTER TABLE "acp_checkouts" ADD CONSTRAINT "acp_checkouts_certification_id_certifications_id_fk" FOREIGN KEY ("certification_id") REFERENCES "public"."certifications"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "certifications" ADD CONSTRAINT "certifications_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "IDX_session_expire" ON "sessions" USING btree ("expire");