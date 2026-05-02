import { type Express } from "express";
import crypto from "crypto";
import { z } from "zod";
import { db, pool } from "../db";
import { logger } from "../logger";
import { certifications, users, apiKeys, acpCheckouts, attestations, acpCheckoutRequestSchema, acpConfirmRequestSchema, type ACPProduct, type ACPCheckoutResponse, type ACPConfirmResponse } from "@shared/schema";
import { eq, sql, and, gt } from "drizzle-orm";
import { publicReadRateLimiter } from "../reliability";
import { getCertificationPriceEgld, getCertificationPriceUsd } from "../pricing";
import { recordOnBlockchain } from "../blockchain";
import { isMX8004Configured, recordCertificationAsJob } from "../mx8004";
import { isAdminWallet, getApiKeyOwnerWallet, getNetworkLabel, buildCanonicalId, validateApiKey } from "./helpers";

export function registerAcpRoutes(app: Express) {
  // ============================================
  // ACP (Agent Commerce Protocol) Endpoints
  // These endpoints enable AI agents to discover
  // and use xproof certification services
  // ============================================

  // ACP Products Discovery - Returns available services for AI agents
  app.get("/api/acp/products", publicReadRateLimiter, async (req, res) => {
    const priceUsd = await getCertificationPriceUsd();
    
    const products: ACPProduct[] = [
      {
        id: "xproof-certification",
        name: "xproof Certification",
        description: "xproof is the canonical proof layer for AI agents. Create cryptographic proof of existence and integrity for digital files on MultiversX blockchain. Records SHA-256 hash with timestamp, providing immutable evidence of file ownership at a specific point in time.",
        pricing: {
          type: "fixed",
          amount: priceUsd.toString(),
          currency: "USD",
          note: "Price converted to EGLD at checkout based on current exchange rate",
        },
        inputs: {
          file_hash: "SHA-256 hash of the file (64 character hex string)",
          filename: "Original filename with extension",
          author_name: "Optional - Name of the author/certifier",
          metadata: "Optional - Additional JSON metadata (supports model_hash, strategy_hash, version_number and any custom fields). Searchable via GET /api/proofs/search",
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
      provider: "xproof",
      chain: "MultiversX",
      products 
    });
  });

  // ACP Checkout - Agent initiates certification
  app.post("/api/acp/checkout", async (req, res) => {
    try {
      const data = acpCheckoutRequestSchema.parse(req.body);

      // Validate product exists
      if (data.product_id !== "xproof-certification") {
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

      // Check if the API key owner is an admin wallet
      let acpAdminExempt = false;
      const acpApiKey = (req as any).apiKey;
      const requestingUserId = acpApiKey?.userId || null;
      if (acpApiKey?.userId) {
        const ownerWallet = await getApiKeyOwnerWallet(acpApiKey);
        if (ownerWallet && isAdminWallet(ownerWallet)) {
          acpAdminExempt = true;
          logger.withRequest(req).info("Admin wallet exempt from ACP payment", { walletAddress: ownerWallet });
        }
      }

      // Get current EGLD price and calculate payment
      const pricing = await getCertificationPriceEgld();
      
      // Create checkout session (expires in 1 hour)
      const expiresAt = new Date(Date.now() + 60 * 60 * 1000);
      
      const chainId = process.env.MULTIVERSX_CHAIN_ID || "1"; // 1 = Mainnet

      // Receiver wallet for certification fees
      const xproofWallet = process.env.MULTIVERSX_RECEIVER_ADDRESS || process.env.XPROOF_WALLET_ADDRESS || process.env.MULTIVERSX_SENDER_ADDRESS;
      if (!xproofWallet) {
        logger.withRequest(req).error("No receiver wallet configured");
        return res.status(500).json({
          error: "CONFIGURATION_ERROR",
          message: "xproof wallet not configured",
        });
      }

      // Build transaction payload for MultiversX
      // Data format: certify@<hash>@<filename>
      const dataField = Buffer.from(
        `certify@${data.inputs.file_hash}@${data.inputs.filename}`
      ).toString("base64");

      // Persist payment invariants so they can be verified at confirm time
      const expectedValue = acpAdminExempt ? "0" : pricing.priceEgld;

      // Require payer_wallet for non-admin checkouts to bind the expected transaction sender.
      // This prevents a third party from observing a pending checkout for a file they control
      // and then using the legitimate payer's tx_hash to confirm it.
      let payerWallet: string | null = null;
      if (!acpAdminExempt) {
        const raw = (data.payer_wallet || "").trim();
        if (!raw.startsWith("erd1") || raw.length < 60) {
          return res.status(400).json({
            error: "PAYER_WALLET_REQUIRED",
            message: "Provide the MultiversX wallet address (erd1...) that will send the EGLD payment as payer_wallet. This binds the checkout to the expected payment sender and prevents tx hijacking.",
          });
        }
        payerWallet = raw;
      }

      // Deduplication via DB-level advisory lock + serialized check-then-insert.
      // pg_advisory_xact_lock(hashtext(file_hash)) serializes concurrent checkout requests
      // for the same file hash within a single PostgreSQL transaction, eliminating the
      // read-before-write race window that a naive application-level check would leave open.
      // The lock is released automatically when the transaction commits or rolls back.
      let checkout: typeof acpCheckouts.$inferSelect;
      try {
        checkout = await db.transaction(async (tx) => {
          await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${data.inputs.file_hash}))`);

          const nowTx = new Date();
          const [pendingCheckout] = await tx
            .select({ id: acpCheckouts.id, userId: acpCheckouts.userId })
            .from(acpCheckouts)
            .where(
              and(
                eq(acpCheckouts.fileHash, data.inputs.file_hash),
                eq(acpCheckouts.status, "pending"),
                gt(acpCheckouts.expiresAt, nowTx),
              )
            );

          if (pendingCheckout && pendingCheckout.userId !== requestingUserId) {
            throw Object.assign(new Error("DUPLICATE_PENDING_CHECKOUT"), { code: "DUPLICATE_PENDING_CHECKOUT" });
          }

          const [newCheckout] = await tx
            .insert(acpCheckouts)
            .values({
              productId: data.product_id,
              fileHash: data.inputs.file_hash,
              fileName: data.inputs.filename,
              authorName: data.inputs.author_name || "AI Agent",
              metadata: {
                ...(data.inputs.metadata || {}),
                ...(payerWallet ? { expectedSender: payerWallet } : {}),
              },
              buyerType: data.buyer?.type || "agent",
              buyerId: data.buyer?.id,
              userId: requestingUserId,
              status: "pending",
              expectedReceiver: xproofWallet,
              expectedValue,
              expectedData: dataField,
              expiresAt,
            })
            .returning();
          return newCheckout;
        });
      } catch (txErr: any) {
        if (txErr.code === "DUPLICATE_PENDING_CHECKOUT") {
          return res.status(409).json({
            error: "DUPLICATE_PENDING_CHECKOUT",
            message: "A pending checkout already exists for this file hash. Each file can have at most one pending ACP checkout at a time. Wait for the existing checkout to expire or complete before creating a new one.",
          });
        }
        throw txErr;
      }

      const response: ACPCheckoutResponse = {
        checkout_id: checkout.id,
        product_id: data.product_id,
        amount: acpAdminExempt ? "0.00" : pricing.priceUsd.toFixed(2),
        currency: "USD",
        status: "ready",
        execution: {
          type: "multiversx",
          mode: "direct",
          chain_id: chainId,
          tx_payload: {
            receiver: xproofWallet,
            data: dataField,
            value: acpAdminExempt ? "0" : pricing.priceEgld,
            gas_limit: 100000,
          },
        },
        expires_at: expiresAt.toISOString(),
      };

      logger.withRequest(req).info("ACP checkout created", { checkoutId: checkout.id, priceUsd: acpAdminExempt ? "0 (admin)" : pricing.priceUsd, priceEgld: acpAdminExempt ? "0 (admin)" : pricing.priceEgld, egldUsdRate: pricing.egldUsdRate, fileHash: data.inputs.file_hash.slice(0, 16), adminExempt: acpAdminExempt });
      
      res.status(201).json(response);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ 
          error: "INVALID_REQUEST",
          message: "Invalid checkout request",
          details: error.errors 
        });
      }
      logger.withRequest(req).error("ACP checkout failed");
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

      // Block tx replay: a tx_hash may only be used for one checkout
      const [replayCheck] = await db
        .select({ id: acpCheckouts.id })
        .from(acpCheckouts)
        .where(eq(acpCheckouts.txHash, data.tx_hash));
      if (replayCheck && replayCheck.id !== checkout.id) {
        return res.status(409).json({
          error: "TX_ALREADY_USED",
          message: "This transaction has already been used to confirm another checkout",
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

      // Admin-exempt checkouts have expectedValue "0" — skip on-chain payment checks
      const isAdminExempt = checkout.expectedValue === "0";

      let txVerified = false;
      let txStatus = "pending";

      try {
        const txResponse = await fetch(`${apiUrl}/transactions/${data.tx_hash}`);
        if (txResponse.ok) {
          const txData = await txResponse.json();
          txStatus = txData.status;
          if (txData.status === "success") {
            if (isAdminExempt) {
              txVerified = true;
            } else {
              // Verify receiver matches what was quoted at checkout creation
              const expectedReceiver = checkout.expectedReceiver;
              if (expectedReceiver && txData.receiver !== expectedReceiver) {
                logger.withRequest(req).warn("ACP confirm: tx receiver mismatch", {
                  txHash: data.tx_hash,
                  txReceiver: txData.receiver,
                  expected: expectedReceiver,
                });
                return res.status(402).json({
                  error: "PAYMENT_VERIFICATION_FAILED",
                  message: "Transaction receiver does not match the xproof payment address quoted at checkout",
                });
              }

              // Verify value (EGLD in atomic units) meets or exceeds the quoted price
              const expectedValue = checkout.expectedValue;
              if (expectedValue && expectedValue !== "0") {
                const onChainValue = BigInt(txData.value || "0");
                const requiredValue = BigInt(expectedValue);
                if (onChainValue < requiredValue) {
                  logger.withRequest(req).warn("ACP confirm: insufficient value", {
                    txHash: data.tx_hash,
                    onChainValue: onChainValue.toString(),
                    required: requiredValue.toString(),
                  });
                  return res.status(402).json({
                    error: "PAYMENT_VERIFICATION_FAILED",
                    message: "Transaction value is less than the price quoted at checkout",
                  });
                }
              }

              // Verify data field matches the canonical payload from checkout
              const expectedData = checkout.expectedData;
              if (expectedData && txData.data !== expectedData) {
                logger.withRequest(req).warn("ACP confirm: tx data mismatch", {
                  txHash: data.tx_hash,
                  checkoutId: checkout.id,
                });
                return res.status(402).json({
                  error: "PAYMENT_VERIFICATION_FAILED",
                  message: "Transaction data field does not match the certify payload for this checkout",
                });
              }

              // Verify tx sender matches the expected payer wallet captured at checkout creation.
              // This prevents a competing actor from using their own tx to confirm someone else's
              // checkout (tx hijacking). If no expectedSender was stored, reject as fail-closed.
              const checkoutMeta = checkout.metadata as Record<string, unknown> | null;
              const expectedSender: string | undefined = checkoutMeta?.expectedSender as string | undefined;
              if (!expectedSender) {
                logger.withRequest(req).warn("ACP confirm: checkout has no expectedSender — created before sender binding was enforced; rejecting fail-closed", { checkoutId: checkout.id, txHash: data.tx_hash });
                return res.status(402).json({
                  error: "SENDER_BINDING_MISSING",
                  message: "This checkout was created without a payer_wallet binding. Re-create the checkout providing payer_wallet to bind the expected payment sender.",
                });
              }
              if (txData.sender !== expectedSender) {
                logger.withRequest(req).warn("ACP confirm: tx sender mismatch", {
                  txHash: data.tx_hash,
                  checkoutId: checkout.id,
                  txSender: txData.sender,
                  expectedSender,
                });
                return res.status(402).json({
                  error: "PAYMENT_VERIFICATION_FAILED",
                  message: `Transaction sender (${txData.sender}) does not match the expected payer wallet (${expectedSender}) that was provided when the checkout was created.`,
                });
              }

              txVerified = true;

              // Reject if we cannot verify the checkout predates the transaction (fail-closed).
              // This prevents an attacker from observing a victim's payment, creating a new
              // checkout for the same file_hash/filename, and confirming with the victim's tx.
              if (!txData.timestamp) {
                logger.withRequest(req).warn("ACP confirm: transaction timestamp unavailable — cannot verify checkout/tx ordering", { txHash: data.tx_hash });
                return res.status(402).json({
                  error: "TX_TIMESTAMP_UNAVAILABLE",
                  message: "Transaction timestamp could not be verified. Payment cannot be attributed without proof that the checkout predates the transaction.",
                });
              }
              const txTime = new Date(txData.timestamp * 1000);
              if (checkout.createdAt && checkout.createdAt > txTime) {
                logger.withRequest(req).warn("ACP confirm: checkout postdates transaction", {
                  txHash: data.tx_hash,
                  checkoutCreatedAt: checkout.createdAt,
                  txTime,
                });
                return res.status(402).json({
                  error: "CHECKOUT_POSTDATES_TRANSACTION",
                  message: "This checkout was created after the transaction was submitted. Payment cannot be attributed to a checkout that did not exist when the payment was made.",
                });
              }
            }
          }
        }
      } catch (err) {
        logger.withRequest(req).error("Could not verify ACP transaction", { txHash: data.tx_hash });
        return res.status(503).json({
          error: "VERIFICATION_UNAVAILABLE",
          message: "Could not verify transaction on MultiversX at this time. Please retry.",
        });
      }

      if (!txVerified) {
        return res.status(402).json({
          error: "PAYMENT_VERIFICATION_FAILED",
          message: `Transaction not yet confirmed on-chain (status: ${txStatus}). Retry once the transaction is successful.`,
        });
      }

      // Attribution: use the checkout creator's userId — never the caller of this confirm endpoint.
      // The checkout was created by a specific API key owner; confirm may be called by any agent
      // that holds the checkout_id (including anonymous callers), but the certification always
      // records under the original checkout owner to prevent ownership hijacking.
      let acpOwnerId: string | null = checkout.userId || null;

      if (!acpOwnerId) {
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
        acpOwnerId = systemUser.id!;
      }

      // Create certification record
      const [certification] = await db
        .insert(certifications)
        .values({
          userId: acpOwnerId,
          fileName: checkout.fileName,
          fileHash: checkout.fileHash,
          fileType: checkout.fileName.split(".").pop() || "unknown",
          authorName: checkout.authorName || "AI Agent",
          transactionHash: data.tx_hash,
          transactionUrl: `${explorerUrl}/transactions/${data.tx_hash}`,
          blockchainStatus: txVerified ? "confirmed" : "pending",
          isPublic: true,
          authMethod: "acp",
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

      logger.withRequest(req).info("ACP certification confirmed", { certificationId: certification.id });

      res.json(response);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({
          error: "INVALID_REQUEST",
          message: "Invalid confirmation request",
          details: error.errors,
        });
      }
      logger.withRequest(req).error("ACP confirm failed");
      res.status(500).json({
        error: "CONFIRMATION_FAILED",
        message: "Failed to confirm certification",
      });
    }
  });

  // ACP Status - Check checkout status
  app.get("/api/acp/checkout/:checkoutId", publicReadRateLimiter, async (req, res) => {
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
      logger.withRequest(req).error("ACP status check failed");
      res.status(500).json({
        error: "STATUS_CHECK_FAILED",
        message: "Failed to check checkout status",
      });
    }
  });

  // OpenAPI 3.0 Specification for ACP
  app.get("/api/acp/openapi.json", publicReadRateLimiter, async (req, res) => {
    const baseUrl = `https://${req.get("host")}`;
    const priceUsd = await getCertificationPriceUsd();

    const openApiSpec = {
      openapi: "3.0.3",
      info: {
        title: "xproof ACP - Agent Commerce Protocol",
        description: "API for AI agents to certify files on MultiversX blockchain. Create immutable proofs of file ownership with a simple API call. Supports x402 payment protocol (HTTP 402) as an alternative to API key auth — send requests to POST /api/proof or POST /api/batch without an API key, receive 402 with payment requirements, sign payment in USDC on Base (eip155:8453), and resend with X-PAYMENT header.",
        version: "1.0.0",
        contact: {
          name: "xproof Support",
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
              id: { type: "string", example: "xproof-certification" },
              name: { type: "string", example: "xproof Certification" },
              description: { type: "string" },
              pricing: {
                type: "object",
                properties: {
                  type: { type: "string", enum: ["fixed", "variable"] },
                  amount: { type: "string", example: priceUsd.toString() },
                  currency: { type: "string", example: "USD" },
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
              product_id: { type: "string", example: "xproof-certification" },
              inputs: {
                type: "object",
                required: ["file_hash", "filename"],
                properties: {
                  file_hash: { type: "string", description: "SHA-256 hash of the file (64 hex chars)", example: "a1b2c3d4e5f678901234567890123456789012345678901234567890123456ab" },
                  filename: { type: "string", example: "document.pdf" },
                  author_name: { type: "string", example: "AI Agent" },
                  metadata: { type: "object", description: "Optional JSON metadata. Supports model_hash, strategy_hash, version_number, and any custom fields. Searchable via GET /api/proofs/search.", properties: { model_hash: { type: "string" }, strategy_hash: { type: "string" }, version_number: { type: "string" } }, additionalProperties: true },
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
              amount: { type: "string", description: "Price in USD" },
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
                      receiver: { type: "string", description: "xproof wallet address" },
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
                        provider: { type: "string", example: "xproof" },
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
        "/mcp": {
          post: {
            summary: "MCP Server (JSON-RPC 2.0)",
            description: "Model Context Protocol server endpoint. Accepts JSON-RPC 2.0 requests over Streamable HTTP. Supports methods: initialize, tools/list, tools/call, resources/list, resources/read. Tools: certify_file, certify_with_confidence, verify_proof, get_proof, discover_services, audit_agent_session, check_attestations, investigate_proof, register_free_trial. Resources: xproof://specification, xproof://openapi. Stateless (no session management). Protocol version: 2025-03-26.",
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    required: ["jsonrpc", "method"],
                    properties: {
                      jsonrpc: { type: "string", example: "2.0" },
                      id: { type: "integer", example: 1 },
                      method: { type: "string", enum: ["initialize", "tools/list", "tools/call", "resources/list", "resources/read"], example: "initialize" },
                      params: { type: "object", description: "Method-specific parameters" },
                    },
                  },
                },
              },
            },
            responses: {
              "200": {
                description: "JSON-RPC 2.0 response",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        jsonrpc: { type: "string", example: "2.0" },
                        id: { type: "integer" },
                        result: { type: "object", description: "Method-specific result" },
                      },
                    },
                  },
                },
              },
              "401": { description: "Invalid or missing API key (for authenticated methods like tools/call)" },
            },
          },
        },
        "/api/proof": {
          post: {
            summary: "Certify a file (simplified)",
            description: "Single-call endpoint for AI agents. Creates a blockchain certification by recording the SHA-256 hash on MultiversX. No checkout flow needed.",
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    required: ["file_hash", "filename"],
                    properties: {
                      file_hash: { type: "string", description: "SHA-256 hash of the file (64 hex chars)", example: "a1b2c3d4e5f678901234567890123456789012345678901234567890123456ab" },
                      filename: { type: "string", example: "document.pdf" },
                      author_name: { type: "string", example: "AI Agent", description: "Optional author name" },
                      webhook_url: { type: "string", format: "uri", description: "Optional HTTPS URL to receive a POST notification when the proof is confirmed on-chain. Payload includes proof_id, file_hash, verify_url, blockchain details. Signed with X-xProof-Signature (HMAC-SHA256).", example: "https://your-agent.example.com/webhooks/xproof" },
                    },
                  },
                },
              },
            },
            responses: {
              "201": {
                description: "File certified successfully",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        proof_id: { type: "string", format: "uuid" },
                        status: { type: "string", example: "certified" },
                        file_hash: { type: "string" },
                        filename: { type: "string" },
                        verify_url: { type: "string", format: "uri" },
                        certificate_url: { type: "string", format: "uri" },
                        proof_json_url: { type: "string", format: "uri" },
                        blockchain: {
                          type: "object",
                          properties: {
                            network: { type: "string", example: "MultiversX" },
                            transaction_hash: { type: "string" },
                            explorer_url: { type: "string", format: "uri" },
                          },
                        },
                        timestamp: { type: "string", format: "date-time" },
                        webhook_status: { type: "string", enum: ["pending", "delivered", "failed", "not_requested", "not_applicable"], description: "Webhook delivery status. 'pending': delivery in progress, 'delivered': successfully sent, 'failed': delivery failed after retries or invalid URL, 'not_requested': no webhook_url provided, 'not_applicable': file was already certified." },
                        message: { type: "string" },
                      },
                    },
                  },
                },
              },
              "200": { description: "File already certified (returns existing proof)" },
              "400": { description: "Invalid request data" },
              "401": { description: "API key required" },
              "429": { description: "Rate limit exceeded" },
            },
          },
        },
        "/api/audit": {
          post: {
            summary: "Certify an agent audit log",
            description: "Agent Audit Log Standard — certify an AI agent's work session on the MultiversX blockchain BEFORE executing any critical action (trade, deploy, data access). Returns a proof_id that serves as a compliance certificate. The agent MUST call this endpoint before acting. Schema: /.well-known/agent-audit-schema.json",
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    required: ["agent_id", "session_id", "action_type", "action_description", "inputs_hash", "risk_level", "decision", "timestamp"],
                    properties: {
                      agent_id: { type: "string", description: "Identifier of the agent making the decision", example: "trading-bot-v2" },
                      session_id: { type: "string", description: "Unique session identifier (UUID)", example: "sess_20260227_001" },
                      action_type: { type: "string", enum: ["trade_execution", "code_deploy", "data_access", "content_generation", "api_call", "other"] },
                      action_description: { type: "string", description: "Human-readable description of the action", example: "Buy 0.5 ETH at market price on Uniswap v3" },
                      inputs_hash: { type: "string", description: "SHA-256 of all inputs analyzed (64 hex chars)", example: "a1b2c3d4e5f678901234567890123456789012345678901234567890123456ab" },
                      inputs_manifest: { type: "object", description: "Optional declaration of what inputs_hash covers (field names, sources, hash method) — enables regulatory audit without revealing values", properties: { fields: { type: "array", items: { type: "string" }, description: "Input field names included in the hash" }, sources: { type: "array", items: { type: "string" }, description: "Data sources consulted" }, hash_method: { type: "string", description: "How the hash was computed" } }, required: ["fields"] },
                      risk_level: { type: "string", enum: ["low", "medium", "high", "critical"] },
                      decision: { type: "string", enum: ["approved", "rejected", "deferred"] },
                      timestamp: { type: "string", format: "date-time", example: "2026-02-27T23:00:00Z" },
                      risk_summary: { type: "string", description: "Optional brief risk analysis" },
                      context: { type: "object", description: "Optional additional context" },
                    },
                  },
                },
              },
            },
            responses: {
              "201": {
                description: "Audit log certified on blockchain",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        proof_id: { type: "string", format: "uuid" },
                        audit_url: { type: "string", format: "uri" },
                        proof_url: { type: "string", format: "uri" },
                        blockchain: { type: "object", properties: { network: { type: "string" }, transaction_hash: { type: "string" }, explorer_url: { type: "string", format: "uri" } } },
                        decision: { type: "string" },
                        risk_level: { type: "string" },
                        inputs_hash: { type: "string" },
                        inputs_manifest: { type: "object", description: "Present when submitted — declares what the inputs_hash covers" },
                      },
                    },
                  },
                },
              },
              "400": { description: "Invalid audit log data" },
              "401": { description: "API key required" },
              "429": { description: "Rate limit exceeded" },
            },
          },
        },
        "/api/agent/register": {
          post: {
            summary: "Register a free trial agent",
            description: "Get a free API key instantly — 10 blockchain certifications included. No wallet, no payment, no credit card required. This is the recommended first step for AI agents integrating with xproof.",
            security: [],
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    required: ["agent_name"],
                    properties: {
                      agent_name: { type: "string", minLength: 1, maxLength: 100, description: "A unique name for your agent", example: "my-trading-bot" },
                      webhook_url: { type: "string", format: "uri", description: "Optional HTTPS webhook URL to receive certification notifications", example: "https://your-agent.example.com/webhooks/xproof" },
                    },
                  },
                },
              },
            },
            responses: {
              "201": {
                description: "Trial registration successful — API key returned immediately",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        api_key: { type: "string", description: "pm_ prefixed API key — use as Bearer token in Authorization header", example: "pm_abc123..." },
                        agent_name: { type: "string" },
                        trial: {
                          type: "object",
                          properties: {
                            quota: { type: "integer", example: 10 },
                            remaining: { type: "integer", example: 10 },
                            reset: { type: "string", description: "Trial does not reset — quota is lifetime" },
                          },
                        },
                        certify_endpoint: { type: "string", format: "uri", description: "Use this URL to certify files: POST /api/proof with Authorization: Bearer pm_YOUR_KEY" },
                        message: { type: "string" },
                      },
                    },
                  },
                },
              },
              "400": { description: "Invalid request (agent_name missing or malformed)" },
              "409": { description: "Agent name already registered" },
              "429": { description: "Too many registrations from this IP" },
            },
          },
        },
        "/api/agent/status": {
          get: {
            summary: "Check agent trial status",
            description: "Returns the remaining trial quota and usage statistics for the authenticated agent.",
            responses: {
              "200": {
                description: "Agent status",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        agent_name: { type: "string" },
                        is_trial: { type: "boolean" },
                        trial_quota: { type: "integer", example: 10 },
                        trial_used: { type: "integer", example: 3 },
                        trial_remaining: { type: "integer", example: 7 },
                        credit_balance: { type: "integer", description: "Prepaid credit balance (post-trial)" },
                      },
                    },
                  },
                },
              },
              "401": { description: "API key required" },
            },
          },
        },
        "/api/batch": {
          post: {
            summary: "Batch certify multiple files",
            description: "Certify up to 50 files in a single request. Each file is recorded individually on MultiversX blockchain. Consumes one credit per file. Returns an array of proof results.",
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    required: ["files"],
                    properties: {
                      files: {
                        type: "array",
                        maxItems: 50,
                        description: "Array of files to certify",
                        items: {
                          type: "object",
                          required: ["file_hash", "filename"],
                          properties: {
                            file_hash: { type: "string", description: "SHA-256 hash (64 hex chars)", example: "a1b2c3d4e5f678901234567890123456789012345678901234567890123456ab" },
                            filename: { type: "string", example: "report.pdf" },
                            author_name: { type: "string", example: "AI Agent" },
                            metadata: { type: "object", description: "Optional key-value metadata (searchable)", additionalProperties: true },
                          },
                        },
                      },
                      webhook_url: { type: "string", format: "uri", description: "Optional HTTPS URL to receive notifications for each certified file" },
                    },
                  },
                },
              },
            },
            responses: {
              "207": {
                description: "Multi-status — array of results, one per file. Each result has its own status code.",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        results: {
                          type: "array",
                          items: {
                            type: "object",
                            properties: {
                              filename: { type: "string" },
                              file_hash: { type: "string" },
                              status: { type: "string", enum: ["certified", "already_certified", "error"] },
                              proof_id: { type: "string", format: "uuid" },
                              verify_url: { type: "string", format: "uri" },
                              blockchain: { type: "object", properties: { transaction_hash: { type: "string" }, explorer_url: { type: "string", format: "uri" } } },
                            },
                          },
                        },
                        summary: {
                          type: "object",
                          properties: {
                            total: { type: "integer" },
                            certified: { type: "integer" },
                            already_certified: { type: "integer" },
                            errors: { type: "integer" },
                          },
                        },
                      },
                    },
                  },
                },
              },
              "400": { description: "Invalid request (too many files, missing fields)" },
              "401": { description: "API key required" },
              "402": { description: "Payment required — trial exhausted or no credits (x402 protocol response body includes payment instructions)" },
              "429": { description: "Rate limit exceeded" },
            },
          },
        },
      },
    };

    res.json(openApiSpec);
  });

  // ============================================
  // LLM-READY ROUTES (AI-first documentation)
  // ============================================

  function getNetworkLabel(chainId: string): string {
    switch (chainId) {
      case "1": return "mainnet";
      case "D": return "devnet";
      case "T": return "testnet";
      default: return "mainnet";
    }
  }

  function buildCanonicalId(chainId: string, txHash: string | null): string | null {
    if (!txHash) return null;
    return `xproof:mvx:${getNetworkLabel(chainId)}:tx:${txHash}`;
  }

  // Genesis certification data (first xproof certification)
  const GENESIS_CERTIFICATION = {
    canonical_id: "xproof:mvx:mainnet:tx:f376c0809d5c8fd91f854d39cf6f9f83ac3d80231477538a1b423db0537aad7e",
    id: "genesis",
    type: "proof_of_existence",
    version: "2.0",
    confidence: "cryptographically-certified",
    file_name: "XPROOF - Genesis.pdf",
    file_hash: "173200d6fa0d1577b456bb85dc505193e31dd8be5fc69bd4e461612a588427de",
    hash_algorithm: "SHA-256",
    author: "Jason Petitfourg",
    timestamp_utc: "2025-12-12T20:28:00Z",
    blockchain: {
      network: "MultiversX Mainnet",
      chain_id: "1",
      transaction_hash: "f376c0809d5c8fd91f854d39cf6f9f83ac3d80231477538a1b423db0537aad7e",
      explorer_url: "https://explorer.multiversx.com/transactions/f376c0809d5c8fd91f854d39cf6f9f83ac3d80231477538a1b423db0537aad7e",
      gas_cost_egld: "0.0002935",
    },
    verification: {
      method: "SHA-256 hash comparison",
      instructions: [
        "Compute SHA-256 hash of the original file",
        "Compare with file_hash in this proof",
        "Verify transaction on MultiversX explorer",
        "Confirm transaction data contains the file hash"
      ]
    },
    significance: "This is the first certification ever created on xproof, establishing the genesis of the platform."
  };

  // /.well-known/xproof.md - Canonical specification

  app.get("/api/acp/health", (req, res) => {
    const mx8004 = isMX8004Configured();
    res.json({
      status: "operational",
      service: "xproof",
      version: "1.0",
      timestamp: new Date().toISOString(),
      mx8004_enabled: mx8004,
      endpoints: {
        products: "/api/acp/products",
        checkout: "/api/acp/checkout",
        confirm: "/api/acp/confirm",
        openapi: "/api/acp/openapi.json",
        mx8004_status: "/api/mx8004/status",
        agent_reputation: "/api/agent/:nonce/reputation",
      }
    });
  });
}
