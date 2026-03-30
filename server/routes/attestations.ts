import { type Express } from "express";
import { db } from "../db";
import { logger } from "../logger";
import { certifications, users, attestations } from "@shared/schema";
import { eq, desc, sql, and, gte, count } from "drizzle-orm";
import { z } from "zod";
import { isWalletAuthenticated } from "../walletAuth";
import { attestationIssuanceRateLimiter, publicSearchRateLimiter } from "../reliability";
import { computeTrustScoreByWallet } from "../trust";

export function registerAttestationsRoutes(app: Express) {
  // ============================================
  // Attestation routes — Domain-specific trust signals
  // ============================================

  // POST /api/attestation — issue an attestation (issuer must be wallet-authenticated)
  app.post("/api/attestation", isWalletAuthenticated, attestationIssuanceRateLimiter, async (req: any, res) => {
    try {
      const issuerWallet = req.walletAddress;
      const schema = z.object({
        subjectWallet: z.string().min(3, "Subject wallet required"),
        issuerName: z.string().min(1).max(120),
        domain: z.enum(["healthcare", "finance", "legal", "security", "research", "other"]),
        standard: z.string().min(1).max(80),
        title: z.string().min(1).max(200),
        description: z.string().max(500).optional().nullable(),
        expiresAt: z.string().datetime().optional().nullable(),
        webhookUrl: z.string().url().optional().nullable(),
      });

      const data = schema.parse(req.body);

      if (data.subjectWallet === issuerWallet) {
        return res.status(400).json({ message: "Cannot self-attest" });
      }

      const issuerCertCheck = await db.execute(sql`
        SELECT COUNT(*) AS cnt
        FROM certifications c
        JOIN users u ON u.id = c.user_id
        WHERE u.wallet_address = ${issuerWallet}
          AND c.blockchain_status = 'confirmed'
      `);
      const issuerConfirmedCerts = Number((issuerCertCheck.rows[0] as any)?.cnt || 0);
      if (issuerConfirmedCerts < 3) {
        return res.status(403).json({
          message: "Minimum 3 confirmed on-chain certifications required to issue attestations.",
          issuer_confirmed_certs: issuerConfirmedCerts,
          required: 3,
        });
      }

      const dupCheck = await db.execute(sql`
        SELECT id FROM attestations
        WHERE subject_wallet = ${data.subjectWallet}
          AND issuer_wallet = ${issuerWallet}
          AND domain = ${data.domain}
          AND standard = ${data.standard}
          AND status = 'active'
        LIMIT 1
      `);
      if ((dupCheck.rows as any[])[0]?.id) {
        return res.status(409).json({ message: "An active attestation for this domain/standard already exists from you for this agent." });
      }

      const result = await db.execute(sql`
        INSERT INTO attestations (subject_wallet, issuer_wallet, issuer_name, domain, standard, title, description, expires_at, status, webhook_url)
        VALUES (
          ${data.subjectWallet},
          ${issuerWallet},
          ${data.issuerName},
          ${data.domain},
          ${data.standard},
          ${data.title},
          ${data.description ?? null},
          ${data.expiresAt ? new Date(data.expiresAt) : null},
          'active',
          ${data.webhookUrl ?? null}
        )
        RETURNING *
      `);

      logger.info("Attestation issued", { issuer: issuerWallet, subject: data.subjectWallet, domain: data.domain, standard: data.standard });
      res.status(201).json((result.rows as any[])[0]);
    } catch (err: any) {
      if (err.name === "ZodError") {
        return res.status(400).json({ message: "Validation error", errors: err.errors });
      }
      logger.error("Failed to create attestation", { error: err.message });
      res.status(500).json({ error: err.message });
    }
  });

  // GET /api/attestations/expiring — list attestations expiring within N days (auth required, must be before :wallet)
  app.get("/api/attestations/expiring", isWalletAuthenticated, async (req: any, res) => {
    try {
      const issuerWallet = req.walletAddress;
      const days = Math.min(Math.max(parseInt(req.query.days as string || "30"), 1), 90);
      const result = await db.execute(sql`
        SELECT id, subject_wallet, issuer_name, domain, standard, title, expires_at, status, created_at
        FROM attestations
        WHERE issuer_wallet = ${issuerWallet}
          AND status = 'active'
          AND expires_at IS NOT NULL
          AND expires_at BETWEEN NOW() AND NOW() + (${days} || ' days')::interval
        ORDER BY expires_at ASC
      `);
      res.json({ days, expiring: result.rows });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // GET /api/attestations/:wallet — public, returns all active attestations for a wallet
  app.get("/api/attestations/:wallet", async (req, res) => {
    try {
      const { wallet } = req.params;
      const now = new Date();
      const result = await db.execute(sql`
        SELECT id, subject_wallet, issuer_wallet, issuer_name, domain, standard, title, description, expires_at, status, created_at
        FROM attestations
        WHERE subject_wallet = ${wallet}
          AND status = 'active'
          AND (expires_at IS NULL OR expires_at > ${now})
        ORDER BY created_at DESC
      `);
      res.json(result.rows);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // GET /api/attestation/:id — public, returns a single attestation by ID
  app.get("/api/attestation/:id", async (req, res) => {
    try {
      const { id } = req.params;
      const result = await db.execute(sql`
        SELECT id, subject_wallet, issuer_wallet, issuer_name, domain, standard, title, description, expires_at, status, revoked_at, created_at
        FROM attestations
        WHERE id = ${id}
        LIMIT 1
      `);
      const row = (result.rows as any[])[0];
      if (!row) return res.status(404).json({ error: "Attestation not found" });
      res.json(row);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // DELETE /api/attestation/:id — revoke an attestation (issuer only)
  app.delete("/api/attestation/:id", isWalletAuthenticated, async (req: any, res) => {
    try {
      const issuerWallet = req.walletAddress;
      const { id } = req.params;

      const existing = await db.execute(sql`
        SELECT id, issuer_wallet, status FROM attestations WHERE id = ${id} LIMIT 1
      `);
      const row = (existing.rows as any[])[0];

      if (!row) {
        return res.status(404).json({ message: "Attestation not found" });
      }
      if (row.issuer_wallet !== issuerWallet) {
        return res.status(403).json({ message: "Only the issuer can revoke this attestation" });
      }
      if (row.status === "revoked") {
        return res.status(409).json({ message: "Attestation already revoked" });
      }

      const fullRow = await db.execute(sql`
        SELECT webhook_url FROM attestations WHERE id = ${id} LIMIT 1
      `);
      const webhookUrl = (fullRow.rows as any[])[0]?.webhook_url;

      await db.execute(sql`
        UPDATE attestations SET status = 'revoked', revoked_at = NOW() WHERE id = ${id}
      `);

      if (webhookUrl) {
        try {
          const timestamp = Math.floor(Date.now() / 1000).toString();
          const payload = JSON.stringify({
            event: "attestation.revoked",
            attestation_id: id,
            issuer_wallet: issuerWallet,
            revoked_at: new Date().toISOString(),
          });
          const crypto = await import("crypto");
          const secret = process.env.SESSION_SECRET || "xproof-webhook-secret";
          const signature = crypto.createHmac("sha256", secret).update(`${timestamp}.${payload}`).digest("hex");
          fetch(webhookUrl, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "X-xProof-Signature": signature,
              "X-xProof-Timestamp": timestamp,
              "X-xProof-Event": "attestation.revoked",
              "X-xProof-Delivery": id,
              "User-Agent": "xProof-Webhook/1.0",
            },
            body: payload,
            signal: AbortSignal.timeout(10000),
          }).catch(() => {});
        } catch {}
      }

      logger.info("Attestation revoked", { issuer: issuerWallet, attestationId: id });
      res.json({ success: true, id });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // GET /api/my-attestations/issued — attestations issued by the authenticated user
  app.get("/api/my-attestations/issued", isWalletAuthenticated, async (req: any, res) => {
    try {
      const issuerWallet = req.walletAddress;
      const result = await db.execute(sql`
        SELECT id, subject_wallet, issuer_name, domain, standard, title, description, expires_at, status, created_at, revoked_at
        FROM attestations
        WHERE issuer_wallet = ${issuerWallet}
        ORDER BY created_at DESC
        LIMIT 50
      `);
      res.json(result.rows);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // GET /api/issuer/:wallet — public issuer directory profile with all issued attestations
  app.get("/api/issuer/:wallet", async (req, res) => {
    try {
      const { wallet } = req.params;

      const stats = await db.execute(sql`
        SELECT
          COUNT(*) FILTER (WHERE status = 'active') AS active_count,
          COUNT(*) FILTER (WHERE status = 'revoked') AS revoked_count,
          COUNT(DISTINCT domain) AS domain_count,
          COUNT(DISTINCT subject_wallet) AS agents_attested,
          MIN(created_at) AS first_issued_at,
          MAX(created_at) AS last_issued_at
        FROM attestations
        WHERE issuer_wallet = ${wallet}
      `);

      const issued = await db.execute(sql`
        SELECT id, subject_wallet, issuer_name, domain, standard, title, description, expires_at, status, revoked_at, created_at
        FROM attestations
        WHERE issuer_wallet = ${wallet}
        ORDER BY created_at DESC
        LIMIT 100
      `);

      const statsRow = (stats.rows as any[])[0] || {};
      res.json({
        issuerWallet: wallet,
        issuerName: ((issued.rows as any[])[0]?.issuer_name) || null,
        activeCount: Number(statsRow.active_count || 0),
        revokedCount: Number(statsRow.revoked_count || 0),
        domainCount: Number(statsRow.domain_count || 0),
        agentsAttested: Number(statsRow.agents_attested || 0),
        firstIssuedAt: statsRow.first_issued_at || null,
        lastIssuedAt: statsRow.last_issued_at || null,
        attestations: issued.rows,
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // POST /api/attestations/batch — batch issue up to 20 attestations at once
  app.post("/api/attestations/batch", isWalletAuthenticated, attestationIssuanceRateLimiter, async (req: any, res) => {
    try {
      const issuerWallet = req.walletAddress;
      const itemSchema = z.object({
        subjectWallet: z.string().min(3),
        issuerName: z.string().min(1).max(120),
        domain: z.enum(["healthcare", "finance", "legal", "security", "research", "other"]),
        standard: z.string().min(1).max(80),
        title: z.string().min(1).max(200),
        description: z.string().max(500).optional().nullable(),
        expiresAt: z.string().datetime().optional().nullable(),
      });
      const batchSchema = z.object({
        attestations: z.array(itemSchema).min(1).max(20),
      });

      const { attestations: items } = batchSchema.parse(req.body);

      const results: any[] = [];
      const errors: any[] = [];

      for (const item of items) {
        try {
          if (item.subjectWallet === issuerWallet) {
            errors.push({ subjectWallet: item.subjectWallet, error: "Cannot self-attest" });
            continue;
          }

          const dup = await db.execute(sql`
            SELECT id FROM attestations
            WHERE subject_wallet = ${item.subjectWallet}
              AND issuer_wallet = ${issuerWallet}
              AND domain = ${item.domain}
              AND standard = ${item.standard}
              AND status = 'active'
            LIMIT 1
          `);
          if ((dup.rows as any[])[0]?.id) {
            errors.push({ subjectWallet: item.subjectWallet, error: "Duplicate active attestation" });
            continue;
          }

          const r = await db.execute(sql`
            INSERT INTO attestations (subject_wallet, issuer_wallet, issuer_name, domain, standard, title, description, expires_at, status)
            VALUES (
              ${item.subjectWallet}, ${issuerWallet}, ${item.issuerName},
              ${item.domain}, ${item.standard}, ${item.title},
              ${item.description ?? null},
              ${item.expiresAt ? new Date(item.expiresAt) : null},
              'active'
            ) RETURNING *
          `);
          results.push((r.rows as any[])[0]);
        } catch (e: any) {
          errors.push({ subjectWallet: item.subjectWallet, error: e.message });
        }
      }

      logger.info("Batch attestation", { issuer: issuerWallet, created: results.length, errors: errors.length });
      res.status(201).json({ created: results.length, error_count: errors.length, results, errors });
    } catch (err: any) {
      if (err.name === "ZodError") {
        return res.status(400).json({ message: "Validation error", errors: err.errors });
      }
      res.status(500).json({ error: err.message });
    }
  });

  // GET /api/trust/:wallet/history — trust score history (last 90 days snapshots)
  app.get("/api/trust/:wallet/history", publicSearchRateLimiter, async (req, res) => {
    try {
      const { wallet } = req.params;
      const days = Math.min(parseInt(req.query.days as string || "90"), 90);

      const result = await db.execute(sql`
        SELECT score, level, cert_total, active_attestations, rank, snapshot_date
        FROM trust_score_snapshots
        WHERE wallet_address = ${wallet}
          AND snapshot_date >= CURRENT_DATE - (${days} || ' days')::interval
        ORDER BY snapshot_date ASC
      `);

      res.json({
        walletAddress: wallet,
        days,
        snapshots: result.rows,
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // GET /agent/:wallet/compliance.pdf — compliance report PDF
  app.get("/agent/:wallet/compliance.pdf", async (req, res) => {
    try {
      const { wallet } = req.params;
      const PDFDocument = (await import("pdfkit")).default;

      const trust = await computeTrustScoreByWallet(wallet);
      if (!trust) {
        return res.status(404).json({ error: "Agent not found" });
      }

      const attestations = await db.execute(sql`
        SELECT domain, standard, title, issuer_name, created_at, expires_at
        FROM attestations
        WHERE subject_wallet = ${wallet} AND status = 'active'
        ORDER BY created_at DESC
      `);

      const [agentUser] = await db.select({ id: users.id }).from(users).where(eq(users.walletAddress, wallet));
      const certs = agentUser ? await db.execute(sql`
        SELECT file_name, file_hash, blockchain_status AS status, created_at, transaction_hash
        FROM certifications
        WHERE user_id = ${agentUser.id}
          AND created_at >= NOW() - INTERVAL '90 days'
        ORDER BY created_at DESC
        LIMIT 50
      `) : { rows: [] };

      const doc = new PDFDocument({ margin: 50, size: "A4" });
      res.setHeader("Content-Type", "application/pdf");
      res.setHeader("Content-Disposition", `attachment; filename="xproof-compliance-${wallet.slice(0, 10)}.pdf"`);
      doc.pipe(res);

      const green = "#10b981";
      const gray = "#6b7280";
      const dark = "#111827";

      doc.fontSize(20).fillColor(green).text("xproof Compliance Report", { align: "center" });
      doc.moveDown(0.3);
      doc.fontSize(10).fillColor(gray).text(`Generated: ${new Date().toUTCString()}`, { align: "center" });
      doc.moveDown(1.5);

      doc.fontSize(13).fillColor(dark).text("Agent Identity", { underline: true });
      doc.moveDown(0.3);
      doc.fontSize(10).fillColor(dark).text(`Wallet: ${wallet}`);
      if (trust.agentName) doc.text(`Name: ${trust.agentName}`);
      doc.text(`Trust Level: ${trust.level} (score ${trust.score})`);
      doc.text(`Total certifications: ${trust.certTotal}`);
      doc.text(`Streak: ${trust.streakWeeks} consecutive weeks`);
      doc.moveDown(1.5);

      const attRows = attestations.rows as any[];
      doc.fontSize(13).fillColor(dark).text("Active Attestations", { underline: true });
      doc.moveDown(0.3);
      if (attRows.length === 0) {
        doc.fontSize(10).fillColor(gray).text("No active attestations");
      } else {
        for (const att of attRows) {
          doc.fontSize(10).fillColor(dark).text(`• [${att.domain.toUpperCase()}] ${att.title}`);
          doc.fontSize(9).fillColor(gray).text(`  Standard: ${att.standard}  |  Issued by: ${att.issuer_name}  |  Date: ${new Date(att.created_at).toLocaleDateString()}`);
          if (att.expires_at) {
            doc.fontSize(9).fillColor(gray).text(`  Expires: ${new Date(att.expires_at).toLocaleDateString()}`);
          }
          doc.moveDown(0.3);
        }
      }
      doc.moveDown(1);

      const certRows = certs.rows as any[];
      doc.fontSize(13).fillColor(dark).text("Recent Certifications (last 90 days)", { underline: true });
      doc.moveDown(0.3);
      if (certRows.length === 0) {
        doc.fontSize(10).fillColor(gray).text("No certifications in this period");
      } else {
        for (const cert of certRows) {
          doc.fontSize(10).fillColor(dark).text(`• ${cert.file_name}`);
          doc.fontSize(9).fillColor(gray).text(`  Hash: ${cert.file_hash}  |  Status: ${cert.status}  |  ${new Date(cert.created_at).toLocaleDateString()}`);
          doc.moveDown(0.2);
        }
      }

      doc.moveDown(2);
      doc.fontSize(9).fillColor(gray).text(`Verified on MultiversX blockchain. Full audit trail: https://xproof.app/agent/${wallet}`, { align: "center" });
      doc.end();
    } catch (err: any) {
      logger.error("PDF generation error", { error: err.message });
      if (!res.headersSent) res.status(500).json({ error: err.message });
    }
  });

  // GET /widget/trust/:wallet.js — embeddable trust badge JS widget
  app.get("/widget/trust/:wallet.js", async (req, res) => {
    try {
      const { wallet } = req.params;
      const baseUrl = `https://${req.get("host")}`;

      const js = `(function(){
  var w="${wallet}";
  var base="${baseUrl}";
  function inject(el){
    var img=document.createElement("img");
    img.src=base+"/badge/trust/"+w+".svg";
    img.alt="xproof trust badge";
    img.style.cssText="height:24px;vertical-align:middle;border:0;";
    img.addEventListener("click",function(){window.open(base+"/agent/"+w,"_blank");});
    img.style.cursor="pointer";
    el.appendChild(img);
  }
  function run(){
    var els=document.querySelectorAll("xproof-badge[wallet='"+w+"'],xproof-badge:not([wallet]),[data-xproof-wallet='"+w+"']");
    if(els.length>0){els.forEach(function(el){inject(el);});}
    else{var d=document.currentScript||document.querySelector("script[src*='"+w+"']");if(d&&d.parentNode){inject(d.parentNode);}}
  }
  if(document.readyState==="loading"){document.addEventListener("DOMContentLoaded",run);}else{run();}
})();`;

      res.setHeader("Content-Type", "application/javascript; charset=utf-8");
      res.setHeader("Cache-Control", "public, max-age=300");
      res.send(js);
    } catch (err: any) {
      res.status(500).send(`/* error: ${err.message} */`);
    }
  });

  // GET /api/user/agent-profile PATCH — also update agentCategory Zod to allow new categories
  app.patch("/api/user/agent-profile/category-extended", isWalletAuthenticated, async (req: any, res) => {
    res.status(410).json({ message: "Use PATCH /api/user/agent-profile" });
  });

  // ============================================
  // Agent Proof Standard — Open composability endpoints
  // ============================================

  const SHA256_REGEX = /^sha256:[a-fA-F0-9]{64}$/;
  const HEX_SIG_REGEX = /^hex:[a-fA-F0-9]{128,}$/;

  const standardProofSchema = z.object({
    version: z.literal("1.0"),
    agent_id: z.string().min(1, "agent_id is required"),
    instruction_hash: z.string().regex(SHA256_REGEX, "Must be sha256: followed by 64 hex chars"),
    action_hash: z.string().regex(SHA256_REGEX, "Must be sha256: followed by 64 hex chars"),
    timestamp: z.string().refine((ts) => !isNaN(Date.parse(ts)), "Must be a valid ISO 8601 timestamp"),
    signature: z.string().regex(HEX_SIG_REGEX, "Must be hex: followed by at least 128 hex chars"),
    action_type: z.string().optional(),
    post_id: z.string().optional(),
    target_author: z.string().optional(),
    session_id: z.string().optional(),
    chain_anchor: z.object({
      chain: z.string(),
      network: z.string().optional(),
      tx_hash: z.string().min(1),
      explorer_url: z.string().url().optional(),
    }).optional(),
    metadata: z.record(z.any()).optional(),
  });

}
