import type { Request, Response, NextFunction } from "express";
import { db } from "./db";
import { certifications } from "@shared/schema";
import { eq } from "drizzle-orm";
import { logger } from "./logger";

const CRAWLER_USER_AGENTS = [
  "ChatGPT", "GPTBot", "Googlebot", "Bingbot", "Twitterbot",
  "facebookexternalhit", "LinkedInBot", "Slurp", "DuckDuckBot",
  "Baiduspider", "YandexBot", "Applebot", "ia_archiver", "Discordbot",
  "WhatsApp", "Telegram", "Slackbot", "Embedly", "Quora Link Preview",
  "Showyoubot", "outbrain", "Pinterest", "Pinterestbot", "Slack-ImgProxy",
  "vkShare", "W3C_Validator", "Redditbot", "Rogerbot", "AhrefsBot",
  "SemrushBot",
];

const SKIP_EXTENSIONS = /\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map|json|xml|txt|pdf|zip|webp|avif|mp4|webm)$/i;
const SKIP_PATHS = ["/api/", "/.well-known/", "/mcp", "/llms.txt", "/llms-full.txt", "/robots.txt", "/sitemap.xml", "/learn/", "/dashboard", "/settings", "/agent-tools/", "/genesis.proof.json"];

function isCrawler(userAgent: string): boolean {
  const ua = userAgent.toLowerCase();
  return CRAWLER_USER_AGENTS.some(bot => ua.includes(bot.toLowerCase()));
}

function shouldSkip(path: string): boolean {
  if (SKIP_EXTENSIONS.test(path)) return true;
  return SKIP_PATHS.some(skip => path.startsWith(skip));
}

function commonHead(title: string, description: string, canonicalUrl: string, ogType: string = "website") {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1">
<title>${escapeHtml(title)}</title>
<meta name="description" content="${escapeHtml(description)}">
<meta name="robots" content="index, follow">
<link rel="canonical" href="${escapeHtml(canonicalUrl)}">

<meta property="og:type" content="${ogType}">
<meta property="og:title" content="${escapeHtml(title)}">
<meta property="og:description" content="${escapeHtml(description)}">
<meta property="og:url" content="${escapeHtml(canonicalUrl)}">
<meta property="og:site_name" content="xproof">
<meta property="og:image" content="https://xproof.app/icon-512.png">

<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="${escapeHtml(title)}">
<meta name="twitter:description" content="${escapeHtml(description)}">
<meta name="twitter:image" content="https://xproof.app/icon-512.png">

<link rel="icon" href="/favicon.ico" sizes="32x32">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="manifest" href="/site.webmanifest">
<meta name="theme-color" content="#10b981">

<meta name="keywords" content="blockchain certification, proof of existence, MultiversX, AI agent, x402, MCP, proof of authorship, timestamp proof, SHA-256, agent commerce">
<meta name="author" content="xproof">

<link rel="ai-plugin" href="/.well-known/ai-plugin.json">
<link rel="openapi" href="/api/acp/openapi.json" type="application/json">
<meta name="ai:service" content="proof-of-existence">
<meta name="ai:api" content="/api/acp/products">
<meta name="ai:spec" content="/.well-known/xproof.md">

<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
</head>`;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function renderHomePage(baseUrl: string): string {
  const title = "xproof — Proof primitive for AI agents & humans on MultiversX";
  const description = "Verifiable proofs of existence, authorship, and agent output — anchored on MultiversX blockchain. API-first, x402-compatible, built for AI agents and humans. $0.05 per proof.";

  return `${commonHead(title, description, baseUrl)}
<body>
<header>
  <nav>
    <a href="${baseUrl}"><strong>xproof</strong></a>
  </nav>
</header>

<main>
  <section>
    <h1>Prove that's yours. Forever.</h1>
    <p>An irrefutable proof, recognized worldwide, impossible to falsify or delete.</p>
    <p>$0.05 per certification - Unlimited</p>
    <a href="${baseUrl}/certify">Certify a file</a>
  </section>

  <section>
    <h2>How it works - 3 simple steps</h2>
    <p>No technical knowledge required. If you can send an email, you can use xproof.</p>
    <ol>
      <li>
        <h3>Upload your file</h3>
        <p>Drag any file: photo, document, music, code... Your file stays private, it is never uploaded.</p>
      </li>
      <li>
        <h3>We compute the fingerprint</h3>
        <p>A unique fingerprint (SHA-256 hash) is computed locally. It's like the DNA of your file.</p>
      </li>
      <li>
        <h3>Engraved on the blockchain</h3>
        <p>The fingerprint is permanently recorded on the blockchain. You receive a PDF certificate with a QR code.</p>
      </li>
    </ol>
  </section>

  <section>
    <h2>Simple pricing - One price. No subscription.</h2>
    <p>$0.05 per certification. Pay only for what you use. No hidden fees, no commitment.</p>
    <ul>
      <li>Unlimited certifications</li>
      <li>Downloadable PDF certificate</li>
      <li>Public verification page</li>
      <li>Verification QR code</li>
      <li>MultiversX blockchain</li>
    </ul>
  </section>

  <section>
    <h2>Frequently asked questions</h2>
    <dl>
      <dt>Is my file uploaded to your servers?</dt>
      <dd>No, never. Your file stays on your device. Only its fingerprint (a unique 64-character code) is computed locally and recorded on the blockchain.</dd>
      <dt>What is the MultiversX blockchain?</dt>
      <dd>MultiversX is a high-performance, eco-friendly European blockchain. Unlike Bitcoin, it consumes very little energy.</dd>
      <dt>Does it have legal value?</dt>
      <dd>Yes. Blockchain timestamping is recognized in many jurisdictions as proof of prior existence.</dd>
    </dl>
  </section>

  <section>
    <h2>Protect your first creation</h2>
    <p>Join creators who secure their work. Only $0.05 per certification.</p>
  </section>
</main>

<footer>
  <p>&copy; ${new Date().getFullYear()} xproof. All rights reserved.</p>
  <p>Powered by <a href="https://multiversx.com">MultiversX</a></p>
  <nav>
    <a href="${baseUrl}/agents">For AI Agents</a> |
    <a href="${baseUrl}/legal/mentions">Legal notices</a> |
    <a href="${baseUrl}/legal/privacy">Privacy policy</a> |
    <a href="${baseUrl}/legal/terms">Terms</a>
  </nav>
</footer>

<script type="application/ld+json">
${JSON.stringify({
  "@context": "https://schema.org",
  "@type": "Organization",
  "name": "xproof",
  "url": "https://xproof.app",
  "description": description,
  "sameAs": [],
  "offers": {
    "@type": "Offer",
    "name": "Proof of Existence Certification",
    "description": "Verifiable proof of existence, authorship, and agent output on MultiversX blockchain",
    "price": "0.05",
    "priceCurrency": "USD"
  }
}, null, 2)}
</script>
</body>
</html>`;
}

function renderCertifyPage(baseUrl: string): string {
  const title = "Certify a File - xproof";
  const description = "Certify your digital files on the MultiversX blockchain. Upload any document, image, or code file to create an immutable proof of ownership with SHA-256 hashing.";

  return `${commonHead(title, description, `${baseUrl}/certify`)}
<body>
<header>
  <nav>
    <a href="${baseUrl}"><strong>xproof</strong></a>
  </nav>
</header>

<main>
  <h1>Certify your file</h1>
  <p>Drop any file to create an immutable proof on the blockchain.</p>
  <p>Your file stays private - only its SHA-256 fingerprint is recorded on MultiversX.</p>

  <section>
    <h2>How certification works</h2>
    <ol>
      <li>Select or drag your file</li>
      <li>A unique SHA-256 hash is computed locally on your device</li>
      <li>Sign the transaction with your MultiversX wallet</li>
      <li>Receive a downloadable PDF certificate with QR code</li>
    </ol>
  </section>

  <p><a href="${baseUrl}">Back to home</a></p>
</main>

<footer>
  <p>&copy; ${new Date().getFullYear()} xproof. Powered by <a href="https://multiversx.com">MultiversX</a></p>
</footer>
</body>
</html>`;
}

function renderProofPage(baseUrl: string, cert: any): string {
  const title = `${cert.fileName} - Blockchain Proof | xproof`;
  const description = `Blockchain proof for ${cert.fileName}. SHA-256: ${cert.fileHash.substring(0, 16)}... Certified on ${cert.createdAt ? new Date(cert.createdAt).toISOString().split('T')[0] : 'MultiversX blockchain'}. Status: ${cert.blockchainStatus || 'confirmed'}.`;
  const proofUrl = `${baseUrl}/proof/${cert.id}`;
  const certDate = cert.createdAt ? new Date(cert.createdAt).toLocaleString("en-US") : "Unknown";

  return `${commonHead(title, description, proofUrl, "article")}
<body>
<header>
  <nav>
    <a href="${baseUrl}"><strong>xproof</strong></a>
  </nav>
</header>

<main>
  <h1>${escapeHtml(cert.fileName)} - Blockchain Proof</h1>
  <p>The authenticity of this document has been ${cert.blockchainStatus === "confirmed" ? "verified" : "recorded"} on the MultiversX blockchain.</p>

  <section>
    <h2>File information</h2>
    <dl>
      <dt>File name</dt>
      <dd>${escapeHtml(cert.fileName)}</dd>
      <dt>SHA-256 hash</dt>
      <dd><code>${escapeHtml(cert.fileHash)}</code></dd>
      <dt>Certification date</dt>
      <dd>${escapeHtml(certDate)}</dd>
      <dt>Status</dt>
      <dd>${cert.blockchainStatus === "confirmed" ? "Verified on blockchain" : "Pending confirmation"}</dd>
      ${cert.authorName ? `<dt>Certified by</dt><dd>${escapeHtml(cert.authorName)}</dd>` : ""}
      ${cert.fileSize ? `<dt>File size</dt><dd>${cert.fileSize} bytes</dd>` : ""}
    </dl>
  </section>

  ${cert.transactionHash ? `
  <section>
    <h2>Blockchain details</h2>
    <dl>
      <dt>Transaction hash</dt>
      <dd><code>${escapeHtml(cert.transactionHash)}</code></dd>
      ${cert.transactionUrl ? `<dt>Explorer</dt><dd><a href="${escapeHtml(cert.transactionUrl)}">View on MultiversX explorer</a></dd>` : ""}
    </dl>
  </section>` : ""}

  <p><a href="${baseUrl}">Certify your files on xproof</a></p>
</main>

<footer>
  <p>&copy; ${new Date().getFullYear()} xproof. Powered by <a href="https://multiversx.com">MultiversX</a></p>
</footer>

<script type="application/ld+json">
${JSON.stringify({
  "@context": "https://schema.org",
  "@type": "CreativeWork",
  "name": cert.fileName,
  "description": `Blockchain-certified proof of existence for ${cert.fileName}`,
  "dateCreated": cert.createdAt ? new Date(cert.createdAt).toISOString() : undefined,
  "identifier": cert.fileHash,
  "url": proofUrl,
  "publisher": {
    "@type": "Organization",
    "name": "xproof",
    "url": "https://xproof.app"
  }
}, null, 2)}
</script>
</body>
</html>`;
}

function renderProofNotFound(baseUrl: string): string {
  const title = "Proof Not Found - xproof";
  const description = "The certification proof you are looking for does not exist or is not public.";

  return `${commonHead(title, description, baseUrl)}
<body>
<header>
  <nav>
    <a href="${baseUrl}"><strong>xproof</strong></a>
  </nav>
</header>

<main>
  <h1>Proof not found</h1>
  <p>The certification proof you are looking for does not exist or is not public.</p>
  <p><a href="${baseUrl}">Back to home</a> | <a href="${baseUrl}/certify">Certify a file</a></p>
</main>

<footer>
  <p>&copy; ${new Date().getFullYear()} xproof. Powered by <a href="https://multiversx.com">MultiversX</a></p>
</footer>
</body>
</html>`;
}

function renderAgentsPage(baseUrl: string): string {
  const title = "Agent Integrations — xproof";
  const description = "xproof works everywhere agents work. MCP, x402, ACP, MX-8004, OpenClaw, GitHub Action. One proof layer, every protocol. $0.05 per proof.";

  return `${commonHead(title, description, `${baseUrl}/agents`)}
<body>
<header>
  <nav>
    <a href="${baseUrl}"><strong>xproof</strong></a>
  </nav>
</header>

<main>
  <h1>xproof for AI Agents</h1>
  <p>The deterministic, blockchain-backed proof-of-existence API designed for autonomous systems. No human interaction required.</p>

  <section>
    <h2>What xproof guarantees</h2>
    <ul>
      <li>Immutable SHA-256 anchoring on MultiversX</li>
      <li>Deterministic (same input = same output)</li>
      <li>Verifiable without xproof (on-chain)</li>
      <li>Non-custodial (files never leave client)</li>
      <li>$0.05 per certification in EGLD</li>
    </ul>
  </section>

  <section>
    <h2>Simplest Integration: POST /api/proof</h2>
    <p>One API call to certify a file. No checkout flow, no transaction management. Just send a hash and get a proof.</p>
    <code>POST ${baseUrl}/api/proof</code>
    <p>Request: { "file_hash": "sha256...", "filename": "document.pdf" }</p>
    <p>Response: { "proof_id": "...", "verify_url": "...", "certificate_url": "...", "blockchain": "MultiversX" }</p>
    <p>Authentication: Bearer token with pm_ prefix API key.</p>
  </section>

  <section>
    <h2>Batch Certification: POST /api/batch</h2>
    <p>Certify up to 50 files in a single API call. Ideal for agents that generate multiple outputs.</p>
    <code>POST ${baseUrl}/api/batch</code>
    <p>Request: { "files": [{ "file_hash": "...", "filename": "..." }, ...], "author_name": "optional" }</p>
    <p>Response: { "batch_id": "...", "total": N, "created": X, "results": [...] }</p>
    <p>Authentication: Bearer token with pm_ prefix API key.</p>
  </section>

  <section>
    <h2>MCP Server (Model Context Protocol)</h2>
    <p>Native MCP integration for Claude, GPT, Cursor, and any MCP-compatible agent.</p>
    <code>POST ${baseUrl}/mcp</code>
    <p>Transport: Streamable HTTP (JSON-RPC 2.0). Protocol version: 2025-03-26.</p>
    <p>Tools: certify_file, verify_proof, get_proof, discover_services.</p>
    <p>Authentication: Bearer token with pm_ prefix API key for certify_file. Other tools are public.</p>
  </section>

  <section>
    <h2>ACP Flow - 3 API calls</h2>
    <p>Agent Commerce Protocol for agents that manage their own transactions.</p>
    <ol>
      <li>
        <h3>Discover</h3>
        <p>Fetch available products and pricing.</p>
        <code>GET ${baseUrl}/api/acp/products</code>
      </li>
      <li>
        <h3>Certify</h3>
        <p>Submit a file hash for blockchain anchoring.</p>
        <code>POST ${baseUrl}/api/acp/checkout</code>
      </li>
      <li>
        <h3>Confirm</h3>
        <p>Finalize the certification with the transaction hash.</p>
        <code>POST ${baseUrl}/api/acp/confirm</code>
      </li>
    </ol>
  </section>

  <section>
    <h2>Discovery Endpoints</h2>
    <ul>
      <li><a href="${baseUrl}/llms.txt">llms.txt</a> - LLM-friendly summary</li>
      <li><a href="${baseUrl}/llms-full.txt">llms-full.txt</a> - Extended documentation</li>
      <li><a href="${baseUrl}/.well-known/mcp.json">mcp.json</a> - Model Context Protocol manifest</li>
      <li><a href="${baseUrl}/.well-known/agent.json">agent.json</a> - Agent Protocol manifest</li>
      <li><a href="${baseUrl}/.well-known/ai-plugin.json">ai-plugin.json</a> - OpenAI plugin manifest</li>
      <li><a href="${baseUrl}/api/acp/openapi.json">openapi.json</a> - OpenAPI 3.0 specification</li>
      <li><a href="${baseUrl}/api/acp/products">products</a> - Product discovery (JSON)</li>
      <li><a href="${baseUrl}/api/acp/health">health</a> - Health check</li>
    </ul>
  </section>

  <section>
    <h2>Verification Badges</h2>
    <p>Embed a dynamic verification badge in your README or documentation.</p>
    <code>![xProof Verified](https://xproof.app/badge/{proof_id})</code>
    <p>Badge links to the public proof page. Status updates automatically: Verified (green), Pending (yellow), Not Found (red).</p>
  </section>

  <section>
    <h2>Framework Integrations</h2>
    <ul>
      <li>LangChain - Python tool for LangChain agent pipelines</li>
      <li>CrewAI - Python tool for CrewAI multi-agent systems</li>
      <li>Custom GPTs - OpenAPI actions schema for ChatGPT custom GPTs</li>
    </ul>
  </section>
</main>

<footer>
  <p>&copy; ${new Date().getFullYear()} xproof. Built on <a href="https://multiversx.com">MultiversX</a></p>
</footer>
</body>
</html>`;
}

export function prerenderMiddleware() {
  return async (req: Request, res: Response, next: NextFunction) => {
    const userAgent = req.get("user-agent") || "";
    if (!isCrawler(userAgent)) {
      return next();
    }

    const accept = req.get("accept") || "";
    if (!accept.includes("text/html") && !accept.includes("*/*") && accept !== "") {
      return next();
    }

    const path = req.path;
    if (shouldSkip(path)) {
      return next();
    }

    const baseUrl = `${req.protocol}://${req.get("host")}`;

    try {
      if (path === "/" || path === "") {
        return res.status(200).set("Content-Type", "text/html").send(renderHomePage(baseUrl));
      }

      if (path === "/certify") {
        return res.status(200).set("Content-Type", "text/html").send(renderCertifyPage(baseUrl));
      }

      if (path === "/agents") {
        return res.status(200).set("Content-Type", "text/html").send(renderAgentsPage(baseUrl));
      }

      const proofMatch = path.match(/^\/proof\/([^/]+)$/);
      if (proofMatch) {
        const proofId = proofMatch[1];
        try {
          const [cert] = await db.select().from(certifications).where(eq(certifications.id, proofId));
          if (cert && cert.isPublic) {
            return res.status(200).set("Content-Type", "text/html").send(renderProofPage(baseUrl, cert));
          }
        } catch (e) {
          logger.error("Error fetching proof", { component: "prerender" });
        }
        return res.status(404).set("Content-Type", "text/html").send(renderProofNotFound(baseUrl));
      }

      return next();
    } catch (error) {
      logger.error("Prerender error", { component: "prerender" });
      return next();
    }
  };
}
