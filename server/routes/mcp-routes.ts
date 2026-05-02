import { type Express } from "express";
import { logger } from "../logger";
import { paymentRateLimiter } from "../reliability";
import { createMcpServer, authenticateApiKey } from "../mcp";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

export function registerMcpRoutesRoutes(app: Express) {
  app.post("/mcp", paymentRateLimiter, async (req, res) => {
    try {
      const auth = await authenticateApiKey(req.headers.authorization);
      const baseUrl = `https://${req.get('host')}`;

      const method = req.body?.method;
      const toolName = req.body?.params?.name;

      // Block all write tools at transport level when the caller is not authenticated.
      // Each tool also performs an internal auth check, but this early return prevents
      // the MCP server from even initialising for unauthenticated write calls.
      const WRITE_TOOLS = new Set(["certify_file", "certify_with_confidence", "audit_agent_session"]);
      if (method === "tools/call" && WRITE_TOOLS.has(toolName) && !auth.valid) {
        return res.status(200).json({
          jsonrpc: "2.0",
          id: req.body?.id || null,
          error: {
            code: -32600,
            message: `Authentication required. Include 'Authorization: Bearer pm_xxx' header for ${toolName}.`,
          },
        });
      }

      const xPaymentHeader = req.headers["x-payment"] as string | undefined;
      const host = req.get('host') || '';
      // Forward the caller's IP so register_free_trial can enforce the same
      // per-IP hourly trial-issuance quota as POST /api/agent/register.
      const clientIp = req.headers["x-forwarded-for"]?.toString().split(",")[0]?.trim() || req.ip || "unknown";
      const mcpServer = await createMcpServer({ baseUrl, auth, xPaymentHeader, host, clientIp });

      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
      });

      res.on("close", () => {
        transport.close();
      });

      await mcpServer.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (error) {
      logger.withRequest(req).error("MCP error");
      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: "2.0",
          error: { code: -32603, message: "Internal server error" },
          id: null,
        });
      }
    }
  });

  app.get("/mcp", (_req, res) => {
    res.status(405).json({
      jsonrpc: "2.0",
      error: { code: -32601, message: "Method not allowed. Use POST for MCP requests." },
      id: null,
    });
  });

  app.delete("/mcp", (_req, res) => {
    res.status(204).end();
  });
}
