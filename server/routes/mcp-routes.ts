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

      // register_free_trial has been removed from the MCP server. Trial registration
      // must go through POST /api/agent/register (REST), which enforces per-IP hourly
      // quotas, paymentRateLimiter, and duplicate-name checks. Block all callers
      // (authenticated or not) with a clear migration message so existing integrations
      // self-heal rather than receiving a confusing generic "tool not found" error.
      if (method === "tools/call" && toolName === "register_free_trial") {
        return res.status(200).json({
          jsonrpc: "2.0",
          id: req.body?.id || null,
          error: {
            code: -32601,
            message: `register_free_trial is not available via MCP. Use POST ${req.protocol}://${req.get("host")}/api/agent/register with body {"agent_name":"your-agent"} to obtain a free trial API key, then include Authorization: Bearer pm_xxx in subsequent MCP requests.`,
          },
        });
      }

      // Block all other write tools at transport level when the caller is not
      // authenticated. Each tool also performs an internal auth check, but this
      // early return prevents the MCP server from even initialising for
      // unauthenticated write calls.
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
      const mcpServer = await createMcpServer({ baseUrl, auth, xPaymentHeader, host });

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
