import { z } from "zod";

export const ACTION_TYPES = [
  "trade_execution",
  "code_deploy",
  "data_access",
  "content_generation",
  "api_call",
  "other",
] as const;

export const RISK_LEVELS = ["low", "medium", "high", "critical"] as const;

export const DECISIONS = ["approved", "rejected", "deferred"] as const;

export const auditLogSchema = z.object({
  agent_id: z.string().min(1, "agent_id is required").max(256),
  session_id: z.string().min(1, "session_id is required").max(128),
  action_type: z.enum(ACTION_TYPES, {
    errorMap: () => ({ message: `action_type must be one of: ${ACTION_TYPES.join(", ")}` }),
  }),
  action_description: z.string().min(1, "action_description is required").max(1000),
  inputs_hash: z
    .string()
    .length(64, "inputs_hash must be a SHA-256 hex string (64 chars)")
    .regex(/^[a-fA-F0-9]+$/, "inputs_hash must be a valid hex string"),
  risk_level: z.enum(RISK_LEVELS, {
    errorMap: () => ({ message: `risk_level must be one of: ${RISK_LEVELS.join(", ")}` }),
  }),
  risk_summary: z.string().max(500).optional(),
  decision: z.enum(DECISIONS, {
    errorMap: () => ({ message: `decision must be one of: ${DECISIONS.join(", ")}` }),
  }),
  context: z.record(z.any()).optional(),
  timestamp: z
    .string()
    .refine((v) => !isNaN(Date.parse(v)), { message: "timestamp must be a valid ISO8601 date string" }),
});

export type AgentAuditLog = z.infer<typeof auditLogSchema>;

export const AUDIT_LOG_JSON_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://xproof.app/.well-known/agent-audit-schema.json",
  title: "xProof Agent Audit Log",
  description:
    "Standard schema for certifying an AI agent's session of work on the MultiversX blockchain. " +
    "An agent MUST obtain a proof_id from POST /api/audit before executing any critical action (trade, deployment, data access). " +
    "The proof_id is an immutable, tamper-proof certificate that the agent analyzed the risks and made an explicit decision.",
  type: "object",
  required: [
    "agent_id",
    "session_id",
    "action_type",
    "action_description",
    "inputs_hash",
    "risk_level",
    "decision",
    "timestamp",
  ],
  properties: {
    agent_id: {
      type: "string",
      maxLength: 256,
      description: "Unique identifier of the agent (wallet address, DID, or any stable ID)",
      examples: ["erd1qyu5wthldzr8wx5ad27msh6tq4wvszsrd7ckl7xztvkmmcxg7qvs9qy867", "agent-trading-001"],
    },
    session_id: {
      type: "string",
      maxLength: 128,
      description: "Unique identifier for this work session (UUID recommended)",
      examples: ["550e8400-e29b-41d4-a716-446655440000"],
    },
    action_type: {
      type: "string",
      enum: ACTION_TYPES,
      description: "Category of the action being certified",
      examples: ["trade_execution", "code_deploy"],
    },
    action_description: {
      type: "string",
      maxLength: 1000,
      description: "Human-readable description of the action the agent is about to execute",
      examples: [
        "Buy 0.5 ETH at market price on Uniswap v3",
        "Deploy smart contract 0xabc... to Ethereum mainnet",
      ],
    },
    inputs_hash: {
      type: "string",
      pattern: "^[a-fA-F0-9]{64}$",
      description:
        "SHA-256 hash of all inputs analyzed by the agent before making the decision (market data, code diff, dataset, etc.). " +
        "This anchors the proof to the exact data the agent saw.",
      examples: ["a3f5b2c1d4e6f7890123456789abcdef0123456789abcdef0123456789abcdef"],
    },
    risk_level: {
      type: "string",
      enum: RISK_LEVELS,
      description: "Agent's self-assessed risk level for this action",
      examples: ["high"],
    },
    risk_summary: {
      type: "string",
      maxLength: 500,
      description: "Optional brief summary of the agent's risk analysis",
      examples: ["Market volatility is elevated (+2σ). Slippage estimated at 0.3%. Liquidity sufficient."],
    },
    decision: {
      type: "string",
      enum: DECISIONS,
      description:
        "The agent's explicit decision. 'approved' = will execute, 'rejected' = will not execute, 'deferred' = awaits human approval",
      examples: ["approved"],
    },
    context: {
      type: "object",
      description: "Optional additional metadata (strategy name, version, environment, etc.)",
      examples: [{ strategy: "momentum-v2", environment: "production", version: "1.4.2" }],
    },
    timestamp: {
      type: "string",
      format: "date-time",
      description: "ISO8601 timestamp of when the audit log was created",
      examples: ["2026-02-27T22:00:00.000Z"],
    },
  },
  additionalProperties: false,
  examples: [
    {
      agent_id: "erd1qyu5wthldzr8wx5ad27msh6tq4wvszsrd7ckl7xztvkmmcxg7qvs9qy867",
      session_id: "550e8400-e29b-41d4-a716-446655440000",
      action_type: "trade_execution",
      action_description: "Buy 0.5 ETH at market price on Uniswap v3 (USDC→ETH)",
      inputs_hash: "a3f5b2c1d4e6f789012345678901234567890123456789abcdef01234567890a",
      risk_level: "high",
      risk_summary: "Market volatility elevated. Slippage < 0.5%. Liquidity verified.",
      decision: "approved",
      context: { strategy: "momentum-v2", environment: "production" },
      timestamp: "2026-02-27T22:00:00.000Z",
    },
  ],
};
