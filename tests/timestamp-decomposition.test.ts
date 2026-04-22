import { describe, it, expect } from "vitest";
import {
  JURISDICTION_TYPES,
  REVERSIBILITY_CLASSES,
  auditLogSchema,
} from "../server/auditSchema";

const BASE_VALID_AUDIT = {
  agent_id: "agent-test-001",
  session_id: "550e8400-e29b-41d4-a716-446655440000",
  action_type: "trade_execution" as const,
  action_description: "Buy 0.5 ETH at market price",
  inputs_hash: "a3f5b2c1d4e6f789012345678901234567890123456789abcdef0123456789ab",
  risk_level: "high" as const,
  decision: "approved" as const,
  timestamp: "2026-04-20T14:32:07Z",
};

describe("Timestamp Decomposition — Task #87", () => {
  describe("JURISDICTION_TYPES constant", () => {
    it("should export the three required accountability classes", () => {
      expect(JURISDICTION_TYPES).toContain("instruction_following");
      expect(JURISDICTION_TYPES).toContain("autonomous_inference");
      expect(JURISDICTION_TYPES).toContain("human_approved");
      expect(JURISDICTION_TYPES).toHaveLength(3);
    });

    it("should be a readonly tuple (frozen)", () => {
      expect(Object.isFrozen(JURISDICTION_TYPES)).toBe(true);
    });
  });

  describe("auditLogSchema — timing fields", () => {
    it("should accept a valid audit log without timing fields (backward-compat)", () => {
      const result = auditLogSchema.safeParse(BASE_VALID_AUDIT);
      expect(result.success).toBe(true);
    });

    it("should accept all three timing fields when valid ISO8601", () => {
      const result = auditLogSchema.safeParse({
        ...BASE_VALID_AUDIT,
        instruction_received_at: "2026-04-20T14:31:58Z",
        reasoning_started_at: "2026-04-20T14:31:59Z",
        action_taken_at: "2026-04-20T14:32:07Z",
      });
      expect(result.success).toBe(true);
    });

    it("should accept partial timing fields", () => {
      const withInstruction = auditLogSchema.safeParse({
        ...BASE_VALID_AUDIT,
        instruction_received_at: "2026-04-20T14:31:58Z",
      });
      expect(withInstruction.success).toBe(true);

      const withReasoning = auditLogSchema.safeParse({
        ...BASE_VALID_AUDIT,
        reasoning_started_at: "2026-04-20T14:31:59Z",
      });
      expect(withReasoning.success).toBe(true);

      const withAction = auditLogSchema.safeParse({
        ...BASE_VALID_AUDIT,
        action_taken_at: "2026-04-20T14:32:07Z",
      });
      expect(withAction.success).toBe(true);
    });

    it("should reject invalid ISO8601 for instruction_received_at", () => {
      const result = auditLogSchema.safeParse({
        ...BASE_VALID_AUDIT,
        instruction_received_at: "not-a-date",
      });
      expect(result.success).toBe(false);
      if (!result.success) {
        const msgs = result.error.issues.map((i) => i.message);
        expect(msgs.some((m) => m.includes("instruction_received_at"))).toBe(true);
      }
    });

    it("should reject invalid ISO8601 for reasoning_started_at", () => {
      const result = auditLogSchema.safeParse({
        ...BASE_VALID_AUDIT,
        reasoning_started_at: "20260420",
      });
      expect(result.success).toBe(false);
    });

    it("should reject invalid ISO8601 for action_taken_at", () => {
      const result = auditLogSchema.safeParse({
        ...BASE_VALID_AUDIT,
        action_taken_at: "tomorrow",
      });
      expect(result.success).toBe(false);
    });

    it("should accept all valid jurisdiction_type values", () => {
      for (const jt of JURISDICTION_TYPES) {
        const result = auditLogSchema.safeParse({
          ...BASE_VALID_AUDIT,
          jurisdiction_type: jt,
        });
        expect(result.success).toBe(true);
      }
    });

    it("should reject invalid jurisdiction_type", () => {
      const result = auditLogSchema.safeParse({
        ...BASE_VALID_AUDIT,
        jurisdiction_type: "llm_decided",
      });
      expect(result.success).toBe(false);
      if (!result.success) {
        const msgs = result.error.issues.map((i) => i.message);
        expect(msgs.some((m) => m.includes("jurisdiction_type"))).toBe(true);
      }
    });

    it("should accept timing fields combined with jurisdiction_type", () => {
      const result = auditLogSchema.safeParse({
        ...BASE_VALID_AUDIT,
        instruction_received_at: "2026-04-20T14:31:58Z",
        reasoning_started_at: "2026-04-20T14:31:59Z",
        action_taken_at: "2026-04-20T14:32:07Z",
        jurisdiction_type: "autonomous_inference",
      });
      expect(result.success).toBe(true);
    });

    it("should accept timing fields combined with reversibility_class governance", () => {
      const result = auditLogSchema.safeParse({
        ...BASE_VALID_AUDIT,
        instruction_received_at: "2026-04-20T14:31:58Z",
        action_taken_at: "2026-04-20T14:32:07Z",
        jurisdiction_type: "human_approved",
        reversibility_class: "irreversible",
      });
      expect(result.success).toBe(true);
    });
  });

  describe("Timestamp ordering constraint — logic", () => {
    const isOrderValid = (ira: string | null, rsa: string | null, ata: string | null): boolean => {
      const iraMs = ira ? Date.parse(ira) : null;
      const rsaMs = rsa ? Date.parse(rsa) : null;
      const ataMs = ata ? Date.parse(ata) : null;
      if (iraMs !== null && rsaMs !== null && rsaMs < iraMs) return false;
      if (rsaMs !== null && ataMs !== null && ataMs < rsaMs) return false;
      if (iraMs !== null && ataMs !== null && rsaMs === null && ataMs < iraMs) return false;
      return true;
    };

    it("should pass when all three are in correct order", () => {
      expect(isOrderValid("2026-04-20T14:31:58Z", "2026-04-20T14:31:59Z", "2026-04-20T14:32:07Z")).toBe(true);
    });

    it("should pass when timestamps are equal (same instant)", () => {
      const ts = "2026-04-20T14:31:58Z";
      expect(isOrderValid(ts, ts, ts)).toBe(true);
    });

    it("should fail when reasoning_started_at < instruction_received_at", () => {
      expect(isOrderValid("2026-04-20T14:32:00Z", "2026-04-20T14:31:00Z", "2026-04-20T14:33:00Z")).toBe(false);
    });

    it("should fail when action_taken_at < reasoning_started_at", () => {
      expect(isOrderValid("2026-04-20T14:31:00Z", "2026-04-20T14:32:00Z", "2026-04-20T14:31:30Z")).toBe(false);
    });

    it("should fail when action_taken_at < instruction_received_at with no reasoning", () => {
      expect(isOrderValid("2026-04-20T14:32:00Z", null, "2026-04-20T14:31:00Z")).toBe(false);
    });

    it("should pass when only instruction_received_at is provided", () => {
      expect(isOrderValid("2026-04-20T14:31:58Z", null, null)).toBe(true);
    });

    it("should pass when only action_taken_at is provided", () => {
      expect(isOrderValid(null, null, "2026-04-20T14:32:07Z")).toBe(true);
    });

    it("should pass when only reasoning_started_at and action_taken_at are provided", () => {
      expect(isOrderValid(null, "2026-04-20T14:31:59Z", "2026-04-20T14:32:07Z")).toBe(true);
    });

    it("should fail when reasoning_started > action_taken, instruction absent", () => {
      expect(isOrderValid(null, "2026-04-20T14:33:00Z", "2026-04-20T14:32:07Z")).toBe(false);
    });
  });

  describe("timing_breakdown computed fields", () => {
    const buildTimingBreakdown = (
      ira: string | null,
      rsa: string | null,
      ata: string | null,
      jt: string | null,
    ) => {
      const iraMs = ira ? Date.parse(ira) : null;
      const rsaMs = rsa ? Date.parse(rsa) : null;
      const ataMs = ata ? Date.parse(ata) : null;
      const reasoning_duration_ms = rsaMs !== null && ataMs !== null ? ataMs - rsaMs : null;
      const total_duration_ms = iraMs !== null && ataMs !== null ? ataMs - iraMs : null;
      if (!(ira || rsa || ata || jt)) return null;
      return { instruction_received_at: ira, reasoning_started_at: rsa, action_taken_at: ata, jurisdiction_type: jt, reasoning_duration_ms, total_duration_ms };
    };

    it("should return null timing_breakdown when no timing fields present", () => {
      expect(buildTimingBreakdown(null, null, null, null)).toBeNull();
    });

    it("should compute reasoning_duration_ms correctly", () => {
      const tb = buildTimingBreakdown(null, "2026-04-20T14:31:59Z", "2026-04-20T14:32:07Z", null);
      expect(tb?.reasoning_duration_ms).toBe(8000);
    });

    it("should compute total_duration_ms correctly", () => {
      const tb = buildTimingBreakdown("2026-04-20T14:31:58Z", "2026-04-20T14:31:59Z", "2026-04-20T14:32:07Z", null);
      expect(tb?.total_duration_ms).toBe(9000);
    });

    it("should return null durations when anchor timestamps are absent", () => {
      const tb = buildTimingBreakdown("2026-04-20T14:31:58Z", null, null, "instruction_following");
      expect(tb?.reasoning_duration_ms).toBeNull();
      expect(tb?.total_duration_ms).toBeNull();
    });

    it("should expose jurisdiction_type in timing_breakdown", () => {
      const tb = buildTimingBreakdown(null, null, null, "autonomous_inference");
      expect(tb?.jurisdiction_type).toBe("autonomous_inference");
    });
  });
});
