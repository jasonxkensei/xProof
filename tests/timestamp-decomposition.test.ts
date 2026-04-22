import { describe, it, expect } from "vitest";
import {
  JURISDICTION_TYPES,
  auditLogSchema,
  validateTimestampOrdering,
  buildTimingBreakdown,
  isStrictDatetime,
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

    it("should be frozen at runtime (Object.freeze)", () => {
      expect(Object.isFrozen(JURISDICTION_TYPES)).toBe(true);
    });
  });

  describe("auditLogSchema — timing field validation", () => {
    it("accepts a valid audit log without timing fields (backward-compat)", () => {
      const result = auditLogSchema.safeParse(BASE_VALID_AUDIT);
      expect(result.success).toBe(true);
    });

    it("accepts all three timing fields as valid ISO8601", () => {
      const result = auditLogSchema.safeParse({
        ...BASE_VALID_AUDIT,
        instruction_received_at: "2026-04-20T14:31:58Z",
        reasoning_started_at: "2026-04-20T14:31:59Z",
        action_taken_at: "2026-04-20T14:32:07Z",
      });
      expect(result.success).toBe(true);
    });

    it("accepts partial timing fields (only instruction_received_at)", () => {
      const result = auditLogSchema.safeParse({
        ...BASE_VALID_AUDIT,
        instruction_received_at: "2026-04-20T14:31:58Z",
      });
      expect(result.success).toBe(true);
    });

    it("rejects non-ISO8601 instruction_received_at with correct error message", () => {
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

    it("rejects non-ISO8601 reasoning_started_at with correct error message", () => {
      const result = auditLogSchema.safeParse({
        ...BASE_VALID_AUDIT,
        reasoning_started_at: "yesterday",
      });
      expect(result.success).toBe(false);
      if (!result.success) {
        const msgs = result.error.issues.map((i) => i.message);
        expect(msgs.some((m) => m.includes("reasoning_started_at"))).toBe(true);
      }
    });

    it("rejects non-ISO8601 action_taken_at with correct error message", () => {
      const result = auditLogSchema.safeParse({
        ...BASE_VALID_AUDIT,
        action_taken_at: "20260420",
      });
      expect(result.success).toBe(false);
      if (!result.success) {
        const msgs = result.error.issues.map((i) => i.message);
        expect(msgs.some((m) => m.includes("action_taken_at"))).toBe(true);
      }
    });

    it("accepts every valid jurisdiction_type value", () => {
      for (const jt of JURISDICTION_TYPES) {
        const result = auditLogSchema.safeParse({
          ...BASE_VALID_AUDIT,
          jurisdiction_type: jt,
        });
        expect(result.success).toBe(true);
      }
    });

    it("rejects unknown jurisdiction_type with correct error message", () => {
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

    it("accepts timing fields combined with jurisdiction_type", () => {
      const result = auditLogSchema.safeParse({
        ...BASE_VALID_AUDIT,
        instruction_received_at: "2026-04-20T14:31:58Z",
        reasoning_started_at: "2026-04-20T14:31:59Z",
        action_taken_at: "2026-04-20T14:32:07Z",
        jurisdiction_type: "autonomous_inference",
      });
      expect(result.success).toBe(true);
    });

    it("accepts timing fields alongside reversibility_class governance field", () => {
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

  describe("isStrictDatetime — strict ISO8601 datetime validator", () => {
    it("accepts UTC Z-suffixed datetime strings", () => {
      expect(isStrictDatetime("2026-04-20T14:31:58Z")).toBe(true);
      expect(isStrictDatetime("2026-04-20T14:31:58.123Z")).toBe(true);
    });

    it("accepts timezone-offset datetime strings", () => {
      expect(isStrictDatetime("2026-04-20T14:31:58+05:30")).toBe(true);
      expect(isStrictDatetime("2026-04-20T00:00:00-08:00")).toBe(true);
    });

    it("rejects date-only strings (not datetime)", () => {
      expect(isStrictDatetime("2026-04-20")).toBe(false);
    });

    it("rejects naive datetime strings (no timezone offset)", () => {
      expect(isStrictDatetime("2026-04-20T14:31:58")).toBe(false);
    });

    it("rejects arbitrary strings", () => {
      expect(isStrictDatetime("not-a-date")).toBe(false);
      expect(isStrictDatetime("yesterday")).toBe(false);
      expect(isStrictDatetime("20260420")).toBe(false);
    });
  });

  describe("validateTimestampOrdering — exported utility", () => {
    it("passes when all three are in correct chronological order", () => {
      const r = validateTimestampOrdering(
        "2026-04-20T14:31:58Z",
        "2026-04-20T14:31:59Z",
        "2026-04-20T14:32:07Z",
      );
      expect(r.valid).toBe(true);
      expect(r.message).toBeNull();
    });

    it("passes when all three are the same instant", () => {
      const ts = "2026-04-20T14:31:58Z";
      expect(validateTimestampOrdering(ts, ts, ts).valid).toBe(true);
    });

    it("fails when reasoning_started_at < instruction_received_at", () => {
      const r = validateTimestampOrdering(
        "2026-04-20T14:32:00Z",
        "2026-04-20T14:31:00Z",
        "2026-04-20T14:33:00Z",
      );
      expect(r.valid).toBe(false);
      expect(r.message).toMatch(/reasoning_started_at/);
    });

    it("fails when action_taken_at < reasoning_started_at", () => {
      const r = validateTimestampOrdering(
        "2026-04-20T14:31:00Z",
        "2026-04-20T14:32:00Z",
        "2026-04-20T14:31:30Z",
      );
      expect(r.valid).toBe(false);
      expect(r.message).toMatch(/action_taken_at/);
    });

    it("fails when action_taken_at < instruction_received_at with no reasoning step", () => {
      const r = validateTimestampOrdering("2026-04-20T14:32:00Z", null, "2026-04-20T14:31:00Z");
      expect(r.valid).toBe(false);
      expect(r.message).toMatch(/action_taken_at/);
    });

    it("passes when only instruction_received_at is provided", () => {
      expect(validateTimestampOrdering("2026-04-20T14:31:58Z", null, null).valid).toBe(true);
    });

    it("passes when only action_taken_at is provided", () => {
      expect(validateTimestampOrdering(null, null, "2026-04-20T14:32:07Z").valid).toBe(true);
    });

    it("passes when reasoning_started_at and action_taken_at are provided without instruction", () => {
      expect(validateTimestampOrdering(null, "2026-04-20T14:31:59Z", "2026-04-20T14:32:07Z").valid).toBe(true);
    });

    it("fails when reasoning > action, instruction absent", () => {
      const r = validateTimestampOrdering(null, "2026-04-20T14:33:00Z", "2026-04-20T14:32:07Z");
      expect(r.valid).toBe(false);
    });
  });

  describe("buildTimingBreakdown — exported utility", () => {
    it("returns null when no timing fields are present in metadata", () => {
      expect(buildTimingBreakdown({})).toBeNull();
      expect(buildTimingBreakdown({ confidence_level: 0.9 })).toBeNull();
    });

    it("returns a breakdown object when at least one timing field is present", () => {
      const result = buildTimingBreakdown({ instruction_received_at: "2026-04-20T14:31:58Z" });
      expect(result).not.toBeNull();
      expect(result?.instruction_received_at).toBe("2026-04-20T14:31:58Z");
    });

    it("computes reasoning_duration_ms correctly from reasoning and action timestamps", () => {
      const result = buildTimingBreakdown({
        reasoning_started_at: "2026-04-20T14:31:59Z",
        action_taken_at: "2026-04-20T14:32:07Z",
      });
      expect(result?.reasoning_duration_ms).toBe(8000);
    });

    it("computes total_duration_ms correctly from instruction to action timestamps", () => {
      const result = buildTimingBreakdown({
        instruction_received_at: "2026-04-20T14:31:58Z",
        reasoning_started_at: "2026-04-20T14:31:59Z",
        action_taken_at: "2026-04-20T14:32:07Z",
      });
      expect(result?.total_duration_ms).toBe(9000);
    });

    it("returns null durations when action_taken_at is absent", () => {
      const result = buildTimingBreakdown({
        instruction_received_at: "2026-04-20T14:31:58Z",
        reasoning_started_at: "2026-04-20T14:31:59Z",
      });
      expect(result?.reasoning_duration_ms).toBeNull();
      expect(result?.total_duration_ms).toBeNull();
    });

    it("exposes jurisdiction_type when only jurisdiction_type is set (no timestamps)", () => {
      const result = buildTimingBreakdown({ jurisdiction_type: "autonomous_inference" });
      expect(result).not.toBeNull();
      expect(result?.jurisdiction_type).toBe("autonomous_inference");
    });

    it("exposes all six output fields when all inputs are provided", () => {
      const result = buildTimingBreakdown({
        instruction_received_at: "2026-04-20T14:31:58Z",
        reasoning_started_at: "2026-04-20T14:31:59Z",
        action_taken_at: "2026-04-20T14:32:07Z",
        jurisdiction_type: "human_approved",
      });
      expect(result).toMatchObject({
        instruction_received_at: "2026-04-20T14:31:58Z",
        reasoning_started_at: "2026-04-20T14:31:59Z",
        action_taken_at: "2026-04-20T14:32:07Z",
        jurisdiction_type: "human_approved",
        reasoning_duration_ms: 8000,
        total_duration_ms: 9000,
      });
    });
  });
});
