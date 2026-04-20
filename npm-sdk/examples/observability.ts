/**
 * Compliance observability — runnable example.
 *
 * Demonstrates the pattern from the README "Observability — surfacing
 * violations in dashboards" section using a fully mocked XProofClient so no
 * real API key or network access is required.
 *
 * Run from the npm-sdk directory:
 *
 *   npx tsx examples/observability.ts
 *
 * Expected output: structured JSON log lines on stderr and a final JSON
 * summary on stdout. The script exits 0 on success.
 *
 * To test the webhook path, set the VIOLATION_WEBHOOK_URL environment variable:
 *
 *   VIOLATION_WEBHOOK_URL=https://hooks.example.com/compliance \
 *     npx tsx examples/observability.ts
 */

import type {
  ConfidenceTrail,
  PolicyCheckResult,
  PolicyViolation,
} from "../src/index.js";

// ── Mock helpers ──────────────────────────────────────────────────────────────

const DECISION_ID = "demo-decision-42";

const VIOLATION_WEBHOOK_URL: string | null =
  process.env.VIOLATION_WEBHOOK_URL ?? null;

function buildMockViolation(): PolicyViolation {
  return {
    rule:               "irreversible-confidence",
    proofId:            "proof-stage-2",
    confidenceLevel:    0.72,
    threshold:          0.95,
    reversibilityClass: "irreversible",
    thresholdStage:     "execution",
    severity:           "error",
    message:            "Irreversible action certified with confidence 0.72 — minimum 0.95 required.",
  };
}

function buildMockPolicyCheck(decisionId: string): PolicyCheckResult {
  return {
    decisionId,
    totalAnchors:    2,
    policyCompliant: false,
    policyViolations: [buildMockViolation()],
    checkedAt:       "2026-04-20T12:00:00Z",
  };
}

function buildMockTrail(decisionId: string): ConfidenceTrail {
  const violation = buildMockViolation();
  return {
    decisionId,
    totalAnchors:       2,
    currentConfidence:  0.72,
    currentStage:       "execution",
    isFinalized:        false,
    policyCompliant:    false,
    policyViolations:   [violation],
    stages: [
      {
        proofId:            "proof-stage-1",
        confidenceLevel:    0.50,
        thresholdStage:     "draft",
        reversibilityClass: "reversible",
        anchoredAt:         "2026-04-20T11:00:00Z",
        transactionHash:    "0xabc123",
        transactionUrl:     "https://explorer.multiversx.com/transactions/0xabc123",
        policyViolations:   [],
      },
      {
        proofId:            "proof-stage-2",
        confidenceLevel:    0.72,
        thresholdStage:     "execution",
        reversibilityClass: "irreversible",
        anchoredAt:         "2026-04-20T12:00:00Z",
        transactionHash:    "0xdef456",
        transactionUrl:     "https://explorer.multiversx.com/transactions/0xdef456",
        policyViolations:   [violation],
      },
    ],
    raw: {},
  };
}

interface MockClient {
  getPolicyCheck(decisionId: string): Promise<PolicyCheckResult>;
  getConfidenceTrail(decisionId: string): Promise<ConfidenceTrail>;
}

function buildMockClient(): MockClient {
  return {
    getPolicyCheck:    async (id) => buildMockPolicyCheck(id),
    getConfidenceTrail: async (id) => buildMockTrail(id),
  };
}

// ── Core observability helpers (identical to the README recipe) ───────────────

async function emitViolation(
  decisionId: string,
  violation: PolicyViolation,
): Promise<void> {
  const payload = {
    event:               "policy_violation",
    decision_id:         decisionId,
    rule:                violation.rule,
    proof_id:            violation.proofId,
    confidence_level:    violation.confidenceLevel,
    threshold:           violation.threshold,
    reversibility_class: violation.reversibilityClass,
    threshold_stage:     violation.thresholdStage,
  };

  // Structured JSON log — ingested by Datadog / CloudWatch / Loki
  console.error(JSON.stringify(payload));

  // Optional webhook (best-effort, non-blocking)
  if (VIOLATION_WEBHOOK_URL) {
    try {
      await fetch(VIOLATION_WEBHOOK_URL, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify(payload),
        signal:  AbortSignal.timeout(5000),
      });
    } catch (exc) {
      console.warn(JSON.stringify({ event: "webhook_error", detail: String(exc) }));
    }
  }
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const client = buildMockClient();

  console.log(`Running compliance observability example for decision '${DECISION_ID}' ...\n`);

  const check = await client.getPolicyCheck(DECISION_ID);

  const emitted: string[] = [];

  if (!check.policyCompliant) {
    for (const v of check.policyViolations) {
      await emitViolation(DECISION_ID, v);
      emitted.push(v.rule);
    }

    // Full audit trail for post-mortem / SIEM export
    const trail = await client.getConfidenceTrail(DECISION_ID);
    console.error(JSON.stringify({
      event:              "audit_trail",
      decision_id:        DECISION_ID,
      current_confidence: trail.currentConfidence,
      is_finalized:       trail.isFinalized,
      total_anchors:      trail.totalAnchors,
      stages:             trail.stages.length,
    }));

    // Assertions
    if (trail.stages.length !== 2) throw new Error("Expected 2 trail stages");
    if (trail.stages[1].transactionHash !== "0xdef456") throw new Error("Wrong tx hash");
  }

  if (emitted.length !== 1) throw new Error("Expected exactly 1 violation");
  if (emitted[0] !== "irreversible-confidence") throw new Error("Wrong violation rule");

  console.log("\n" + JSON.stringify({
    result:      "ok",
    decision_id: DECISION_ID,
    violations:  emitted.length,
    webhook:     VIOLATION_WEBHOOK_URL ? "configured" : "disabled",
  }));

  console.log("\nAll assertions passed — example exited cleanly.");
}

main().catch((err) => { console.error(err); process.exit(1); });
