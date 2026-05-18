import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { pool } from "../server/db";

const BASE_URL = "http://localhost:5000";

// A wallet address guaranteed not to exist in the database.  Every request
// that passes the rate limiter reaches the handler and gets 404 AGENT_NOT_FOUND
// — a clean signal that the rate limiter did not block the request.
const NONEXISTENT_WALLET = "erd1ratelimittest000000000000000000000000000000000000000000";

describe("GET /api/agent/calibration/:agentId/eligible-proofs", () => {
  describe("rate limiting (eligibleProofsRateLimiter, max 30 req/min per IP)", () => {
    beforeAll(async () => {
      // Ensure the rate_limit_counters table exists (it is normally created by
      // server/index.ts on startup, but the test worker is a separate process).
      await pool.query(`
        CREATE TABLE IF NOT EXISTS rate_limit_counters (
          bucket   TEXT PRIMARY KEY,
          count    INTEGER NOT NULL DEFAULT 0,
          reset_at TIMESTAMPTZ NOT NULL
        )
      `);

      // Wipe all eligible_proofs counters so this suite always starts from a
      // clean bucket, regardless of prior runs within the same 60-second window.
      await pool.query(
        `DELETE FROM rate_limit_counters WHERE bucket LIKE 'eligible_proofs:%'`,
      );
    });

    afterAll(async () => {
      // Close the connection pool opened by this worker so vitest exits cleanly.
      await pool.end();
    });

    it(
      "requests 1–30 pass through the rate limiter (handler returns 404 for unknown agent)",
      async () => {
        for (let i = 0; i < 30; i++) {
          const res = await fetch(
            `${BASE_URL}/api/agent/calibration/${NONEXISTENT_WALLET}/eligible-proofs`,
          );
          // 404 AGENT_NOT_FOUND proves the rate limiter did NOT block the request.
          expect(res.status, `request ${i + 1} must not be rate-limited`).toBe(404);
          const body = await res.json();
          expect(body.error).toBe("AGENT_NOT_FOUND");
        }
      },
      20_000,
    );

    it("the 31st request within the 60-second window returns HTTP 429 TOO_MANY_REQUESTS", async () => {
      // The previous test consumed all 30 slots.  This is request #31.
      const res = await fetch(
        `${BASE_URL}/api/agent/calibration/${NONEXISTENT_WALLET}/eligible-proofs`,
      );
      expect(res.status).toBe(429);
      const body = await res.json();
      expect(body.error).toBe("TOO_MANY_REQUESTS");
    });
  });
});
