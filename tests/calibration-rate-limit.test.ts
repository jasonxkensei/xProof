/**
 * Integration tests for the eligible-proofs rate limiter.
 *
 * These tests verify that eligibleProofsRateLimiter — configured at 30 req/min
 * per API key — correctly gates GET /api/agent/calibration/:agentId/eligible-proofs
 * and that the middleware ordering (preloadApiKeyForRateLimit before
 * eligibleProofsRateLimiter) works as intended.
 *
 * Requests are sent with a real api_keys DB fixture so the rate-limit bucket is
 * keyed on req.apiKey.id (the per-key path) rather than the IP fallback.  This
 * also exercises the preloadApiKeyForRateLimit → eligibleProofsRateLimiter chain.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import crypto from "crypto";
import { pool } from "../server/db";

const BASE_URL = "http://localhost:5000";

// ── Stable test fixtures ──────────────────────────────────────────────────────
// Using a unique wallet address and raw key that will never collide with real data.
const TEST_WALLET   = "erd1ratetest000000000000000000000000000000000000000000000000";
const TEST_RAW_KEY  = "pm_ratelimit_fixture_000000000000000000000";
const TEST_KEY_HASH = crypto.createHash("sha256").update(TEST_RAW_KEY).digest("hex");
const TEST_KEY_PREFIX = TEST_RAW_KEY.slice(0, 8);

let testUserId = "";   // filled by beforeAll
let testApiKeyId = ""; // filled by beforeAll

// ── Setup / teardown ──────────────────────────────────────────────────────────
beforeAll(async () => {
  // 1. Ensure the rate_limit_counters table exists.
  //    (Created by server/index.ts on startup but the test worker is a
  //    separate process that runs before ensureRateLimitTable() is called.)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS rate_limit_counters (
      bucket   TEXT PRIMARY KEY,
      count    INTEGER NOT NULL DEFAULT 0,
      reset_at TIMESTAMPTZ NOT NULL
    )
  `);

  // 2. Upsert the test user (wallet_address is the only required column).
  //    ON CONFLICT makes this idempotent across repeated test runs.
  const userRow = await pool.query<{ id: string }>(
    `INSERT INTO users (wallet_address)
     VALUES ($1)
     ON CONFLICT (wallet_address)
     DO UPDATE SET wallet_address = EXCLUDED.wallet_address
     RETURNING id`,
    [TEST_WALLET],
  );
  testUserId = userRow.rows[0].id;

  // 3. Upsert the test API key.
  const keyRow = await pool.query<{ id: string }>(
    `INSERT INTO api_keys (key_hash, key_prefix, user_id, name, is_active)
     VALUES ($1, $2, $3, 'rate-limit-test-fixture', TRUE)
     ON CONFLICT (key_hash)
     DO UPDATE SET is_active = TRUE
     RETURNING id`,
    [TEST_KEY_HASH, TEST_KEY_PREFIX, testUserId],
  );
  testApiKeyId = keyRow.rows[0].id;

  // 4. Wipe any leftover rate-limit counters for this key so the test
  //    always starts from a clean bucket regardless of when it runs.
  await pool.query(
    `DELETE FROM rate_limit_counters WHERE bucket LIKE $1`,
    [`eligible_proofs:${testApiKeyId}:%`],
  );
});

afterAll(async () => {
  // Remove fixture data — deletion cascades from users to api_keys.
  await pool.query(`DELETE FROM users WHERE wallet_address = $1`, [TEST_WALLET]);
  // Close the connection pool opened by this worker so vitest exits cleanly.
  await pool.end();
});

// ── Tests ─────────────────────────────────────────────────────────────────────
describe("GET /api/agent/calibration/:agentId/eligible-proofs", () => {
  describe("eligibleProofsRateLimiter — per-API-key bucket, max 30 req/min", () => {
    it(
      "requests 1–30 return 200; the 31st request in the same window returns HTTP 429 TOO_MANY_REQUESTS",
      async () => {
        // agentId == testUserId so the caller (the test API key) is the owner → 200.
        const url     = `${BASE_URL}/api/agent/calibration/${testUserId}/eligible-proofs`;
        const headers = { Authorization: `Bearer ${TEST_RAW_KEY}` };

        // ── Within-limit: first 30 requests ─────────────────────────────────
        // The rate limiter passes these through; the handler returns 200 because
        // callerUserId (from req.apiKey.userId) matches agent.id.
        for (let i = 0; i < 30; i++) {
          const res  = await fetch(url, { headers });
          const body = await res.json() as Record<string, unknown>;
          expect(res.status, `request ${i + 1} must not be rate-limited`).toBe(200);
          // Handler returns { proofs: [...] } for an authenticated owner
          expect(body).toHaveProperty("proofs");
          expect(Array.isArray(body.proofs)).toBe(true);
        }

        // ── Rate-limited: the 31st request in the same 60-second window ─────
        const limited     = await fetch(url, { headers });
        const limitedBody = await limited.json() as Record<string, unknown>;
        expect(limited.status).toBe(429);
        expect(limitedBody.error).toBe("TOO_MANY_REQUESTS");
      },
      25_000, // 30+ sequential HTTP requests; allow generous headroom
    );
  });
});
