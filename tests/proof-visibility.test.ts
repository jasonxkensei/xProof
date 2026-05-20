/**
 * Integration tests for the /api/proof/:id and /api/proof/hash/:hash
 * visibility gates.
 *
 * These tests guard against regressions in the is_public_profile gate
 * and the trial-user carve-out that was introduced to fix the task-#278
 * trial proof page 404 bug.
 *
 * All tests run against the real local DB (same pattern as
 * tests/calibration-rate-limit.test.ts).
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import crypto from "crypto";
import { pool } from "../server/db";

const BASE_URL = "http://localhost:5000";

// ── Stable test fixtures ──────────────────────────────────────────────────────
// Unique wallet addresses that will never collide with real data.
const TRIAL_WALLET    = "erd1prooftest_trial_000000000000000000000000000000000000000000";
const NONTRIAL_WALLET = "erd1prooftest_private000000000000000000000000000000000000000000";
const PUBLIC_WALLET   = "erd1prooftest_public000000000000000000000000000000000000000000";

// Deterministic file hashes for each fixture certification.
const TRIAL_FILE_HASH   = crypto.createHash("sha256").update("proof-visibility-trial-fixture-v1").digest("hex");
const PRIVATE_FILE_HASH = crypto.createHash("sha256").update("proof-visibility-private-fixture-v1").digest("hex");
const PUBLIC_FILE_HASH  = crypto.createHash("sha256").update("proof-visibility-public-fixture-v1").digest("hex");

let trialUserId   = "";
let trialCertId   = "";
let privateUserId = "";
let privateCertId = "";
let publicUserId  = "";
let publicCertId  = "";

// ── Setup / teardown ──────────────────────────────────────────────────────────
beforeAll(async () => {
  // ── Trial user: is_trial = TRUE, is_public_profile = FALSE ────────────────
  const trialUserRow = await pool.query<{ id: string }>(
    `INSERT INTO users (wallet_address, is_trial, is_public_profile)
     VALUES ($1, TRUE, FALSE)
     ON CONFLICT (wallet_address)
     DO UPDATE SET is_trial = TRUE, is_public_profile = FALSE
     RETURNING id`,
    [TRIAL_WALLET],
  );
  trialUserId = trialUserRow.rows[0].id;

  // Public certification owned by the trial user.
  const trialCertRow = await pool.query<{ id: string }>(
    `INSERT INTO certifications (user_id, file_name, file_hash, is_public, blockchain_status)
     VALUES ($1, 'trial-fixture.txt', $2, TRUE, 'pending')
     ON CONFLICT (file_hash)
     DO UPDATE SET user_id = $1, is_public = TRUE
     RETURNING id`,
    [trialUserId, TRIAL_FILE_HASH],
  );
  trialCertId = trialCertRow.rows[0].id;

  // ── Public non-trial user: is_trial = FALSE, is_public_profile = TRUE ───────
  const publicUserRow = await pool.query<{ id: string }>(
    `INSERT INTO users (wallet_address, is_trial, is_public_profile)
     VALUES ($1, FALSE, TRUE)
     ON CONFLICT (wallet_address)
     DO UPDATE SET is_trial = FALSE, is_public_profile = TRUE
     RETURNING id`,
    [PUBLIC_WALLET],
  );
  publicUserId = publicUserRow.rows[0].id;

  // Public certification owned by the public (non-trial) user.
  const publicCertRow = await pool.query<{ id: string }>(
    `INSERT INTO certifications (user_id, file_name, file_hash, is_public, blockchain_status)
     VALUES ($1, 'public-fixture.txt', $2, TRUE, 'pending')
     ON CONFLICT (file_hash)
     DO UPDATE SET user_id = $1, is_public = TRUE
     RETURNING id`,
    [publicUserId, PUBLIC_FILE_HASH],
  );
  publicCertId = publicCertRow.rows[0].id;

  // ── Non-trial user: is_trial = FALSE, is_public_profile = FALSE ───────────
  const privateUserRow = await pool.query<{ id: string }>(
    `INSERT INTO users (wallet_address, is_trial, is_public_profile)
     VALUES ($1, FALSE, FALSE)
     ON CONFLICT (wallet_address)
     DO UPDATE SET is_trial = FALSE, is_public_profile = FALSE
     RETURNING id`,
    [NONTRIAL_WALLET],
  );
  privateUserId = privateUserRow.rows[0].id;

  // Public certification owned by the private (non-trial) user.
  const privateCertRow = await pool.query<{ id: string }>(
    `INSERT INTO certifications (user_id, file_name, file_hash, is_public, blockchain_status)
     VALUES ($1, 'private-fixture.txt', $2, TRUE, 'pending')
     ON CONFLICT (file_hash)
     DO UPDATE SET user_id = $1, is_public = TRUE
     RETURNING id`,
    [privateUserId, PRIVATE_FILE_HASH],
  );
  privateCertId = privateCertRow.rows[0].id;
});

afterAll(async () => {
  // Remove fixture data in dependency order.
  // Certifications must go first (FK → users).
  await pool.query(
    `DELETE FROM certifications WHERE file_hash = ANY($1)`,
    [[TRIAL_FILE_HASH, PRIVATE_FILE_HASH, PUBLIC_FILE_HASH]],
  );
  await pool.query(
    `DELETE FROM users WHERE wallet_address = ANY($1)`,
    [[TRIAL_WALLET, NONTRIAL_WALLET, PUBLIC_WALLET]],
  );
});

// ── Tests ─────────────────────────────────────────────────────────────────────
describe("GET /api/proof/:id — visibility gate", () => {
  it("returns 200 for a public certification owned by a trial user (trial carve-out)", async () => {
    const res  = await fetch(`${BASE_URL}/api/proof/${trialCertId}`);
    const body = await res.json() as Record<string, unknown>;

    expect(res.status, `expected 200 but got ${res.status}: ${JSON.stringify(body)}`).toBe(200);
    expect(body.id).toBe(trialCertId);
    expect(body.fileHash).toBe(TRIAL_FILE_HASH);
    expect(body.isPublic).toBe(true);
  });

  it("returns 404 for a public certification whose owner has is_public_profile = false and is not a trial user", async () => {
    const res  = await fetch(`${BASE_URL}/api/proof/${privateCertId}`);
    const body = await res.json() as Record<string, unknown>;

    expect(res.status, `expected 404 but got ${res.status}: ${JSON.stringify(body)}`).toBe(404);
  });

  it("returns 200 for a public certification owned by a non-trial user with is_public_profile = true", async () => {
    const res  = await fetch(`${BASE_URL}/api/proof/${publicCertId}`);
    const body = await res.json() as Record<string, unknown>;

    expect(res.status, `expected 200 but got ${res.status}: ${JSON.stringify(body)}`).toBe(200);
    expect(body.id).toBe(publicCertId);
    expect(body.fileHash).toBe(PUBLIC_FILE_HASH);
    expect(body.isPublic).toBe(true);
  });

  it("returns 404 for an unknown proof id", async () => {
    const res = await fetch(`${BASE_URL}/api/proof/00000000-0000-0000-0000-000000000000`);
    expect(res.status).toBe(404);
  });
});

describe("GET /api/proof/hash/:hash — visibility gate", () => {
  it("returns 200 for a public certification owned by a trial user (trial carve-out)", async () => {
    const res  = await fetch(`${BASE_URL}/api/proof/hash/${TRIAL_FILE_HASH}`);
    const body = await res.json() as Record<string, unknown>;

    expect(res.status, `expected 200 but got ${res.status}: ${JSON.stringify(body)}`).toBe(200);
    expect(body.proof_id).toBe(trialCertId);
    expect(body.file_hash).toBe(TRIAL_FILE_HASH);
  });

  it("returns 404 for a public certification whose owner has is_public_profile = false and is not a trial user", async () => {
    const res  = await fetch(`${BASE_URL}/api/proof/hash/${PRIVATE_FILE_HASH}`);
    const body = await res.json() as Record<string, unknown>;

    expect(res.status, `expected 404 but got ${res.status}: ${JSON.stringify(body)}`).toBe(404);
  });

  it("returns 200 for a public certification owned by a non-trial user with is_public_profile = true", async () => {
    const res  = await fetch(`${BASE_URL}/api/proof/hash/${PUBLIC_FILE_HASH}`);
    const body = await res.json() as Record<string, unknown>;

    expect(res.status, `expected 200 but got ${res.status}: ${JSON.stringify(body)}`).toBe(200);
    expect(body.proof_id).toBe(publicCertId);
    expect(body.file_hash).toBe(PUBLIC_FILE_HASH);
  });

  it("returns 400 for a malformed hash", async () => {
    const res = await fetch(`${BASE_URL}/api/proof/hash/not-a-valid-sha256-hash`);
    expect(res.status).toBe(400);
  });

  it("returns 404 for a well-formed hash with no matching certification", async () => {
    const unknownHash = crypto.createHash("sha256").update("no-such-file-xproof-v1").digest("hex");
    const res = await fetch(`${BASE_URL}/api/proof/hash/${unknownHash}`);
    expect(res.status).toBe(404);
  });
});
