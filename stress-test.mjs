#!/usr/bin/env node
/**
 * xproof Stress Test
 * Usage:
 *   node stress-test.mjs --level=1      # HTTP burst only
 *   node stress-test.mjs --level=2      # Full queue stress (registers agents + certifies)
 *   node stress-test.mjs --register     # Step 2a: Register trial agents and save keys
 *   node stress-test.mjs --burst        # Step 2b: Load saved keys and run certification burst
 *   node stress-test.mjs                # Both levels
 */
import { readFileSync, writeFileSync, existsSync } from "fs";

const BASE_URL = "http://localhost:5000";
const args = process.argv.slice(2);
const levelArg = args.find(a => a.startsWith("--level="));
const LEVEL = levelArg ? parseInt(levelArg.split("=")[1]) : 0; // 0 = both
const MODE_REGISTER = args.includes("--register");
const MODE_BURST = args.includes("--burst");

// ─── Utilities ───────────────────────────────────────────────────────────────

function percentile(sorted, p) {
  if (sorted.length === 0) return null;
  const idx = Math.ceil((p / 100) * sorted.length) - 1;
  return sorted[Math.max(0, idx)];
}

function stats(times) {
  if (times.length === 0) return { p50: null, p95: null, p99: null, avg: null, min: null, max: null };
  const sorted = [...times].sort((a, b) => a - b);
  const avg = Math.round(times.reduce((s, v) => s + v, 0) / times.length);
  return {
    p50: percentile(sorted, 50),
    p95: percentile(sorted, 95),
    p99: percentile(sorted, 99),
    avg,
    min: sorted[0],
    max: sorted[sorted.length - 1],
  };
}

function table(rows, headers) {
  const colWidths = headers.map((h, i) => Math.max(h.length, ...rows.map(r => String(r[i] ?? "—").length)));
  const sep = "+" + colWidths.map(w => "-".repeat(w + 2)).join("+") + "+";
  const row = (cells) => "| " + cells.map((c, i) => String(c ?? "—").padEnd(colWidths[i])).join(" | ") + " |";
  return [sep, row(headers), sep, ...rows.map(row), sep].join("\n");
}

async function timed(fn) {
  const start = Date.now();
  try {
    const res = await fn();
    return { ms: Date.now() - start, status: res.status, ok: res.ok };
  } catch (e) {
    return { ms: Date.now() - start, status: 0, ok: false, error: e.message };
  }
}

async function burst(label, n, fn, delayMs = 0) {
  process.stdout.write(`  Firing ${n} concurrent requests [${label}]...`);
  const tasks = [];
  for (let i = 0; i < n; i++) {
    if (delayMs > 0) await sleep(delayMs);
    tasks.push(timed(fn));
  }
  const results = await Promise.all(tasks);
  process.stdout.write(" done\n");

  const times = results.filter(r => r.status > 0).map(r => r.ms);
  const byStatus = {};
  for (const r of results) {
    const key = r.status === 0 ? "net_err" : String(r.status);
    byStatus[key] = (byStatus[key] || 0) + 1;
  }
  return { results, times, byStatus, s: stats(times) };
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

async function getHealth() {
  const res = await fetch(`${BASE_URL}/api/health`);
  return res.json();
}

function printHealth(h, label = "") {
  const bl = h.blockchain_latency;
  const tx = h.transactions;
  console.log(`  ${label}`);
  console.log(`    Queue depth  : ${bl.queue_depth}`);
  console.log(`    p95 latency  : ${bl.p95_ms ?? "n/a"} ms`);
  console.log(`    avg latency  : ${tx.avg_latency_ms ?? "n/a"} ms`);
  console.log(`    success total: ${tx.total_success}`);
  console.log(`    failed total : ${tx.total_failed}`);
  if (tx.latency_percentiles) {
    const lp = tx.latency_percentiles;
    console.log(`    [p50=${lp.p50_ms ?? "—"} p95=${lp.p95_ms ?? "—"} p99=${lp.p99_ms ?? "—"}] (${lp.sample_size} samples)`);
  }
}

// ─── Level 1: HTTP Burst ──────────────────────────────────────────────────────

async function runLevel1() {
  console.log("\n" + "═".repeat(60));
  console.log("  NIVEAU 1 — BURST HTTP PUR");
  console.log("═".repeat(60));

  const baseline = await getHealth();
  console.log("\n[Baseline avant le test]");
  printHealth(baseline, "état initial");

  // ── Phase A: /api/health (no rate limit) ──
  console.log("\n── Phase A : 200 req concurrentes → GET /api/health (pas de rate limit) ──");
  const phA = await burst("GET /api/health ×200", 200, () => fetch(`${BASE_URL}/api/health`));
  console.log("  Status distribution:", phA.byStatus);
  console.log("  " + table(
    [["GET /api/health ×200", phA.s.p50, phA.s.p95, phA.s.p99, phA.s.avg, phA.s.min, phA.s.max]],
    ["Phase", "p50 ms", "p95 ms", "p99 ms", "avg ms", "min ms", "max ms"]
  ));

  await sleep(2000);

  // ── Phase B: /api/audit without auth ──
  console.log("\n── Phase B : 150 req concurrentes → POST /api/audit (sans auth) ──");
  const auditBody = JSON.stringify({
    agent_id: "stress-test",
    session_id: "stress-session",
    action_type: "deploy",
    action_description: "stress test",
    inputs_hash: "a".repeat(64),
    risk_level: "low",
    decision: "approved",
  });
  const phB = await burst("POST /api/audit ×150", 150, () =>
    fetch(`${BASE_URL}/api/audit`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: auditBody,
    })
  );
  console.log("  Status distribution:", phB.byStatus);
  console.log("  " + table(
    [["POST /api/audit ×150", phB.s.p50, phB.s.p95, phB.s.p99, phB.s.avg, phB.s.min, phB.s.max]],
    ["Phase", "p50 ms", "p95 ms", "p99 ms", "avg ms", "min ms", "max ms"]
  ));

  await sleep(3000);

  // ── Phase C: Rampe progressive ──
  console.log("\n── Phase C : Rampe progressive sur /api/health ──");
  const rampResults = [];
  for (const n of [10, 25, 50, 75, 100, 125, 150]) {
    const r = await burst(`×${n}`, n, () => fetch(`${BASE_URL}/api/health`));
    rampResults.push([`×${n}`, r.s.p50, r.s.p95, r.s.p99, r.s.avg, Object.entries(r.byStatus).map(([k, v]) => `${k}:${v}`).join(" ")]);
    await sleep(1000);
  }
  console.log("  " + table(rampResults, ["Concurrence", "p50 ms", "p95 ms", "p99 ms", "avg ms", "Status codes"]));

  await sleep(2000);

  const after = await getHealth();
  console.log("\n[État après niveau 1]");
  printHealth(after, "post-burst");

  // Verdict
  const maxP99 = Math.max(...[phA, phB].map(p => p.s.p99 || 0));
  const has5xx = [phA, phB].some(p => Object.keys(p.byStatus).some(s => s.startsWith("5")));
  const hasCrash = [phA, phB].some(p => (p.byStatus["net_err"] || 0) > 5);

  console.log("\n── Verdict Niveau 1 ──");
  console.log(`  p99 max observé : ${maxP99} ms`);
  console.log(`  Erreurs 5xx     : ${has5xx ? "OUI ⚠" : "NON ✓"}`);
  console.log(`  Drops réseau    : ${hasCrash ? "OUI ⚠" : "NON ✓"}`);
  console.log(`  Rate limiting   : ${Object.keys({...phB.byStatus}).includes("429") ? "actif ✓" : "non déclenché (normal si < seuil)"}`);
  if (maxP99 < 500 && !has5xx && !hasCrash) {
    console.log("  → RÉSULTAT : STABLE sous charge HTTP pure ✓");
  } else if (maxP99 < 2000 && !hasCrash) {
    console.log("  → RÉSULTAT : DÉGRADATION acceptable, pas de crash ⚠");
  } else {
    console.log("  → RÉSULTAT : DÉGRADATION sévère, investigation nécessaire ✗");
  }
}

// ─── Level 2: Queue Stress ────────────────────────────────────────────────────

const AGENTS_CACHE = "/tmp/xproof-stress-agents.json";

async function runLevel2() {
  console.log("\n" + "═".repeat(60));
  console.log("  NIVEAU 2 — STRESS TX_QUEUE (certifications réelles)");
  console.log("═".repeat(60));

  // Step 1: Load cached agents or register new ones
  let agents = [];
  if (existsSync(AGENTS_CACHE)) {
    try {
      const cached = JSON.parse(readFileSync(AGENTS_CACHE, "utf8"));
      // Filter to agents with remaining quota
      agents = cached.filter(a => (a.remaining ?? 10) > 0);
      if (agents.length > 0) {
        console.log(`\n[Étape 1] Agents chargés depuis le cache (${agents.length}) — skip registration`);
        for (const a of agents) console.log(`  ✓ ${a.name} (quota restant: ${a.remaining ?? "inconnu"})`);
      }
    } catch {}
  }

  if (agents.length === 0) {
    console.log("\n[Étape 1] Enregistrement des agents trial...");
    for (let i = 0; i < 3; i++) {
      try {
        const res = await fetch(`${BASE_URL}/api/agent/register`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ agent_name: `stress-agent-${Date.now()}-${i}` }),
        });
        const data = await res.json();
        if (res.ok && data.api_key) {
          agents.push({ key: data.api_key, name: data.agent_name, remaining: data.trial?.quota ?? 10 });
          console.log(`  ✓ Agent ${i + 1} enregistré: ${data.agent_name} (quota: ${data.trial?.quota ?? 10})`);
        } else {
          console.log(`  ✗ Échec agent ${i + 1}: ${JSON.stringify(data)}`);
        }
      } catch (e) {
        console.log(`  ✗ Erreur réseau agent ${i + 1}: ${e.message}`);
      }
      if (i < 2) await sleep(1500);
    }
    if (agents.length > 0) {
      writeFileSync(AGENTS_CACHE, JSON.stringify(agents, null, 2));
      console.log(`  Clés sauvegardées dans ${AGENTS_CACHE}`);
      // Wait for paymentRateLimiter to reset before certification burst
      console.log("\n  Pause 65s pour reset du paymentRateLimiter avant le burst...");
      await sleep(65_000);
    }
  }

  if (agents.length === 0) {
    console.log("  → Aucun agent disponible, abandon niveau 2");
    return;
  }

  console.log(`\n  ${agents.length} agent(s) prêt(s) → max ${agents.length * 10} certifications`);

  // Step 2: Baseline snapshot
  console.log("\n[Étape 2] Snapshot baseline...");
  const baseline = await getHealth();
  printHealth(baseline, "baseline avant burst");

  // Step 3: Fire certifications in waves of 10 (paymentRateLimiter = 10/min per IP)
  // Wave strategy: simultaneous within a wave, 65s between waves to reset rate limit
  const WAVE_SIZE = 10;
  const totalCerts = agents.length * 10;
  // Build cert tasks per agent: agent 0 has certs 0-9, agent 1 has certs 10-19, etc.
  const allCertJobs = [];
  for (const agent of agents) {
    for (let j = 0; j < 10; j++) {
      const hash = Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join("");
      allCertJobs.push({ agent, j, hash });
    }
  }

  const certResults = [];
  const waves = Math.ceil(allCertJobs.length / WAVE_SIZE);

  console.log(`\n[Étape 3] Lancement de ${totalCerts} certifications en ${waves} vague(s) de ${WAVE_SIZE} (paymentRateLimiter: 10/min par IP)...`);

  for (let w = 0; w < waves; w++) {
    const waveJobs = allCertJobs.slice(w * WAVE_SIZE, (w + 1) * WAVE_SIZE);
    console.log(`\n  Vague ${w + 1}/${waves} — ${waveJobs.length} certifications simultanées...`);
    const waveStart = Date.now();

    const waveTasks = waveJobs.map(({ agent, j, hash }) =>
      timed(() =>
        fetch(`${BASE_URL}/api/proof`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${agent.key}`,
          },
          body: JSON.stringify({
            file_hash: hash,
            filename: `stress-file-${w}-${j}.bin`,
            author_name: agent.name,
          }),
        })
      )
    );

    const waveResults = await Promise.all(waveTasks);
    const waveElapsed = Date.now() - waveStart;
    certResults.push(...waveResults);

    const waveByStatus = {};
    for (const r of waveResults) {
      const key = r.status === 0 ? "net_err" : String(r.status);
      waveByStatus[key] = (waveByStatus[key] || 0) + 1;
    }
    const waveTimes = waveResults.filter(r => r.status === 201).map(r => r.ms);
    const ws = stats(waveTimes);
    console.log(`    Temps: ${waveElapsed}ms | Status: ${JSON.stringify(waveByStatus)} | p50=${ws.p50 ?? "—"}ms p95=${ws.p95 ?? "—"}ms`);

    // Snapshot queue after each wave
    const h = await getHealth();
    const lp = h.transactions.latency_percentiles || {};
    console.log(`    Queue: depth=${h.blockchain_latency.queue_depth} p95=${lp.p95_ms ?? "—"}ms success=${h.transactions.total_success}`);

    if (w < waves - 1) {
      console.log(`\n    Pause 65s avant vague suivante (reset paymentRateLimiter)...`);
      await sleep(65_000);
    }
  }

  // Aggregate results
  const certByStatus = {};
  for (const r of certResults) {
    const key = r.status === 0 ? "net_err" : String(r.status);
    certByStatus[key] = (certByStatus[key] || 0) + 1;
  }
  const certTimes = certResults.filter(r => r.status === 201).map(r => r.ms);
  const certStats = stats(certTimes);

  console.log(`\n  Total — Status: ${JSON.stringify(certByStatus)}`);
  if (certTimes.length > 0) {
    console.log(`  Temps de réponse (certifs acceptées) : p50=${certStats.p50}ms p95=${certStats.p95}ms p99=${certStats.p99}ms avg=${certStats.avg}ms`);
  }

  // Step 4: Monitor queue over time
  console.log("\n[Étape 4] Monitoring queue pendant 3 minutes (sonde toutes les 5s)...");
  console.log("  " + ["T+0s", "queue_depth", "p50_ms", "p95_ms", "p99_ms", "total_success"].join(" | "));
  console.log("  " + "-".repeat(60));

  const monitorRows = [];
  const monitorStart = Date.now();
  const MONITOR_DURATION = 90_000; // 90s
  const POLL_INTERVAL = 5_000;

  while (Date.now() - monitorStart < MONITOR_DURATION) {
    try {
      const h = await getHealth();
      const elapsed = Math.round((Date.now() - monitorStart) / 1000);
      const bl = h.blockchain_latency;
      const lp = h.transactions.latency_percentiles || {};
      const row = [
        `T+${elapsed}s`,
        bl.queue_depth,
        lp.p50_ms ?? "—",
        lp.p95_ms ?? "—",
        lp.p99_ms ?? "—",
        h.transactions.total_success,
      ];
      monitorRows.push(row);
      console.log("  " + row.join(" | "));

      if (bl.queue_depth === 0 && elapsed > 10) {
        console.log("  → Queue vidée ✓");
        break;
      }
    } catch (e) {
      console.log(`  [sonde erreur: ${e.message}]`);
    }
    await sleep(POLL_INTERVAL);
  }

  // Final snapshot
  console.log("\n[Étape 5] Snapshot final...");
  const finalH = await getHealth();
  printHealth(finalH, "état final");

  // Verdict niveau 2
  const queuePeak = Math.max(...monitorRows.map(r => Number(r[1]) || 0));
  const maxP99Queue = Math.max(...monitorRows.map(r => Number(r[4]) || 0).filter(v => v > 0));
  const allConfirmed = certByStatus["201"] === agents.length * 10;

  console.log("\n── Verdict Niveau 2 ──");
  console.log(`  Certifications lancées  : ${agents.length * 10}`);
  console.log(`  Acceptées (201)         : ${certByStatus["201"] || 0}`);
  console.log(`  Queue peak depth        : ${queuePeak}`);
  console.log(`  p99 latency max observé : ${maxP99Queue || "n/a"} ms`);
  console.log(`  Toutes certifiées       : ${allConfirmed ? "OUI ✓" : "NON ⚠"}`);

  if (queuePeak <= 5 && allConfirmed) {
    console.log("  → RÉSULTAT : Queue gère le burst sans backlog significatif ✓");
  } else if (queuePeak <= 30 && (certByStatus["201"] || 0) > 0) {
    console.log(`  → RÉSULTAT : Backlog de ${queuePeak} jobs MX-8004 — se résorbe dans le temps ⚠`);
    console.log("     Pour 200 agents simultanés, prévoir ~" + Math.ceil(queuePeak * 10 / 30) + " min de backlog");
  } else {
    console.log("  → RÉSULTAT : Saturation détectée — optimisation worker recommandée ✗");
  }
}

// ─── Standalone Register ─────────────────────────────────────────────────────

async function runRegisterAgents() {
  console.log("\n" + "═".repeat(60));
  console.log("  ENREGISTREMENT AGENTS TRIAL");
  console.log("═".repeat(60));
  const agents = [];
  for (let i = 0; i < 3; i++) {
    try {
      const res = await fetch(`${BASE_URL}/api/agent/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ agent_name: `stress-agent-${Date.now()}-${i}` }),
      });
      const data = await res.json();
      if (res.ok && data.api_key) {
        agents.push({ key: data.api_key, name: data.agent_name, remaining: data.trial?.quota ?? 10 });
        console.log(`  ✓ Agent ${i + 1}: ${data.agent_name}`);
      } else {
        console.log(`  ✗ Échec: ${JSON.stringify(data)}`);
      }
    } catch (e) {
      console.log(`  ✗ Erreur: ${e.message}`);
    }
    if (i < 2) await sleep(1500);
  }
  if (agents.length > 0) {
    writeFileSync(AGENTS_CACHE, JSON.stringify(agents, null, 2));
    console.log(`\n  ${agents.length} agent(s) sauvegardés → ${AGENTS_CACHE}`);
    console.log("  Attends 65s puis lance: node stress-test.mjs --burst");
  }
}

// ─── Standalone Burst ─────────────────────────────────────────────────────────

async function runCertBurst() {
  console.log("\n" + "═".repeat(60));
  console.log("  BURST CERTIFICATIONS + MONITORING QUEUE");
  console.log("═".repeat(60));

  if (!existsSync(AGENTS_CACHE)) {
    console.log("  ✗ Pas de cache agents. Lance d'abord: node stress-test.mjs --register");
    return;
  }
  const agents = JSON.parse(readFileSync(AGENTS_CACHE, "utf8")).filter(a => (a.remaining ?? 10) > 0);
  if (agents.length === 0) {
    console.log("  ✗ Tous les quotas épuisés.");
    return;
  }
  console.log(`\n  ${agents.length} agent(s) chargés depuis le cache`);

  const baseline = await getHealth();
  console.log("\n[Baseline]");
  printHealth(baseline, "avant burst");

  // Build all cert jobs
  const allJobs = [];
  for (const agent of agents) {
    for (let j = 0; j < 10; j++) {
      const hash = Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join("");
      allJobs.push({ agent, j, hash });
    }
  }

  const WAVE_SIZE = 10;
  const waves = Math.ceil(allJobs.length / WAVE_SIZE);
  const allResults = [];

  console.log(`\n[Burst] ${allJobs.length} certifications en ${waves} vague(s) de ${WAVE_SIZE}...`);

  for (let w = 0; w < waves; w++) {
    const waveJobs = allJobs.slice(w * WAVE_SIZE, (w + 1) * WAVE_SIZE);
    if (w > 0) {
      console.log(`\n  Pause 65s (reset paymentRateLimiter)...`);
      await sleep(65_000);
    }

    const wStart = Date.now();
    process.stdout.write(`  Vague ${w + 1}/${waves} (${waveJobs.length} certs)...`);
    const results = await Promise.all(
      waveJobs.map(({ agent, j, hash }) =>
        timed(() => fetch(`${BASE_URL}/api/proof`, {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${agent.key}` },
          body: JSON.stringify({ file_hash: hash, filename: `stress-${w}-${j}.bin`, author_name: agent.name }),
        }))
      )
    );
    process.stdout.write(` ${Date.now() - wStart}ms\n`);
    allResults.push(...results);

    const byS = {};
    for (const r of results) { const k = r.status === 0 ? "err" : String(r.status); byS[k] = (byS[k] || 0) + 1; }
    const okTimes = results.filter(r => r.status === 201).map(r => r.ms);
    const ws = stats(okTimes);
    console.log(`    Status: ${JSON.stringify(byS)} | p50=${ws.p50 ?? "—"}ms p95=${ws.p95 ?? "—"}ms p99=${ws.p99 ?? "—"}ms`);

    const h = await getHealth();
    const lp = h.transactions.latency_percentiles || {};
    console.log(`    Queue: depth=${h.blockchain_latency.queue_depth} | health p95=${lp.p95_ms ?? "—"}ms | total_success=${h.transactions.total_success}`);
  }

  // Monitor queue drain
  console.log("\n[Monitoring queue 90s]");
  console.log("  " + ["T+s", "depth", "p50", "p95", "p99", "success"].join(" | "));
  console.log("  " + "-".repeat(50));
  const mStart = Date.now();
  const mRows = [];
  while (Date.now() - mStart < 90_000) {
    const h = await getHealth();
    const elapsed = Math.round((Date.now() - mStart) / 1000);
    const lp = h.transactions.latency_percentiles || {};
    const row = [`T+${elapsed}`, h.blockchain_latency.queue_depth, lp.p50_ms ?? "—", lp.p95_ms ?? "—", lp.p99_ms ?? "—", h.transactions.total_success];
    mRows.push(row);
    console.log("  " + row.join(" | "));
    if (h.blockchain_latency.queue_depth === 0 && elapsed > 5) { console.log("  → Queue vidée ✓"); break; }
    await sleep(5_000);
  }

  // Final verdict
  const totalOk = allResults.filter(r => r.status === 201).length;
  const qPeak = Math.max(...mRows.map(r => Number(r[1]) || 0));
  const okTimes = allResults.filter(r => r.status === 201).map(r => r.ms);
  const fStats = stats(okTimes);

  console.log("\n── Verdict Niveau 2 ──");
  console.log(table(
    [
      ["Certifications envoyées", allJobs.length],
      ["Acceptées (201)", totalOk],
      ["Queue peak depth", qPeak],
      ["p50 réponse serveur", `${fStats.p50 ?? "—"} ms`],
      ["p95 réponse serveur", `${fStats.p95 ?? "—"} ms`],
      ["p99 réponse serveur", `${fStats.p99 ?? "—"} ms`],
    ],
    ["Métrique", "Valeur"]
  ));
  if (totalOk === allJobs.length) console.log("  → Toutes certifications acceptées ✓");
  else console.log(`  → ${allJobs.length - totalOk} certifications rejetées ⚠`);
  if (qPeak <= 10) console.log("  → Queue: backlog faible, résorption rapide ✓");
  else if (qPeak <= 50) console.log(`  → Queue: backlog modéré (${qPeak} jobs MX-8004) — se résorbe ⚠`);
  else console.log(`  → Queue: saturation (${qPeak} jobs) — optimisation worker recommandée ✗`);

  // Clear cache
  writeFileSync(AGENTS_CACHE, JSON.stringify(agents.map(a => ({ ...a, remaining: 0 })), null, 2));
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  console.log("╔" + "═".repeat(58) + "╗");
  console.log("║  xproof Stress Test                                      ║");
  console.log("║  Target: " + BASE_URL.padEnd(48) + "║");
  console.log("╚" + "═".repeat(58) + "╝");
  const modeLabel = MODE_REGISTER ? "Register agents seulement" :
                    MODE_BURST ? "Burst certifications seulement" :
                    LEVEL === 1 ? "Niveau 1 seulement" :
                    LEVEL === 2 ? "Niveau 2 seulement" : "Niveaux 1 + 2";
  console.log(`  Mode: ${modeLabel}`);
  console.log(`  Heure: ${new Date().toISOString()}\n`);

  // Connectivity check
  try {
    await fetch(`${BASE_URL}/api/health`);
  } catch (e) {
    console.error(`✗ Serveur inaccessible sur ${BASE_URL}: ${e.message}`);
    process.exit(1);
  }

  if (MODE_REGISTER) { await runRegisterAgents(); return; }
  if (MODE_BURST) { await runCertBurst(); return; }
  if (LEVEL === 0 || LEVEL === 1) await runLevel1();
  if (LEVEL === 0 || LEVEL === 2) await runLevel2();

  console.log("\n" + "═".repeat(60));
  console.log("  STRESS TEST TERMINÉ");
  console.log("═".repeat(60) + "\n");
}

main().catch(e => {
  console.error("Erreur fatale:", e);
  process.exit(1);
});
