const BASE_URL = process.env.BASE_URL || "http://localhost:5000";
const CONCURRENCY = parseInt(process.env.CONCURRENCY || "50");
const API_KEY = process.env.LOAD_TEST_API_KEY || "";

interface Result {
  status: number;
  latency_ms: number;
  error?: string;
}

async function callProofEndpoint(index: number): Promise<Result> {
  const hash = Array.from(crypto.getRandomValues(new Uint8Array(32)))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  const start = performance.now();
  try {
    const res = await fetch(`${BASE_URL}/api/proof`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${API_KEY}`,
      },
      body: JSON.stringify({
        file_hash: hash,
        filename: `loadtest-${index}.txt`,
      }),
    });
    const latency_ms = Math.round(performance.now() - start);
    return { status: res.status, latency_ms };
  } catch (err: any) {
    const latency_ms = Math.round(performance.now() - start);
    return { status: 0, latency_ms, error: err.message };
  }
}

async function callHealthEndpoint(): Promise<Result> {
  const start = performance.now();
  try {
    const res = await fetch(`${BASE_URL}/api/health`);
    const latency_ms = Math.round(performance.now() - start);
    return { status: res.status, latency_ms };
  } catch (err: any) {
    const latency_ms = Math.round(performance.now() - start);
    return { status: 0, latency_ms, error: err.message };
  }
}

async function runLoadTest() {
  console.log(`\n=== xproof Load Test ===`);
  console.log(`Target: ${BASE_URL}`);
  console.log(`Concurrency: ${CONCURRENCY}\n`);

  console.log("--- Health endpoint (warm-up) ---");
  const healthResults = await Promise.all(
    Array.from({ length: 20 }, () => callHealthEndpoint())
  );
  const healthLatencies = healthResults.map((r) => r.latency_ms);
  const healthErrors = healthResults.filter((r) => r.status !== 200).length;
  console.log(`  Requests: 20 | Errors: ${healthErrors}`);
  console.log(`  Avg: ${Math.round(healthLatencies.reduce((a, b) => a + b, 0) / healthLatencies.length)}ms`);
  console.log(`  P50: ${healthLatencies.sort((a, b) => a - b)[Math.floor(healthLatencies.length * 0.5)]}ms`);
  console.log(`  P99: ${healthLatencies.sort((a, b) => a - b)[Math.floor(healthLatencies.length * 0.99)]}ms`);
  console.log(`  Max: ${Math.max(...healthLatencies)}ms\n`);

  if (!API_KEY) {
    console.log("--- POST /api/proof (auth check, no API key) ---");
    const authResults = await Promise.all(
      Array.from({ length: CONCURRENCY }, (_, i) => callProofEndpoint(i))
    );
    const authLatencies = authResults.map((r) => r.latency_ms);
    const got401 = authResults.filter((r) => r.status === 401).length;
    const authErrors = authResults.filter((r) => r.status !== 401 && r.status !== 200).length;
    console.log(`  Requests: ${CONCURRENCY} | 401s: ${got401} | Other errors: ${authErrors}`);
    console.log(`  Avg: ${Math.round(authLatencies.reduce((a, b) => a + b, 0) / authLatencies.length)}ms`);
    console.log(`  P50: ${authLatencies.sort((a, b) => a - b)[Math.floor(authLatencies.length * 0.5)]}ms`);
    console.log(`  P99: ${authLatencies.sort((a, b) => a - b)[Math.floor(authLatencies.length * 0.99)]}ms`);
    console.log(`  Max: ${Math.max(...authLatencies)}ms`);
    console.log(`\n  (Set LOAD_TEST_API_KEY env var to test actual certification flow)\n`);
  } else {
    console.log(`--- POST /api/proof (${CONCURRENCY} concurrent) ---`);
    const proofResults = await Promise.all(
      Array.from({ length: CONCURRENCY }, (_, i) => callProofEndpoint(i))
    );
    const proofLatencies = proofResults.map((r) => r.latency_ms);
    const success = proofResults.filter((r) => r.status === 200 || r.status === 201).length;
    const errors = proofResults.filter((r) => r.status !== 200 && r.status !== 201);
    const sorted = proofLatencies.sort((a, b) => a - b);

    console.log(`  Requests: ${CONCURRENCY}`);
    console.log(`  Success: ${success} | Errors: ${errors.length}`);
    console.log(`  Avg: ${Math.round(proofLatencies.reduce((a, b) => a + b, 0) / proofLatencies.length)}ms`);
    console.log(`  P50: ${sorted[Math.floor(sorted.length * 0.5)]}ms`);
    console.log(`  P95: ${sorted[Math.floor(sorted.length * 0.95)]}ms`);
    console.log(`  P99: ${sorted[Math.floor(sorted.length * 0.99)]}ms`);
    console.log(`  Max: ${Math.max(...proofLatencies)}ms`);

    if (errors.length > 0) {
      const statusCounts: Record<number, number> = {};
      errors.forEach((e) => { statusCounts[e.status] = (statusCounts[e.status] || 0) + 1; });
      console.log(`  Error breakdown: ${JSON.stringify(statusCounts)}`);
    }
  }

  console.log("\n=== Load test complete ===\n");
}

runLoadTest().catch(console.error);
