import {
  Transaction,
  TransactionComputer,
  Address,
} from "@multiversx/sdk-core";

const PRIVATE_KEY = process.env.MULTIVERSX_PRIVATE_KEY;
const SENDER_ADDRESS = process.env.MULTIVERSX_SENDER_ADDRESS;
const GATEWAY_URL = process.env.MULTIVERSX_GATEWAY_URL || "https://gateway.multiversx.com";
const API_URL = process.env.MULTIVERSX_API_URL || "https://api.multiversx.com";
const CHAIN_ID = process.env.MULTIVERSX_CHAIN_ID || "1";

const IDENTITY_REGISTRY = process.env.MX8004_IDENTITY_REGISTRY;
const VALIDATION_REGISTRY = process.env.MX8004_VALIDATION_REGISTRY;
const REPUTATION_REGISTRY = process.env.MX8004_REPUTATION_REGISTRY;
const XPROOF_AGENT_NONCE = process.env.MX8004_XPROOF_AGENT_NONCE;

export function isMX8004Configured(): boolean {
  return !!(PRIVATE_KEY && SENDER_ADDRESS && IDENTITY_REGISTRY && VALIDATION_REGISTRY && REPUTATION_REGISTRY && XPROOF_AGENT_NONCE);
}

function toHex(str: string): string {
  return Buffer.from(str, "utf-8").toString("hex");
}

function numberToHex(n: number | bigint): string {
  const hex = BigInt(n).toString(16);
  return hex.length % 2 === 0 ? hex : "0" + hex;
}

function addressToHex(bech32: string): string {
  const addr = Address.newFromBech32(bech32);
  return Buffer.from(addr.getPublicKey()).toString("hex");
}

let localNonce: bigint | null = null;
const txQueue: Array<() => Promise<void>> = [];
let processing = false;

async function getNextNonce(): Promise<bigint> {
  if (localNonce === null) {
    const response = await fetch(`${API_URL}/address/${SENDER_ADDRESS}`);
    if (!response.ok) throw new Error(`Failed to fetch nonce: ${response.statusText}`);
    const data = await response.json();
    localNonce = BigInt(data.nonce || 0);
  }
  const nonce = localNonce;
  localNonce = localNonce + BigInt(1);
  return nonce;
}

function resetNonce() {
  localNonce = null;
}

async function processQueue() {
  if (processing) return;
  processing = true;
  while (txQueue.length > 0) {
    const task = txQueue.shift()!;
    try {
      await task();
    } catch (err: any) {
      console.error("[MX-8004] Queue task error:", err.message);
      resetNonce();
    }
  }
  processing = false;
}

function enqueue(task: () => Promise<void>) {
  txQueue.push(task);
  processQueue();
}

async function signAndSubmit(tx: Transaction): Promise<string> {
  const privateKeyHex = PRIVATE_KEY!.replace(/^0x/i, "");
  const privateKeyBuffer = Buffer.from(privateKeyHex, "hex");
  const computer = new TransactionComputer();
  const serializedTx = computer.computeBytesForSigning(tx);
  const ed = await import("@noble/ed25519");
  const signature = await ed.sign(serializedTx, privateKeyBuffer.slice(0, 32));
  tx.signature = Buffer.from(signature);

  const response = await fetch(`${GATEWAY_URL}/transaction/send`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(tx.toSendable()),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Gateway error: ${response.statusText} - ${errorText}`);
  }

  const result = await response.json();
  if (result.error) throw new Error(`Transaction error: ${result.error}`);
  if (!result.data?.txHash) throw new Error(`Invalid response: ${JSON.stringify(result)}`);

  return result.data.txHash;
}

async function buildScCall(
  contractAddress: string,
  functionName: string,
  args: string[],
  value: bigint = BigInt(0),
  gasLimit: bigint = BigInt(10_000_000)
): Promise<Transaction> {
  const nonce = await getNextNonce();
  const dataPayload = [functionName, ...args].join("@");

  return new Transaction({
    nonce,
    value,
    sender: Address.newFromBech32(SENDER_ADDRESS!),
    receiver: Address.newFromBech32(contractAddress),
    gasLimit,
    data: Buffer.from(dataPayload),
    chainID: CHAIN_ID,
  });
}

async function vmQuery(
  contractAddress: string,
  funcName: string,
  args: string[] = []
): Promise<string[]> {
  const response = await fetch(`${API_URL}/vm-values/query`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      scAddress: contractAddress,
      funcName,
      args,
    }),
  });

  if (!response.ok) throw new Error(`VM query error: ${response.statusText}`);
  const result = await response.json();

  if (result.data?.data?.returnCode !== "ok") {
    throw new Error(`VM query failed: ${result.data?.data?.returnMessage || "unknown"}`);
  }

  return result.data?.data?.returnData || [];
}

export async function registerAgent(
  name: string,
  uri: string,
  publicKey: string
): Promise<string> {
  if (!isMX8004Configured()) throw new Error("MX-8004 not configured");

  const tx = await buildScCall(
    IDENTITY_REGISTRY!,
    "register_agent",
    [toHex(name), toHex(uri), toHex(publicKey)],
    BigInt(0),
    BigInt(20_000_000)
  );

  return signAndSubmit(tx);
}

export async function initJob(
  jobId: string,
  agentNonce: number,
  serviceId?: number
): Promise<string> {
  if (!isMX8004Configured()) throw new Error("MX-8004 not configured");

  const args = [toHex(jobId), numberToHex(agentNonce)];
  if (serviceId !== undefined) {
    args.push(numberToHex(serviceId));
  }

  const tx = await buildScCall(
    VALIDATION_REGISTRY!,
    "init_job",
    args,
    BigInt(0),
    BigInt(15_000_000)
  );

  return signAndSubmit(tx);
}

export async function submitProof(
  jobId: string,
  proof: string
): Promise<string> {
  if (!isMX8004Configured()) throw new Error("MX-8004 not configured");

  const tx = await buildScCall(
    VALIDATION_REGISTRY!,
    "submit_proof",
    [toHex(jobId), toHex(proof)],
    BigInt(0),
    BigInt(10_000_000)
  );

  return signAndSubmit(tx);
}

export async function validationRequest(
  jobId: string,
  validatorAddress: string,
  requestUri: string,
  requestHash: string
): Promise<string> {
  if (!isMX8004Configured()) throw new Error("MX-8004 not configured");

  const tx = await buildScCall(
    VALIDATION_REGISTRY!,
    "validation_request",
    [toHex(jobId), addressToHex(validatorAddress), toHex(requestUri), toHex(requestHash)],
    BigInt(0),
    BigInt(15_000_000)
  );

  return signAndSubmit(tx);
}

export async function validationResponse(
  requestHash: string,
  response: number,
  responseUri: string,
  responseHash: string,
  tag: string
): Promise<string> {
  if (!isMX8004Configured()) throw new Error("MX-8004 not configured");

  const tx = await buildScCall(
    VALIDATION_REGISTRY!,
    "validation_response",
    [toHex(requestHash), numberToHex(response), toHex(responseUri), toHex(responseHash), toHex(tag)],
    BigInt(0),
    BigInt(15_000_000)
  );

  return signAndSubmit(tx);
}

export async function getReputationScore(agentNonce: number): Promise<{ score: number; totalJobs: number }> {
  if (!isMX8004Configured()) throw new Error("MX-8004 not configured");

  const [scoreData] = await vmQuery(REPUTATION_REGISTRY!, "get_reputation_score", [numberToHex(agentNonce)]);
  const [jobsData] = await vmQuery(REPUTATION_REGISTRY!, "get_total_jobs", [numberToHex(agentNonce)]);

  const score = scoreData ? parseInt(Buffer.from(scoreData, "base64").toString("hex") || "0", 16) : 0;
  const totalJobs = jobsData ? parseInt(Buffer.from(jobsData, "base64").toString("hex") || "0", 16) : 0;

  return { score, totalJobs };
}

export async function getAgentDetails(agentNonce: number): Promise<{ name: string; publicKey: string } | null> {
  if (!isMX8004Configured()) throw new Error("MX-8004 not configured");

  try {
    const returnData = await vmQuery(IDENTITY_REGISTRY!, "get_agent", [numberToHex(agentNonce)]);
    if (!returnData || returnData.length < 2) return null;

    const name = Buffer.from(returnData[0], "base64").toString("utf-8");
    const publicKey = Buffer.from(returnData[1], "base64").toString("hex");

    return { name, publicKey };
  } catch {
    return null;
  }
}

export async function isJobVerified(jobId: string): Promise<boolean> {
  if (!isMX8004Configured()) throw new Error("MX-8004 not configured");

  try {
    const [data] = await vmQuery(VALIDATION_REGISTRY!, "is_job_verified", [toHex(jobId)]);
    if (!data) return false;
    const hex = Buffer.from(data, "base64").toString("hex");
    return hex === "01";
  } catch {
    return false;
  }
}

export async function recordCertificationAsJob(
  certificationId: string,
  fileHash: string,
  transactionHash: string
): Promise<void> {
  if (!isMX8004Configured()) {
    return;
  }

  const agentNonce = parseInt(XPROOF_AGENT_NONCE!);
  if (isNaN(agentNonce) || agentNonce < 1) {
    console.error("[MX-8004] Invalid XPROOF_AGENT_NONCE value");
    return;
  }

  enqueue(async () => {
    const jobId = `xproof_cert_${certificationId}`;
    const proof = `hash:${fileHash}|tx:${transactionHash}`;

    console.log(`[MX-8004] Registering job: ${jobId} for agent nonce ${agentNonce}`);

    const jobTxHash = await initJob(jobId, agentNonce);
    console.log(`[MX-8004] Job initialized: ${jobTxHash}`);

    const proofTxHash = await submitProof(jobId, proof);
    console.log(`[MX-8004] Proof submitted: ${proofTxHash}`);
  });
}

export function getExplorerUrl(txHash: string): string {
  const base = CHAIN_ID === "D"
    ? "https://devnet-explorer.multiversx.com"
    : CHAIN_ID === "T"
    ? "https://testnet-explorer.multiversx.com"
    : "https://explorer.multiversx.com";
  return `${base}/transactions/${txHash}`;
}

export function getContractAddresses() {
  return {
    identityRegistry: IDENTITY_REGISTRY || null,
    validationRegistry: VALIDATION_REGISTRY || null,
    reputationRegistry: REPUTATION_REGISTRY || null,
  };
}
