/**
 * xProof Skills -- off-chain certification for agent outputs
 *
 * Anchors SHA-256 proofs on MultiversX via the xProof API (https://xproof.app).
 * Supports API-key auth and x402 (HTTP 402) payment protocol.
 *
 * Composable with validation_skills.ts: certifyAndSubmitProof() chains
 * xProof certification with Validation Registry submit_proof in one call.
 */
import {createHash} from 'crypto';
import {promises as fs} from 'fs';

import {CONFIG} from '../config';
import {Logger} from '../utils/logger';
import {submitProof, type SubmitProofParams} from './validation_skills';

const logger = new Logger('xProofSkills');

// ─── Types ─────────────────────────────────────────────────────────────────────

export interface CertifyFileParams {
  filePath: string;
  fileName?: string;
  metadata?: Record<string, string>;
  webhookUrl?: string;
  useX402?: boolean;
  x402Payment?: string;
}

export interface CertifyHashParams {
  hash: string;
  fileName: string;
  fileSize?: number;
  metadata?: Record<string, string>;
  webhookUrl?: string;
  useX402?: boolean;
  x402Payment?: string;
}

export interface CertifyBatchParams {
  files: Array<{
    hash: string;
    fileName: string;
    fileSize?: number;
  }>;
  metadata?: Record<string, string>;
  webhookUrl?: string;
  useX402?: boolean;
  x402Payment?: string;
}

export interface CertificationResult {
  id: string;
  hash: string;
  fileName: string;
  status: string;
  txHash?: string;
  explorerUrl?: string;
  createdAt: string;
}

export interface BatchCertificationResult {
  results: CertificationResult[];
  total: number;
  certified: number;
}

export interface ProofData {
  id: string;
  hash: string;
  fileName: string;
  fileSize?: number;
  status: string;
  txHash?: string;
  explorerUrl?: string;
  blockNonce?: number;
  timestamp?: string;
  certifiedBy?: string;
  metadata?: Record<string, string>;
}

export interface CertifyAndSubmitResult {
  certification: CertificationResult;
  validationTxHash: string;
}

export interface AuditLogParams {
  agentId: string;
  sessionId: string;
  actionType: string;
  actionDescription: string;
  inputsHash: string;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  riskSummary?: string;
  decision: 'approved' | 'rejected' | 'deferred';
  context?: Record<string, unknown>;
  timestamp?: string;
  useX402?: boolean;
  x402Payment?: string;
}

export interface AuditResult {
  proof_id: string;
  audit_url: string;
  proof_url: string;
  decision: string;
  risk_level: string;
  inputs_hash: string;
  blockchain: {
    network: string;
    transaction_hash: string;
    explorer_url: string;
  };
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

async function hashFile(filePath: string): Promise<{hash: string; size: number}> {
  const content = await fs.readFile(filePath);
  const hash = createHash('sha256').update(content).digest('hex');
  return {hash, size: content.length};
}

function buildHeaders(useX402?: boolean, x402Payment?: string): Record<string, string> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'User-Agent': 'moltbot-starter-kit/1.0',
  };

  if (useX402 && x402Payment) {
    headers['X-Payment'] = x402Payment;
  } else if (CONFIG.XPROOF.API_KEY) {
    headers['Authorization'] = `Bearer ${CONFIG.XPROOF.API_KEY}`;
  }

  return headers;
}

async function xproofRequest<T>(
  method: string,
  endpoint: string,
  body?: unknown,
  useX402?: boolean,
  x402Payment?: string,
): Promise<T> {
  const url = `${CONFIG.XPROOF.BASE_URL}${endpoint}`;
  const headers = buildHeaders(useX402, x402Payment);

  const options: RequestInit = {method, headers};
  if (body) {
    options.body = JSON.stringify(body);
  }

  const response = await fetch(url, options);

  // x402: if server responds 402, return the payment requirements
  if (response.status === 402) {
    const paymentRequired = await response.json();
    throw new XProofPaymentRequired(paymentRequired);
  }

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`xProof API error ${response.status}: ${errorText}`);
  }

  return response.json() as Promise<T>;
}

// ─── Errors ────────────────────────────────────────────────────────────────────

export class XProofPaymentRequired extends Error {
  public paymentDetails: unknown;

  constructor(details: unknown) {
    super('xProof requires payment (HTTP 402). Use x402 or provide an API key.');
    this.name = 'XProofPaymentRequired';
    this.paymentDetails = details;
  }
}

export class AuditRequiredError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuditRequiredError';
  }
}

// ─── certify_file ──────────────────────────────────────────────────────────────
// Hash a local file and certify it on MultiversX via xProof

export async function certifyFile(
  params: CertifyFileParams,
): Promise<CertificationResult> {
  const {hash, size} = await hashFile(params.filePath);
  const fileName =
    params.fileName || params.filePath.split('/').pop() || 'unknown';

  logger.info(`Certifying file: ${fileName} (${size} bytes, hash=${hash.slice(0, 12)}...)`);

  const result = await xproofRequest<CertificationResult>(
    'POST',
    '/api/proof',
    {
      hash,
      fileName,
      fileSize: size,
      metadata: params.metadata,
      webhookUrl: params.webhookUrl,
    },
    params.useX402,
    params.x402Payment,
  );

  logger.info(`Certified: id=${result.id}, status=${result.status}`);
  return result;
}

// ─── certify_hash ──────────────────────────────────────────────────────────────
// Certify a pre-computed hash (no local file needed)

export async function certifyHash(
  params: CertifyHashParams,
): Promise<CertificationResult> {
  logger.info(
    `Certifying hash: ${params.hash.slice(0, 12)}... (${params.fileName})`,
  );

  const result = await xproofRequest<CertificationResult>(
    'POST',
    '/api/proof',
    {
      hash: params.hash,
      fileName: params.fileName,
      fileSize: params.fileSize,
      metadata: params.metadata,
      webhookUrl: params.webhookUrl,
    },
    params.useX402,
    params.x402Payment,
  );

  logger.info(`Certified: id=${result.id}, status=${result.status}`);
  return result;
}

// ─── certify_batch ─────────────────────────────────────────────────────────────
// Certify up to 50 files in a single API call

export async function certifyBatch(
  params: CertifyBatchParams,
): Promise<BatchCertificationResult> {
  if (params.files.length === 0) {
    throw new Error('certifyBatch requires at least one file');
  }
  if (params.files.length > 50) {
    throw new Error('certifyBatch supports a maximum of 50 files per call');
  }

  logger.info(`Batch certifying ${params.files.length} files`);

  const result = await xproofRequest<BatchCertificationResult>(
    'POST',
    '/api/batch',
    {
      files: params.files,
      metadata: params.metadata,
      webhookUrl: params.webhookUrl,
    },
    params.useX402,
    params.x402Payment,
  );

  logger.info(
    `Batch result: ${result.certified}/${result.total} certified`,
  );
  return result;
}

// ─── verify_proof ──────────────────────────────────────────────────────────────
// Check the status and blockchain details of an existing certification

export async function verifyProof(certId: string): Promise<ProofData> {
  logger.info(`Verifying proof: ${certId}`);

  const result = await xproofRequest<ProofData>('GET', `/api/proof/${certId}`);

  logger.info(
    `Proof ${certId}: status=${result.status}, txHash=${result.txHash || 'pending'}`,
  );
  return result;
}

// ─── certify_and_submit_proof ──────────────────────────────────────────────────
// Composite: xProof certify → Validation Registry submit_proof
//
// 1. Certify the file/hash on xProof (off-chain anchoring)
// 2. Use the returned hash as proofHash for on-chain submit_proof
//
// This creates a two-layer proof:
//   - xProof: immutable content hash with timestamp + explorer link
//   - MX-8004 Validation Registry: on-chain job proof for the agent economy

export async function certifyAndSubmitProof(params: {
  jobId: string;
  filePath?: string;
  hash?: string;
  fileName?: string;
  fileSize?: number;
  metadata?: Record<string, string>;
  webhookUrl?: string;
  useRelayer?: boolean;
  useX402?: boolean;
  x402Payment?: string;
}): Promise<CertifyAndSubmitResult> {
  if (!params.filePath && !params.hash) {
    throw new Error('certifyAndSubmitProof requires either filePath or hash');
  }

  logger.info(`certifyAndSubmitProof: jobId=${params.jobId}`);

  // Step 1: Certify on xProof
  let certification: CertificationResult;

  if (params.filePath) {
    certification = await certifyFile({
      filePath: params.filePath,
      fileName: params.fileName,
      metadata: params.metadata,
      webhookUrl: params.webhookUrl,
      useX402: params.useX402,
      x402Payment: params.x402Payment,
    });
  } else {
    certification = await certifyHash({
      hash: params.hash!,
      fileName: params.fileName || 'agent-output',
      fileSize: params.fileSize,
      metadata: params.metadata,
      webhookUrl: params.webhookUrl,
      useX402: params.useX402,
      x402Payment: params.x402Payment,
    });
  }

  // Step 2: Submit the xProof hash to the Validation Registry on-chain
  const submitParams: SubmitProofParams = {
    jobId: params.jobId,
    proofHash: certification.hash,
    useRelayer: params.useRelayer,
  };

  const validationTxHash = await submitProof(submitParams);

  logger.info(
    `certifyAndSubmitProof complete: xproof=${certification.id}, validation_tx=${validationTxHash}`,
  );

  return {certification, validationTxHash};
}

// ─── audit_agent_session ────────────────────────────────────────────────────────
// Certify an agent decision on-chain BEFORE executing a critical action.
// If this call fails or returns no proof_id, the caller MUST NOT proceed.
// There is no soft fail. There is no fallback.

export async function auditAgentSession(
  params: AuditLogParams,
): Promise<AuditResult> {
  logger.info(
    `Auditing: ${params.actionType} — ${params.actionDescription} (risk=${params.riskLevel}, decision=${params.decision})`,
  );

  const payload = {
    agent_id: params.agentId,
    session_id: params.sessionId,
    action_type: params.actionType,
    action_description: params.actionDescription,
    inputs_hash: params.inputsHash,
    risk_level: params.riskLevel,
    risk_summary: params.riskSummary,
    decision: params.decision,
    context: params.context,
    timestamp: params.timestamp || new Date().toISOString(),
  };

  try {
    const url = `${CONFIG.XPROOF.BASE_URL}/api/audit`;
    const headers = buildHeaders(params.useX402, params.x402Payment);

    const response = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(15_000),
    });

    if (response.status === 402) {
      const paymentRequired = await response.json();
      throw new AuditRequiredError(
        `EXECUTION BLOCKED: Audit requires payment. ${JSON.stringify(paymentRequired)}`,
      );
    }

    if (!response.ok) {
      const errorText = await response.text();
      throw new AuditRequiredError(
        `EXECUTION BLOCKED: Audit certification failed (HTTP ${response.status}): ${errorText.slice(0, 300)}`,
      );
    }

    const result = (await response.json()) as AuditResult;

    if (!result.proof_id) {
      throw new AuditRequiredError(
        'EXECUTION BLOCKED: xProof returned no proof_id.',
      );
    }

    logger.info(
      `Audit certified: proof_id=${result.proof_id}, decision=${result.decision}, risk=${result.risk_level}`,
    );
    return result;
  } catch (err) {
    if (err instanceof AuditRequiredError) {
      logger.error(`Audit BLOCKED: ${err.message}`);
      throw err;
    }

    const msg = err instanceof Error ? err.message : String(err);
    const blockError = new AuditRequiredError(
      `EXECUTION BLOCKED: Audit certification failed. ${msg}`,
    );
    logger.error(`Audit BLOCKED: ${blockError.message}`);
    throw blockError;
  }
}
