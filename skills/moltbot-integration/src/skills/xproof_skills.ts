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
