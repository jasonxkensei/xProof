import { createHash } from 'crypto';
import type { XProofConfig, XProofApiResponse, AuditLogPayload, AuditResult } from './types';

export function sha256(content: string): string {
  return createHash('sha256').update(content, 'utf8').digest('hex');
}

export async function callXProof(
  config: XProofConfig,
  path: string,
  body: Record<string, unknown>
): Promise<unknown> {
  if (!config.apiKey) {
    throw new Error(
      'XPROOF_API_KEY is not set. Get one at https://xproof.app'
    );
  }

  const res = await fetch(`${config.baseUrl}${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${config.apiKey}`,
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(30_000),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`xProof API error ${res.status}: ${text}`);
  }

  return res.json();
}

export async function getProof(
  config: XProofConfig,
  proofId: string
): Promise<unknown> {
  const res = await fetch(`${config.baseUrl}/api/proof/${proofId}`, {
    headers: { Authorization: `Bearer ${config.apiKey}` },
    signal: AbortSignal.timeout(15_000),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`xProof verify error ${res.status}: ${text}`);
  }

  return res.json();
}

export async function callAudit(
  config: XProofConfig,
  payload: AuditLogPayload
): Promise<AuditResult> {
  if (!config.apiKey) {
    throw new Error(
      'XPROOF_API_KEY is not set. Get one at https://xproof.app'
    );
  }

  const res = await fetch(`${config.baseUrl}/api/audit`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${config.apiKey}`,
    },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(15_000),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(
      `xProof audit certification failed (HTTP ${res.status}): ${text.slice(0, 300)}`
    );
  }

  return res.json() as Promise<AuditResult>;
}

export function formatProofResponse(result: XProofApiResponse): string {
  const lines = [
    'Content certified on MultiversX blockchain.',
    '',
    `Certificate ID: ${result.proof_id}`,
    `Status: ${result.status}`,
    `Hash: ${result.file_hash}`,
    `Filename: ${result.filename}`,
    `Verify: ${result.verify_url}`,
  ];
  if (result.blockchain?.explorer_url) {
    lines.push(`Explorer: ${result.blockchain.explorer_url}`);
  }
  lines.push(`Timestamp: ${result.timestamp}`);
  return lines.join('\n');
}
