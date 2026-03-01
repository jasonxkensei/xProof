import type { IAgentRuntime } from '@elizaos/core';

export interface XProofConfig {
  apiKey: string;
  baseUrl: string;
}

export interface XProofApiResponse {
  proof_id: string;
  status: string;
  file_hash: string;
  filename: string;
  verify_url: string;
  certificate_url: string;
  proof_json_url: string;
  blockchain: {
    network: string;
    transaction_hash: string;
    explorer_url: string;
  };
  timestamp: string;
  message?: string;
}

export interface XProofBatchResponse {
  results: XProofApiResponse[];
  total: number;
  succeeded: number;
  failed: number;
}

export interface AuditLogPayload {
  agent_id: string;
  session_id: string;
  action_type: string;
  action_description: string;
  inputs_hash: string;
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  decision: 'approved' | 'rejected' | 'deferred';
  risk_summary?: string;
  context?: Record<string, unknown>;
  timestamp: string;
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

export class AuditRequiredError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuditRequiredError';
  }
}

export function getConfig(runtime: IAgentRuntime): XProofConfig {
  const apiKey = String(
    runtime.getSetting('XPROOF_API_KEY') ?? process.env.XPROOF_API_KEY ?? ''
  );
  const baseUrl = String(
    runtime.getSetting('XPROOF_BASE_URL') ??
      process.env.XPROOF_BASE_URL ??
      'https://xproof.app'
  );
  return { apiKey, baseUrl };
}
