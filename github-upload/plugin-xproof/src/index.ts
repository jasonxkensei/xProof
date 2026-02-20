import type { Plugin, Action, IAgentRuntime, Memory, State, HandlerCallback } from '@elizaos/core';
import { createHash } from 'crypto';

interface XProofConfig {
  apiKey: string;
  baseUrl: string;
}

interface XProofApiResponse {
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

interface XProofBatchResponse {
  results: XProofApiResponse[];
  total: number;
  succeeded: number;
  failed: number;
}

function getConfig(runtime: IAgentRuntime): XProofConfig {
  const apiKey =
    runtime.getSetting('XPROOF_API_KEY') ?? process.env.XPROOF_API_KEY ?? '';
  const baseUrl =
    runtime.getSetting('XPROOF_BASE_URL') ??
    process.env.XPROOF_BASE_URL ??
    'https://xproof.app';
  return { apiKey, baseUrl };
}

function sha256(content: string): string {
  return createHash('sha256').update(content, 'utf8').digest('hex');
}

async function callXProof(
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
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`xProof API error ${res.status}: ${text}`);
  }

  return res.json();
}

async function getProof(
  config: XProofConfig,
  proofId: string
): Promise<unknown> {
  const res = await fetch(`${config.baseUrl}/api/proof/${proofId}`, {
    headers: { Authorization: `Bearer ${config.apiKey}` },
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`xProof verify error ${res.status}: ${text}`);
  }

  return res.json();
}

function formatProofResponse(result: XProofApiResponse): string {
  const lines = [
    `Content certified on MultiversX blockchain.`,
    ``,
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

const certifyContentAction: Action = {
  name: 'CERTIFY_CONTENT',
  similes: [
    'ANCHOR_CONTENT',
    'PROOF_CONTENT',
    'BLOCKCHAIN_CERTIFY',
    'CERTIFY_OUTPUT',
    'CERTIFY_DECISION',
    'CERTIFY_REPORT',
  ],
  description:
    'Certify text content on the MultiversX blockchain via xProof. The content is hashed locally (SHA-256) and only the hash is sent to xProof — the content never leaves your agent. Returns a certificate ID and verification URL.',
  validate: async (runtime: IAgentRuntime) => {
    const { apiKey } = getConfig(runtime);
    return !!apiKey;
  },
  handler: async (
    runtime: IAgentRuntime,
    message: Memory,
    _state: State,
    options: Record<string, unknown>,
    callback?: HandlerCallback
  ) => {
    const config = getConfig(runtime);
    const content =
      (options?.content as string) ?? message.content?.text ?? '';
    const filename =
      (options?.filename as string) ?? 'agent-output.txt';
    const authorName =
      (options?.author_name as string) ?? 'ElizaOS Agent';
    const webhookUrl = options?.webhook_url as string | undefined;

    if (!content) {
      callback?.({ text: 'No content provided to certify.', error: true });
      return false;
    }

    try {
      const fileHash = sha256(content);

      const body: Record<string, unknown> = {
        file_hash: fileHash,
        filename,
        author_name: authorName,
      };
      if (webhookUrl) body.webhook_url = webhookUrl;

      const result = (await callXProof(config, '/api/proof', body)) as XProofApiResponse;

      callback?.({ text: formatProofResponse(result), data: result });
      return true;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      callback?.({ text: `xProof certification failed: ${msg}`, error: true });
      return false;
    }
  },
  examples: [
    [
      {
        user: '{{user1}}',
        content: { text: 'Certify this decision: deploy to production approved at 2026-02-20T14:00:00Z' },
      },
      {
        user: '{{agent}}',
        content: {
          text: 'Content certified on MultiversX blockchain.\n\nCertificate ID: cert_abc123\nStatus: certified\nVerify: https://xproof.app/proof/cert_abc123',
          action: 'CERTIFY_CONTENT',
        },
      },
    ],
  ],
};

const certifyHashAction: Action = {
  name: 'CERTIFY_HASH',
  similes: ['ANCHOR_HASH', 'PROOF_HASH', 'CERTIFY_FILE_HASH'],
  description:
    'Certify a SHA-256 file hash on the MultiversX blockchain via xProof. Use when you already have a hash and want to create an on-chain proof of existence.',
  validate: async (runtime: IAgentRuntime) => {
    const { apiKey } = getConfig(runtime);
    return !!apiKey;
  },
  handler: async (
    runtime: IAgentRuntime,
    _message: Memory,
    _state: State,
    options: Record<string, unknown>,
    callback?: HandlerCallback
  ) => {
    const config = getConfig(runtime);
    const fileHash = (options?.file_hash as string) ?? (options?.hash as string) ?? '';
    const filename = (options?.filename as string) ?? 'certified-file';
    const authorName = (options?.author_name as string) ?? 'ElizaOS Agent';
    const webhookUrl = options?.webhook_url as string | undefined;

    if (!fileHash || fileHash.length !== 64) {
      callback?.({ text: 'Invalid hash. Expected a 64-character SHA-256 hex string.', error: true });
      return false;
    }

    try {
      const body: Record<string, unknown> = {
        file_hash: fileHash,
        filename,
        author_name: authorName,
      };
      if (webhookUrl) body.webhook_url = webhookUrl;

      const result = (await callXProof(config, '/api/proof', body)) as XProofApiResponse;

      callback?.({ text: formatProofResponse(result), data: result });
      return true;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      callback?.({ text: `xProof hash certification failed: ${msg}`, error: true });
      return false;
    }
  },
  examples: [
    [
      {
        user: '{{user1}}',
        content: { text: 'Certify hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 filename report.pdf' },
      },
      {
        user: '{{agent}}',
        content: {
          text: 'Content certified on MultiversX blockchain.\n\nCertificate ID: cert_abc123\nStatus: certified\nVerify: https://xproof.app/proof/cert_abc123',
          action: 'CERTIFY_HASH',
        },
      },
    ],
  ],
};

const certifyBatchAction: Action = {
  name: 'CERTIFY_BATCH',
  similes: ['BATCH_CERTIFY', 'ANCHOR_BATCH', 'PROOF_BATCH'],
  description:
    'Certify multiple file hashes (up to 50) in a single API call via xProof. Each item needs a file_hash (64-char SHA-256 hex) and filename.',
  validate: async (runtime: IAgentRuntime) => {
    const { apiKey } = getConfig(runtime);
    return !!apiKey;
  },
  handler: async (
    runtime: IAgentRuntime,
    _message: Memory,
    _state: State,
    options: Record<string, unknown>,
    callback?: HandlerCallback
  ) => {
    const config = getConfig(runtime);
    const files = options?.files as Array<{ file_hash: string; filename: string }>;
    const authorName = (options?.author_name as string) ?? 'ElizaOS Agent';

    if (!files || !Array.isArray(files) || files.length === 0) {
      callback?.({ text: 'No files array provided for batch certification. Expected: [{ file_hash, filename }, ...]', error: true });
      return false;
    }

    if (files.length > 50) {
      callback?.({ text: 'Batch limit is 50 items. Please split into smaller batches.', error: true });
      return false;
    }

    try {
      const result = (await callXProof(config, '/api/batch', {
        files,
        author_name: authorName,
      })) as XProofBatchResponse;

      const lines = [
        `Batch certified on MultiversX blockchain.`,
        ``,
        `Total: ${result.total}`,
        `Succeeded: ${result.succeeded}`,
        `Failed: ${result.failed}`,
        ``,
        ...result.results.map((r, i) => `${i + 1}. ${r.proof_id} - ${r.status} - ${r.verify_url}`),
      ];

      callback?.({ text: lines.join('\n'), data: result });
      return true;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      callback?.({ text: `xProof batch certification failed: ${msg}`, error: true });
      return false;
    }
  },
  examples: [],
};

const verifyProofAction: Action = {
  name: 'VERIFY_PROOF',
  similes: ['CHECK_CERT', 'VERIFY_CERT', 'CHECK_PROOF', 'LOOKUP_CERT'],
  description:
    'Verify the status of an xProof certificate by its proof ID. Returns on-chain status and blockchain details.',
  validate: async (runtime: IAgentRuntime) => {
    const { apiKey } = getConfig(runtime);
    return !!apiKey;
  },
  handler: async (
    runtime: IAgentRuntime,
    _message: Memory,
    _state: State,
    options: Record<string, unknown>,
    callback?: HandlerCallback
  ) => {
    const config = getConfig(runtime);
    const proofId = (options?.proof_id as string) ?? (options?.certId as string) ?? '';

    if (!proofId) {
      callback?.({ text: 'No proof ID provided.', error: true });
      return false;
    }

    try {
      const result = (await getProof(config, proofId)) as XProofApiResponse;

      const statusLabel = result.status === 'certified' ? 'Confirmed' : result.status === 'pending' ? 'Pending' : result.status;

      const lines = [
        `Certificate ${result.proof_id}`,
        ``,
        `Status: ${statusLabel}`,
        `Hash: ${result.file_hash}`,
        `Filename: ${result.filename}`,
        `Verify: ${result.verify_url}`,
      ];
      if (result.blockchain?.explorer_url) {
        lines.push(`Explorer: ${result.blockchain.explorer_url}`);
      }
      lines.push(`Timestamp: ${result.timestamp}`);

      callback?.({ text: lines.join('\n'), data: result });
      return true;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      callback?.({ text: `xProof verify failed: ${msg}`, error: true });
      return false;
    }
  },
  examples: [],
};

export const xproofPlugin: Plugin = {
  name: 'xproof',
  description:
    'Certify agent outputs on the MultiversX blockchain via xProof. Supports text content (hashed locally), file hashes, batch certification (up to 50), and proof verification. Starting at $0.05/cert — price decreases as network grows. Current pricing: https://xproof.app/api/pricing. 6-second finality.',
  actions: [
    certifyContentAction,
    certifyHashAction,
    certifyBatchAction,
    verifyProofAction,
  ],
};

export default xproofPlugin;
