import type { Action, IAgentRuntime, Memory, State, HandlerCallback } from '@elizaos/core';
import type { XProofApiResponse } from '../types';
import { getConfig } from '../types';
import { getProof } from '../client';

export const verifyProofAction: Action = {
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
    _state: State | undefined,
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

      const statusLabel =
        result.status === 'certified'
          ? 'Confirmed'
          : result.status === 'pending'
            ? 'Pending'
            : result.status;

      const lines = [
        `Certificate ${result.proof_id}`,
        '',
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
