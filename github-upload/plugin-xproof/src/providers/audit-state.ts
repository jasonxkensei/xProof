import type { Provider, IAgentRuntime, Memory, State } from '@elizaos/core';

export const auditStateProvider: Provider = {
  get: async (
    _runtime: IAgentRuntime,
    _message: Memory,
    state?: State
  ): Promise<string> => {
    const proofId = (state as Record<string, unknown>)?.xproofProofId as
      | string
      | undefined;
    const auditUrl = (state as Record<string, unknown>)?.xproofAuditUrl as
      | string
      | undefined;

    if (!proofId) {
      return 'xProof Audit: No active audit certificate. Call AUDIT_BEFORE_EXECUTE before any critical action.';
    }

    return [
      'xProof Audit State:',
      `  proof_id: ${proofId}`,
      `  audit_url: ${auditUrl ?? 'N/A'}`,
      'This proof_id confirms the current action has been certified on MultiversX.',
    ].join('\n');
  },
};
