import type { Action, IAgentRuntime, Memory, State, HandlerCallback } from '@elizaos/core';
import { randomUUID } from 'crypto';
import type { AuditLogPayload } from '../types';
import { getConfig, AuditRequiredError } from '../types';
import { callAudit, sha256 } from '../client';

export const auditBeforeExecuteAction: Action = {
  name: 'AUDIT_BEFORE_EXECUTE',
  similes: [
    'CERTIFY_ACTION',
    'XPROOF_AUDIT',
    'COMPLIANCE_GATE',
    'AUDIT_DECISION',
    'LOG_DECISION',
    'SECURE_EXECUTION',
  ],
  description:
    'Certify an agent decision on the MultiversX blockchain BEFORE executing a critical action. ' +
    'If certification fails, throws AuditRequiredError and the action is blocked. ' +
    'The proof_id is stored in agent state for downstream actions. ' +
    'Schema: https://xproof.app/.well-known/agent-audit-schema.json',
  validate: async (runtime: IAgentRuntime) => {
    const { apiKey } = getConfig(runtime);
    return !!apiKey;
  },
  handler: async (
    runtime: IAgentRuntime,
    message: Memory,
    state: State | undefined,
    options: Record<string, unknown>,
    callback?: HandlerCallback
  ) => {
    const config = getConfig(runtime);
    const agentId =
      (options?.agent_id as string) ??
      runtime.agentId ??
      'eliza-agent';

    const actionType =
      (options?.action_type as string) ?? 'other';
    const actionDescription =
      (options?.action_description as string) ??
      message.content?.text ??
      'Agent action';
    const riskLevel =
      (options?.risk_level as AuditLogPayload['risk_level']) ?? 'medium';
    const decision =
      (options?.decision as AuditLogPayload['decision']) ?? 'approved';
    const riskSummary = options?.risk_summary as string | undefined;
    const context = options?.context as Record<string, unknown> | undefined;

    const inputsHash =
      (options?.inputs_hash as string) ??
      sha256(JSON.stringify({ text: message.content?.text, options }));

    const payload: AuditLogPayload = {
      agent_id: agentId,
      session_id: (options?.session_id as string) ?? randomUUID(),
      action_type: actionType,
      action_description: actionDescription,
      inputs_hash: inputsHash,
      risk_level: riskLevel,
      decision,
      timestamp: new Date().toISOString(),
    };
    if (riskSummary) payload.risk_summary = riskSummary;
    if (context) payload.context = context;

    try {
      const result = await callAudit(config, payload);

      if (!result.proof_id) {
        throw new AuditRequiredError(
          'EXECUTION BLOCKED: xProof returned no proof_id.'
        );
      }

      if (state) {
        (state as Record<string, unknown>).xproofProofId = result.proof_id;
        (state as Record<string, unknown>).xproofAuditUrl = result.audit_url;
      }

      const lines = [
        'Audit certified on MultiversX blockchain.',
        '',
        `Proof ID: ${result.proof_id}`,
        `Decision: ${decision}`,
        `Risk: ${riskLevel}`,
        `Action: ${actionType}`,
        `Audit URL: ${result.audit_url}`,
      ];
      if (result.blockchain?.explorer_url) {
        lines.push(`Explorer: ${result.blockchain.explorer_url}`);
      }

      callback?.({ text: lines.join('\n'), data: result });
      return true;
    } catch (err) {
      if (err instanceof AuditRequiredError) {
        callback?.({
          text: `EXECUTION BLOCKED: ${err.message}`,
          error: true,
        });
        throw err;
      }

      const msg = err instanceof Error ? err.message : String(err);
      const blockError = new AuditRequiredError(
        `EXECUTION BLOCKED: Audit certification failed. ${msg}`
      );
      callback?.({
        text: blockError.message,
        error: true,
      });
      throw blockError;
    }
  },
  examples: [
    [
      {
        user: '{{user1}}',
        content: { text: 'Execute trade: Buy 10 EGLD at market price' },
      },
      {
        user: '{{agent}}',
        content: {
          text: 'Audit certified on MultiversX blockchain.\n\nProof ID: audit_abc123\nDecision: approved\nRisk: medium\nAction: trade_execution\nAudit URL: https://xproof.app/audit/audit_abc123',
          action: 'AUDIT_BEFORE_EXECUTE',
        },
      },
    ],
    [
      {
        user: '{{user1}}',
        content: { text: 'Deploy smart contract to mainnet' },
      },
      {
        user: '{{agent}}',
        content: {
          text: 'Audit certified on MultiversX blockchain.\n\nProof ID: audit_def789\nDecision: approved\nRisk: high\nAction: code_deploy\nAudit URL: https://xproof.app/audit/audit_def789',
          action: 'AUDIT_BEFORE_EXECUTE',
        },
      },
    ],
  ],
};
