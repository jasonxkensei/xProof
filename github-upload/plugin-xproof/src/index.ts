import type { Plugin } from '@elizaos/core';

export type {
  XProofConfig,
  XProofApiResponse,
  XProofBatchResponse,
  AuditLogPayload,
  AuditResult,
} from './types';
export { AuditRequiredError, getConfig } from './types';

export { sha256, callXProof, getProof, callAudit, formatProofResponse } from './client';

export { auditBeforeExecuteAction } from './actions/audit';
export { certifyContentAction, certifyHashAction, certifyBatchAction } from './actions/certify';
export { verifyProofAction } from './actions/verify';

export { auditStateProvider } from './providers/audit-state';

import { auditBeforeExecuteAction } from './actions/audit';
import { certifyContentAction, certifyHashAction, certifyBatchAction } from './actions/certify';
import { verifyProofAction } from './actions/verify';
import { auditStateProvider } from './providers/audit-state';

export const xproofPlugin: Plugin = {
  name: 'xproof',
  description:
    'Compliance layer for autonomous agents on MultiversX. ' +
    'Audit guard blocks critical actions without on-chain proof. ' +
    'Certify content, file hashes, and batch (up to 50). Verify certificates. ' +
    '6-second finality. Schema: https://xproof.app/.well-known/agent-audit-schema.json',
  actions: [
    auditBeforeExecuteAction,
    certifyContentAction,
    certifyHashAction,
    certifyBatchAction,
    verifyProofAction,
  ],
  providers: [auditStateProvider],
};

export default xproofPlugin;
