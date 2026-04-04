export interface Certification {
  id: string;
  fileName: string;
  fileHash: string;
  transactionHash: string;
  transactionUrl: string;
  createdAt: string;
  authorName: string;
  blockchainStatus: string;
  isPublic: boolean;
  certificateUrl: string;
  verifyUrl: string;
}

export interface BatchResultSummary {
  total: number;
  created: number;
  existing: number;
  certified: number;
  failed: number;
}

export interface BatchResult {
  batchId: string;
  results: Certification[];
  summary: BatchResultSummary;
}

export interface PricingTier {
  minCertifications: number;
  maxCertifications: number | null;
  priceUsd: number;
}

export interface PricingInfo {
  protocol: string;
  version: string;
  priceUsd: number;
  tiers: PricingTier[];
  paymentMethods: Array<Record<string, string>>;
  raw: Record<string, unknown>;
}

export interface TrialInfo {
  quota: number;
  used: number;
  remaining: number;
}

export interface RegistrationResult {
  apiKey: string;
  agentName: string;
  trial: TrialInfo;
  endpoints: Record<string, string>;
  raw: Record<string, unknown>;
}

export interface FourWOptions {
  who?: string;
  what?: string;
  when?: string;
  why?: string;
  metadata?: Record<string, unknown>;
}

export interface CertifyHashOptions extends FourWOptions {
  fileHash: string;
  fileName: string;
  author: string;
}

export type ThresholdStage = "initial" | "partial" | "pre-commitment" | "final";

export interface ConfidenceOptions {
  confidenceLevel: number;
  thresholdStage: ThresholdStage;
  decisionId: string;
}

export interface ConfidenceTrailStage {
  proofId: string;
  fileName: string;
  fileHash: string;
  confidenceLevel: number | null;
  thresholdStage: string | null;
  author: string;
  blockchain: {
    transactionHash: string;
    explorerUrl: string;
    status: string;
  };
  anchoredAt: string;
  metadata: Record<string, unknown>;
}

export interface ConfidenceTrailDrift {
  contextCoherent: boolean;
  driftScore: number;
  fieldsMonitored: string[];
  fieldsDrifted: string[];
  fieldsStable: string[];
  fieldsAbsent: string[];
}

export interface ConfidenceTrail {
  decisionId: string;
  totalAnchors: number;
  currentConfidence: number | null;
  currentStage: string | null;
  isFinalized: boolean;
  contextDrift: ConfidenceTrailDrift | null;
  stages: ConfidenceTrailStage[];
}

export interface BatchFileEntry {
  fileHash: string;
  fileName?: string;
  author?: string;
  metadata?: Record<string, unknown>;
}

export interface XProofClientOptions {
  apiKey?: string;
  baseUrl?: string;
  timeout?: number;
}

export interface ExecutionContext {
  model_hash: string | null;
  tools_version: string | null;
  strategy_snapshot: string | null;
  operator_scope: string | null;
  [key: string]: string | null;
}

export interface ContextDriftStage {
  proofId: string;
  stageIndex: number;
  anchoredAt: string;
  executionContext: ExecutionContext;
  contextBreak: boolean;
  driftedFields: string[];
}

export interface ContextDrift {
  decisionId: string;
  contextCoherent: boolean;
  driftScore: number;
  fieldsMonitored: string[];
  fieldsDrifted: string[];
  fieldsStable: string[];
  fieldsAbsent: string[];
  totalAnchors: number;
  stages: ContextDriftStage[];
}
