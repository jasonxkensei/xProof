import type {
  Certification,
  BatchResult,
  BatchResultSummary,
  PricingInfo,
  PricingTier,
  RegistrationResult,
  TimingBreakdown,
  JurisdictionType,
  TrialInfo,
} from "./types.js";

function parseTimingBreakdown(
  raw: Record<string, unknown>
): TimingBreakdown | undefined {
  const tb: TimingBreakdown = {};
  let hasAnyField = false;

  if (raw.instruction_received_at != null) {
    tb.instructionReceivedAt = raw.instruction_received_at as string;
    hasAnyField = true;
  }
  if (raw.reasoning_started_at != null) {
    tb.reasoningStartedAt = raw.reasoning_started_at as string;
    hasAnyField = true;
  }
  if (raw.action_taken_at != null) {
    tb.actionTakenAt = raw.action_taken_at as string;
    hasAnyField = true;
  }
  if (raw.jurisdiction_type != null) {
    tb.jurisdictionType = raw.jurisdiction_type as JurisdictionType;
    hasAnyField = true;
  }
  if (raw.reasoning_duration_ms != null) {
    tb.reasoningDurationMs = raw.reasoning_duration_ms as number;
    hasAnyField = true;
  }
  if (raw.total_duration_ms != null) {
    tb.totalDurationMs = raw.total_duration_ms as number;
    hasAnyField = true;
  }

  return hasAnyField ? tb : undefined;
}

export function parseCertification(data: Record<string, unknown>): Certification {
  const blockchain = (data.blockchain as Record<string, unknown>) || {};

  const _meta = data.metadata as Record<string, unknown> | undefined;
  const _TIMING_KEYS = [
    "instruction_received_at",
    "reasoning_started_at",
    "action_taken_at",
    "jurisdiction_type",
    "reasoning_duration_ms",
    "total_duration_ms",
  ] as const;
  const rawTiming =
    (data.timing_breakdown as Record<string, unknown> | undefined) ??
    (_meta?.timing_breakdown as Record<string, unknown> | undefined) ??
    (_meta && _TIMING_KEYS.some((k) => _meta[k] != null) ? _meta : undefined);

  return {
    id: (data.id as string) || (data.proof_id as string) || "",
    fileName:
      (data.fileName as string) ||
      (data.filename as string) ||
      (data.file_name as string) ||
      "",
    fileHash:
      (data.fileHash as string) || (data.file_hash as string) || "",
    transactionHash:
      (data.transactionHash as string) ||
      (blockchain.transaction_hash as string) ||
      "",
    transactionUrl:
      (data.transactionUrl as string) ||
      (blockchain.explorer_url as string) ||
      "",
    createdAt:
      (data.createdAt as string) ||
      (data.created_at as string) ||
      (data.timestamp as string) ||
      "",
    authorName:
      (data.authorName as string) || (data.author_name as string) || "",
    blockchainStatus:
      (data.blockchainStatus as string) || (data.status as string) || "",
    isPublic: data.isPublic !== undefined ? !!data.isPublic : (data.is_public !== undefined ? !!data.is_public : true),
    certificateUrl:
      (data.certificateUrl as string) ||
      (data.certificate_url as string) ||
      "",
    verifyUrl:
      (data.verifyUrl as string) || (data.verify_url as string) || "",
    timingBreakdown: rawTiming ? parseTimingBreakdown(rawTiming) : undefined,
  };
}

export function parseBatchResult(data: Record<string, unknown>): BatchResult {
  const rawResults = (data.results as Array<Record<string, unknown>>) || [];
  const results = rawResults.map(parseCertification);
  const total = (data.total as number) ?? rawResults.length;
  const created = (data.created as number) ?? 0;
  const existing = (data.existing as number) ?? 0;

  const summary: BatchResultSummary = {
    total,
    created,
    existing,
    get certified() { return created; },
    get failed() { return total - created - existing; },
  };

  return {
    batchId: (data.batch_id as string) || "",
    results,
    summary,
  };
}

export function parsePricingInfo(data: Record<string, unknown>): PricingInfo {
  const rawTiers = (data.tiers as Array<Record<string, unknown>>) || [];
  const tiers: PricingTier[] = rawTiers.map((t) => ({
    minCertifications:
      (t.min_certifications as number) ?? (t.min as number) ?? 0,
    maxCertifications:
      (t.max_certifications as number) ?? (t.max as number) ?? null,
    priceUsd: (t.price_usd as number) ?? (t.price as number) ?? 0,
  }));

  return {
    protocol: (data.protocol as string) || "",
    version: (data.version as string) || "",
    priceUsd:
      (data.price_usd as number) ?? (data.current_price as number) ?? 0,
    tiers,
    paymentMethods:
      (data.payment_methods as Array<Record<string, string>>) || [],
    raw: data,
  };
}

export function parseRegistrationResult(
  data: Record<string, unknown>
): RegistrationResult {
  const trialData = (data.trial as Record<string, unknown>) || {};
  const trial: TrialInfo = {
    quota: (trialData.quota as number) ?? 0,
    used: (trialData.used as number) ?? 0,
    remaining: (trialData.remaining as number) ?? 0,
  };
  return {
    apiKey: (data.api_key as string) || "",
    agentName: (data.agent_name as string) || "",
    trial,
    endpoints: (data.endpoints as Record<string, string>) || {},
    raw: data,
  };
}
