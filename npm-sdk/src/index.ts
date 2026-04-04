export { XProofClient } from "./client.js";
export {
  XProofError,
  AuthenticationError,
  ValidationError,
  NotFoundError,
  ConflictError,
  RateLimitError,
  ServerError,
} from "./errors.js";
export type {
  Certification,
  BatchResult,
  BatchResultSummary,
  PricingInfo,
  PricingTier,
  RegistrationResult,
  TrialInfo,
  FourWOptions,
  CertifyHashOptions,
  BatchFileEntry,
  XProofClientOptions,
  ThresholdStage,
  ConfidenceOptions,
  ConfidenceTrail,
  ConfidenceTrailStage,
  ExecutionContext,
  ContextDriftStage,
  ContextDrift,
} from "./types.js";
export { hashFile, hashBuffer, hashString } from "./hash.js";
