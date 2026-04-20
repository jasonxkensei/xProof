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
  ReversibilityClass,
  ConfidenceOptions,
  ConfidenceTrail,
  ConfidenceTrailStage,
  ConfidenceTrailDrift,
  PolicyViolation,
  ExecutionContext,
  ContextDriftStage,
  ContextDrift,
} from "./types.js";
export { hashFile, hashBuffer, hashString } from "./hash.js";
