"""xProof Python SDK — blockchain proof-of-existence on MultiversX."""

from .client import XProofClient
from .exceptions import (
    AuthenticationError,
    ConflictError,
    NotFoundError,
    PolicyViolationError,
    RateLimitError,
    ServerError,
    ValidationError,
    XProofError,
)
from .models import (
    BatchFileEntry,
    BatchResult,
    BatchResultSummary,
    CertifyEntry,
    Certification,
    ConfidenceTrail,
    ConfidenceTrailStage,
    PathCertifyEntry,
    PolicyCheckResult,
    PolicyViolation,
    PricingInfo,
    PricingTier,
    RegistrationResult,
    ReversibilityClass,
    TrialInfo,
)
from .utils import hash_bytes, hash_file

__version__ = "0.2.6"

__all__ = [
    "XProofClient",
    "hash_file",
    "hash_bytes",
    "BatchFileEntry",
    "CertifyEntry",
    "PathCertifyEntry",
    "Certification",
    "BatchResult",
    "BatchResultSummary",
    "ConfidenceTrail",
    "ConfidenceTrailStage",
    "PolicyCheckResult",
    "PolicyViolation",
    "ReversibilityClass",
    "PricingInfo",
    "PricingTier",
    "RegistrationResult",
    "TrialInfo",
    "XProofError",
    "AuthenticationError",
    "ConflictError",
    "NotFoundError",
    "PolicyViolationError",
    "RateLimitError",
    "ServerError",
    "ValidationError",
]
