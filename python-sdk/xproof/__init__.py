"""xProof Python SDK — blockchain proof-of-existence on MultiversX."""

from .client import XProofClient
from .exceptions import (
    AuthenticationError,
    ConflictError,
    NotFoundError,
    RateLimitError,
    ServerError,
    ValidationError,
    XProofError,
)
from .models import (
    BatchResult,
    BatchResultSummary,
    Certification,
    ConfidenceTrail,
    ConfidenceTrailStage,
    PolicyViolation,
    PricingInfo,
    PricingTier,
    RegistrationResult,
    ReversibilityClass,
    TrialInfo,
)
from .utils import hash_bytes, hash_file

__version__ = "0.2.5"

__all__ = [
    "XProofClient",
    "hash_file",
    "hash_bytes",
    "Certification",
    "BatchResult",
    "BatchResultSummary",
    "ConfidenceTrail",
    "ConfidenceTrailStage",
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
    "RateLimitError",
    "ServerError",
    "ValidationError",
]
