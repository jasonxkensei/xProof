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
from .models import BatchResult, BatchResultSummary, Certification, PricingInfo, PricingTier
from .utils import hash_file

__version__ = "0.1.0"

__all__ = [
    "XProofClient",
    "hash_file",
    "Certification",
    "BatchResult",
    "BatchResultSummary",
    "PricingInfo",
    "PricingTier",
    "XProofError",
    "AuthenticationError",
    "ConflictError",
    "NotFoundError",
    "RateLimitError",
    "ServerError",
    "ValidationError",
]
