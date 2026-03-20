"""Data models for the xProof SDK."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Certification:
    """Represents a blockchain-anchored certification."""

    id: str
    file_name: str
    file_hash: str
    transaction_hash: str
    transaction_url: str
    created_at: str
    author_name: str = ""
    file_type: str = ""
    file_size: int = 0
    blockchain_status: str = ""
    is_public: bool = True
    certificate_url: str = ""
    verify_url: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Certification":
        """Create a Certification from an API response dictionary."""
        blockchain = data.get("blockchain", {})
        return cls(
            id=data.get("id", data.get("proof_id", "")),
            file_name=data.get("fileName", data.get("filename", data.get("file_name", ""))),
            file_hash=data.get("fileHash", data.get("file_hash", "")),
            transaction_hash=(
                data.get("transactionHash", "")
                or blockchain.get("transaction_hash", "")
            ),
            transaction_url=(
                data.get("transactionUrl", "")
                or blockchain.get("explorer_url", "")
            ),
            created_at=data.get("createdAt", data.get("created_at", data.get("timestamp", ""))),
            author_name=data.get("authorName", data.get("author_name", "")),
            file_type=data.get("fileType", data.get("file_type", "")),
            file_size=data.get("fileSize", data.get("file_size", 0)),
            blockchain_status=data.get("blockchainStatus", data.get("status", "")),
            is_public=data.get("isPublic", data.get("is_public", True)),
            certificate_url=data.get("certificateUrl", data.get("certificate_url", "")),
            verify_url=data.get("verifyUrl", data.get("verify_url", "")),
        )


@dataclass
class BatchResultSummary:
    """Summary of a batch certification request."""

    total: int = 0
    created: int = 0
    existing: int = 0

    @property
    def certified(self) -> int:
        return self.created

    @property
    def failed(self) -> int:
        return self.total - self.created - self.existing


@dataclass
class BatchResult:
    """Result of a batch certification request."""

    batch_id: str = ""
    results: List[Certification] = field(default_factory=list)
    summary: BatchResultSummary = field(default_factory=BatchResultSummary)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BatchResult":
        """Create a BatchResult from an API response dictionary."""
        raw_results = data.get("results", [])
        results = [Certification.from_dict(r) for r in raw_results]

        summary = BatchResultSummary(
            total=data.get("total", len(raw_results)),
            created=data.get("created", 0),
            existing=data.get("existing", 0),
        )

        return cls(
            batch_id=data.get("batch_id", ""),
            results=results,
            summary=summary,
        )


@dataclass
class PricingTier:
    """A single pricing tier."""

    min_certifications: int = 0
    max_certifications: Optional[int] = None
    price_usd: float = 0.0


@dataclass
class PricingInfo:
    """Current pricing information from the xProof API."""

    protocol: str = ""
    version: str = ""
    price_usd: float = 0.0
    tiers: List[PricingTier] = field(default_factory=list)
    payment_methods: List[Dict[str, str]] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PricingInfo":
        """Create a PricingInfo from an API response dictionary."""
        tiers: List[PricingTier] = []
        for t in data.get("tiers", []):
            tiers.append(
                PricingTier(
                    min_certifications=t.get("min_certifications", t.get("min", 0)),
                    max_certifications=t.get("max_certifications", t.get("max")),
                    price_usd=t.get("price_usd", t.get("price", 0.0)),
                )
            )

        return cls(
            protocol=data.get("protocol", ""),
            version=data.get("version", ""),
            price_usd=data.get("price_usd", data.get("current_price", 0.0)),
            tiers=tiers,
            payment_methods=data.get("payment_methods", []),
            raw=data,
        )


@dataclass
class TrialInfo:
    """Trial quota information returned by agent registration."""

    quota: int = 0
    used: int = 0
    remaining: int = 0


@dataclass
class RegistrationResult:
    """Result of agent self-service registration."""

    api_key: str
    agent_name: str
    trial: TrialInfo = field(default_factory=TrialInfo)
    endpoints: Dict[str, str] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RegistrationResult":
        """Create a RegistrationResult from an API response dictionary."""
        trial_data = data.get("trial", {})
        trial = TrialInfo(
            quota=trial_data.get("quota", 0),
            used=trial_data.get("used", 0),
            remaining=trial_data.get("remaining", 0),
        )
        return cls(
            api_key=data.get("api_key", ""),
            agent_name=data.get("agent_name", ""),
            trial=trial,
            endpoints=data.get("endpoints", {}),
            raw=data,
        )
