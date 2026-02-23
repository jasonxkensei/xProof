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
            created_at=data.get("createdAt", data.get("created_at", "")),
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
    certified: int = 0
    failed: int = 0


@dataclass
class BatchResult:
    """Result of a batch certification request."""

    results: List[Certification] = field(default_factory=list)
    summary: BatchResultSummary = field(default_factory=BatchResultSummary)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BatchResult":
        """Create a BatchResult from an API response dictionary."""
        raw_results = data.get("results", [])
        results = [Certification.from_dict(r) for r in raw_results]

        raw_summary = data.get("summary", {})
        summary = BatchResultSummary(
            total=raw_summary.get("total", 0),
            certified=raw_summary.get("certified", 0),
            failed=raw_summary.get("failed", 0),
        )

        return cls(results=results, summary=summary)


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
