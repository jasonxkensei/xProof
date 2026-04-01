"""Main client for the xProof API."""

from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import requests

from .exceptions import (
    AuthenticationError,
    ConflictError,
    NotFoundError,
    RateLimitError,
    ServerError,
    ValidationError,
    XProofError,
)
from .models import BatchResult, Certification, PricingInfo, RegistrationResult
from .utils import hash_file

__version__ = "0.1.0"

DEFAULT_BASE_URL = "https://xproof.app"
DEFAULT_TIMEOUT = 30


class XProofClient:
    """Client for interacting with the xProof API.

    Args:
        api_key: Your xProof API key (starts with ``pm_``).
            Pass an empty string or omit if you plan to call
            :meth:`register` first.
        base_url: Override the API base URL (default: ``https://xproof.app``).
        timeout: Request timeout in seconds (default: 30).

    Example::

        from xproof import XProofClient

        client = XProofClient(api_key="pm_...")
        cert = client.certify("report.pdf", author="Alice")
        print(cert.transaction_url)
    """

    def __init__(
        self,
        api_key: str = "",
        base_url: str = DEFAULT_BASE_URL,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

        self._session = requests.Session()
        self._session.headers.update(
            {
                "Content-Type": "application/json",
                "User-Agent": f"xproof-python/{__version__}",
            }
        )
        if api_key:
            self._session.headers["Authorization"] = f"Bearer {api_key}"

    def _request(
        self,
        method: str,
        path: str,
        json: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        auth_required: bool = True,
    ) -> Dict[str, Any]:
        """Send an HTTP request to the xProof API and return parsed JSON."""
        url = f"{self.base_url}{path}"

        headers: Optional[Dict[str, str]] = None
        if not auth_required:
            headers = {"Authorization": ""}

        try:
            resp = self._session.request(
                method,
                url,
                json=json,
                params=params,
                timeout=self.timeout,
                headers=headers,
            )
        except requests.RequestException as exc:
            raise XProofError(f"Request failed: {exc}") from exc

        if resp.status_code in (200, 201):
            try:
                return resp.json()  # type: ignore[no-any-return]
            except ValueError as exc:
                raise XProofError(
                    f"Unexpected non-JSON response from {method} {url}: "
                    f"{resp.text[:200]}"
                ) from exc

        self._handle_error(resp)
        return {}

    @staticmethod
    def _handle_error(resp: requests.Response) -> None:
        """Raise an appropriate exception based on the HTTP response."""
        try:
            body = resp.json()
        except ValueError:
            body = {"message": resp.text}

        message = body.get("message", body.get("error", resp.text))
        status = resp.status_code

        if status == 400:
            raise ValidationError(message, response=body)
        if status in (401, 403):
            raise AuthenticationError(message, response=body)
        if status == 404:
            raise NotFoundError(message, response=body)
        if status == 409:
            raise ConflictError(
                message,
                certification_id=body.get("certificationId", ""),
                response=body,
            )
        if status == 429:
            raise RateLimitError(message, response=body)
        if status >= 500:
            raise ServerError(message, status_code=status, response=body)

        raise XProofError(message, status_code=status, response=body)

    @classmethod
    def register(
        cls,
        agent_name: str,
        base_url: str = DEFAULT_BASE_URL,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> "XProofClient":
        """Register a new agent and return a configured client.

        This is the zero-friction entry point: no wallet, no payment, no
        browser. The returned client is already authenticated with the
        trial API key and ready to certify.

        Args:
            agent_name: A human-readable name for the agent.
            base_url: Override the API base URL.
            timeout: Request timeout in seconds.

        Returns:
            A new :class:`XProofClient` already configured with the
            trial API key. Access registration details via
            ``client.registration``.

        Example::

            client = XProofClient.register("my-research-agent")
            print(client.registration.trial.remaining)  # 10
            cert = client.certify_hash(...)
        """
        temp = cls(api_key="", base_url=base_url, timeout=timeout)
        data = temp._request(
            "POST",
            "/api/agent/register",
            json={"agent_name": agent_name},
            auth_required=False,
        )
        result = RegistrationResult.from_dict(data)
        new_client = cls(api_key=result.api_key, base_url=base_url, timeout=timeout)
        new_client.registration = result
        return new_client

    registration: Optional[RegistrationResult] = None

    def certify(
        self,
        path: Union[str, Path],
        author: str,
        file_name: Optional[str] = None,
        *,
        who: Optional[str] = None,
        what: Optional[str] = None,
        when: Optional[str] = None,
        why: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Certification:
        """Certify a file by path. The file is hashed locally (SHA-256).

        Supports the xProof 4W framework via optional keyword arguments.

        Args:
            path: Path to the file to certify.
            author: Author / owner name for the certification.
            file_name: Override the file name recorded on-chain
                       (defaults to the basename of *path*).
            who: 4W — agent identity.
            what: 4W — action hash or description.
            when: 4W — ISO-8601 timestamp.
            why: 4W — instruction or reason.
            metadata: Arbitrary key-value metadata stored alongside the proof.

        Returns:
            A :class:`Certification` with the on-chain proof details.
        """
        if not self.api_key:
            raise ValueError("api_key is required — call register() or pass an api_key")

        p = Path(path)
        file_hash = hash_file(p)
        resolved_name = file_name or p.name

        return self.certify_hash(
            file_hash=file_hash,
            file_name=resolved_name,
            author=author,
            who=who,
            what=what,
            when=when,
            why=why,
            metadata=metadata,
        )

    def certify_hash(
        self,
        file_hash: str,
        file_name: str,
        author: str,
        *,
        who: Optional[str] = None,
        what: Optional[str] = None,
        when: Optional[str] = None,
        why: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Certification:
        """Certify a file using a pre-computed SHA-256 hash.

        Supports the xProof 4W framework via optional keyword arguments:

        - **who**: Agent identity (wallet, name, or ID)
        - **what**: Action hash or description being certified
        - **when**: ISO-8601 timestamp of the action
        - **why**: Instruction hash, goal, or reason for the action

        Any additional key-value pairs can be passed via *metadata*.

        Args:
            file_hash: 64-character lowercase hex SHA-256 digest.
            file_name: Original file name.
            author: Author / owner name.
            who: 4W — agent identity.
            what: 4W — action hash or description.
            when: 4W — ISO-8601 timestamp.
            why: 4W — instruction or reason.
            metadata: Arbitrary key-value metadata stored alongside the proof.

        Returns:
            A :class:`Certification` with the on-chain proof details.
        """
        if not self.api_key:
            raise ValueError("api_key is required — call register() or pass an api_key")

        proof_metadata: Dict[str, Any] = dict(metadata) if metadata else {}
        if who is not None:
            proof_metadata["who"] = who
        if what is not None:
            proof_metadata["what"] = what
        if when is not None:
            proof_metadata["when"] = when
        if why is not None:
            proof_metadata["why"] = why

        payload: Dict[str, Any] = {
            "filename": file_name,
            "file_hash": file_hash,
            "author_name": author,
        }
        if proof_metadata:
            payload["metadata"] = proof_metadata
        data = self._request("POST", "/api/proof", json=payload)
        return Certification.from_dict(data)

    VALID_THRESHOLD_STAGES = ("initial", "partial", "pre-commitment", "final")

    def certify_with_confidence(
        self,
        file_hash: str,
        file_name: str,
        author: str,
        confidence_level: float,
        threshold_stage: str,
        decision_id: str,
        *,
        who: Optional[str] = None,
        what: Optional[str] = None,
        when: Optional[str] = None,
        why: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Certification:
        """Certify a file hash with confidence-level anchoring.

        Creates a forensic trail by anchoring proofs at different confidence
        thresholds, linked by a shared ``decision_id``. An agent trading at
        60%, 80%, then final creates an immutable trail that distinguishes
        real reasoning from post-hoc reconstruction.

        Args:
            file_hash: 64-character lowercase hex SHA-256 digest.
            file_name: Original file name.
            author: Author / owner name.
            confidence_level: Confidence between 0.0 and 1.0.
            threshold_stage: One of ``initial``, ``partial``,
                ``pre-commitment``, ``final``.
            decision_id: Shared identifier linking all proofs in the
                same decision chain.
            who: 4W -- agent identity.
            what: 4W -- action hash or description.
            when: 4W -- ISO-8601 timestamp.
            why: 4W -- instruction or reason.
            metadata: Extra key-value metadata stored alongside the proof.

        Returns:
            A :class:`Certification` with the on-chain proof details.

        Raises:
            ValueError: If confidence_level or threshold_stage is invalid.
        """
        if not self.api_key:
            raise ValueError("api_key is required — call register() or pass an api_key")
        if not 0.0 <= confidence_level <= 1.0:
            raise ValueError("confidence_level must be between 0.0 and 1.0")
        if threshold_stage not in self.VALID_THRESHOLD_STAGES:
            raise ValueError(
                f"threshold_stage must be one of: {', '.join(self.VALID_THRESHOLD_STAGES)}"
            )
        if not decision_id or not decision_id.strip():
            raise ValueError("decision_id is required")

        proof_metadata: Dict[str, Any] = dict(metadata) if metadata else {}
        proof_metadata["confidence_level"] = confidence_level
        proof_metadata["threshold_stage"] = threshold_stage
        proof_metadata["decision_id"] = decision_id
        if who is not None:
            proof_metadata["who"] = who
        if what is not None:
            proof_metadata["what"] = what
        if when is not None:
            proof_metadata["when"] = when
        if why is not None:
            proof_metadata["why"] = why

        payload: Dict[str, Any] = {
            "filename": file_name,
            "file_hash": file_hash,
            "author_name": author,
            "metadata": proof_metadata,
        }
        data = self._request("POST", "/api/proof", json=payload)
        return Certification.from_dict(data)

    def get_confidence_trail(self, decision_id: str) -> Dict[str, Any]:
        """Retrieve the full confidence trail for a decision chain.

        Args:
            decision_id: The shared identifier linking proofs in the chain.

        Returns:
            A dictionary with ``decision_id``, ``total_anchors``,
            ``current_confidence``, ``current_stage``, ``is_finalized``,
            and ``stages`` (list of anchor details sorted by confidence).
        """
        from urllib.parse import quote
        data = self._request(
            "GET",
            f"/api/confidence-trail/{quote(decision_id, safe='')}",
            auth_required=False,
        )
        return data

    def batch_certify(
        self,
        files: List[Dict[str, Any]],
    ) -> BatchResult:
        """Certify multiple files in a single API call (up to 50).

        Each entry in *files* must contain:

        - ``path`` (str): Path to the file **or**
        - ``file_hash`` (str): Pre-computed SHA-256 hex hash
        - ``file_name`` (str): File name (required when using ``file_hash``)
        - ``author`` (str): Author name (applied to the entire batch)

        Args:
            files: List of file descriptors.

        Returns:
            A :class:`BatchResult` with individual results and a summary.

        Raises:
            ValueError: If more than 50 files are provided.
        """
        if not self.api_key:
            raise ValueError("api_key is required — call register() or pass an api_key")

        if len(files) > 50:
            raise ValueError("Batch certification supports a maximum of 50 files")

        entries: List[Dict[str, Any]] = []
        for f in files:
            if "path" in f:
                p = Path(f["path"])
                fhash = hash_file(p)
                fname = f.get("file_name", p.name)
            elif "file_hash" in f:
                fhash = f["file_hash"]
                fname = f.get("file_name", "unknown")
            else:
                raise ValueError("Each file entry must contain either 'path' or 'file_hash'")

            entry: Dict[str, Any] = {
                "filename": fname,
                "file_hash": fhash,
            }
            if f.get("metadata"):
                entry["metadata"] = f["metadata"]
            entries.append(entry)

        payload: Dict[str, Any] = {"files": entries}
        author = None
        for f in files:
            if f.get("author"):
                author = f["author"]
                break
        if author:
            payload["author_name"] = author

        data = self._request("POST", "/api/batch", json=payload)
        return BatchResult.from_dict(data)

    def verify(self, proof_id: str) -> Certification:
        """Retrieve a certification by its proof ID.

        This is a public endpoint and does not require authentication.

        Args:
            proof_id: The certification / proof UUID.

        Returns:
            A :class:`Certification` with the proof details.
        """
        data = self._request("GET", f"/api/proof/{proof_id}", auth_required=False)
        return Certification.from_dict(data)

    def verify_hash(self, file_hash: str) -> Certification:
        """Look up a certification by its SHA-256 file hash.

        This is a public endpoint and does not require authentication.

        Args:
            file_hash: The 64-character hex SHA-256 digest.

        Returns:
            A :class:`Certification` with the proof details.

        Raises:
            NotFoundError: If no certification exists for this hash.
        """
        data = self._request("GET", f"/api/proof/hash/{file_hash}", auth_required=False)
        return Certification.from_dict(data)

    def get_pricing(self) -> PricingInfo:
        """Retrieve current pricing information.

        This is a public endpoint and does not require authentication.

        Returns:
            A :class:`PricingInfo` with tier details and payment methods.
        """
        data = self._request("GET", "/api/pricing", auth_required=False)
        return PricingInfo.from_dict(data)
