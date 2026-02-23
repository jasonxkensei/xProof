"""Main client for the xProof API."""

import mimetypes
import os
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
from .models import BatchResult, Certification, PricingInfo
from .utils import hash_file

DEFAULT_BASE_URL = "https://xproof.app"
DEFAULT_TIMEOUT = 30


class XProofClient:
    """Client for interacting with the xProof API.

    Args:
        api_key: Your xProof API key (starts with ``pm_``).
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
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        if not api_key:
            raise ValueError("api_key is required")

        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

        self._session = requests.Session()
        self._session.headers.update(
            {
                "X-API-Key": self.api_key,
                "Content-Type": "application/json",
                "User-Agent": "xproof-python/0.1.0",
            }
        )

    def _request(
        self,
        method: str,
        path: str,
        json: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        auth_required: bool = True,
    ) -> Dict[str, Any]:
        """Send an HTTP request to the xProof API and return parsed JSON.

        Args:
            method: HTTP method (GET, POST, etc.).
            path: API path (e.g. ``/api/proof``).
            json: JSON request body.
            params: Query parameters.
            auth_required: Whether to include the API key header.

        Returns:
            Parsed JSON response as a dictionary.

        Raises:
            XProofError: On any API error.
        """
        url = f"{self.base_url}{path}"

        headers: Dict[str, str] = {}
        if not auth_required:
            headers["X-API-Key"] = ""

        try:
            resp = self._session.request(
                method,
                url,
                json=json,
                params=params,
                timeout=self.timeout,
                headers=headers if not auth_required else None,
            )
        except requests.RequestException as exc:
            raise XProofError(f"Request failed: {exc}") from exc

        if resp.status_code == 200 or resp.status_code == 201:
            return resp.json()  # type: ignore[no-any-return]

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

    def certify(
        self,
        path: Union[str, Path],
        author: str,
        file_name: Optional[str] = None,
    ) -> Certification:
        """Certify a file by path. The file is hashed locally (SHA-256).

        Args:
            path: Path to the file to certify.
            author: Author / owner name for the certification.
            file_name: Override the file name recorded on-chain
                       (defaults to the basename of *path*).

        Returns:
            A :class:`Certification` with the on-chain proof details.
        """
        p = Path(path)
        file_hash = hash_file(p)
        resolved_name = file_name or p.name
        file_type = mimetypes.guess_type(str(p))[0] or "application/octet-stream"
        file_size = p.stat().st_size

        return self.certify_hash(
            file_hash=file_hash,
            file_name=resolved_name,
            author=author,
            file_type=file_type,
            file_size=file_size,
        )

    def certify_hash(
        self,
        file_hash: str,
        file_name: str,
        author: str,
        file_type: str = "application/octet-stream",
        file_size: int = 0,
    ) -> Certification:
        """Certify a file using a pre-computed SHA-256 hash.

        Args:
            file_hash: 64-character lowercase hex SHA-256 digest.
            file_name: Original file name.
            author: Author / owner name.
            file_type: MIME type (default ``application/octet-stream``).
            file_size: File size in bytes.

        Returns:
            A :class:`Certification` with the on-chain proof details.
        """
        payload = {
            "fileName": file_name,
            "fileHash": file_hash,
            "fileType": file_type,
            "fileSize": file_size,
            "authorName": author,
        }
        data = self._request("POST", "/api/proof", json=payload)
        return Certification.from_dict(data)

    def batch_certify(
        self,
        files: List[Dict[str, Any]],
    ) -> BatchResult:
        """Certify multiple files in a single API call (up to 50).

        Each entry in *files* must contain:

        - ``path`` (str): Path to the file **or**
        - ``file_hash`` (str): Pre-computed SHA-256 hex hash
        - ``file_name`` (str): File name (required when using ``file_hash``)
        - ``author`` (str): Author name

        Optional keys: ``file_type``, ``file_size``.

        Args:
            files: List of file descriptors.

        Returns:
            A :class:`BatchResult` with individual results and a summary.

        Raises:
            ValueError: If more than 50 files are provided.
        """
        if len(files) > 50:
            raise ValueError("Batch certification supports a maximum of 50 files")

        entries: List[Dict[str, Any]] = []
        for f in files:
            if "path" in f:
                p = Path(f["path"])
                fhash = hash_file(p)
                fname = f.get("file_name", p.name)
                ftype = f.get("file_type", mimetypes.guess_type(str(p))[0] or "application/octet-stream")
                fsize = f.get("file_size", p.stat().st_size)
            elif "file_hash" in f:
                fhash = f["file_hash"]
                fname = f.get("file_name", "unknown")
                ftype = f.get("file_type", "application/octet-stream")
                fsize = f.get("file_size", 0)
            else:
                raise ValueError("Each file entry must contain either 'path' or 'file_hash'")

            entries.append(
                {
                    "fileName": fname,
                    "fileHash": fhash,
                    "fileType": ftype,
                    "fileSize": fsize,
                    "authorName": f.get("author", ""),
                }
            )

        data = self._request("POST", "/api/batch", json={"files": entries})
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
        data = self._request("GET", f"/api/verify/{file_hash}", auth_required=False)
        return Certification.from_dict(data)

    def get_pricing(self) -> PricingInfo:
        """Retrieve current pricing information.

        This is a public endpoint and does not require authentication.

        Returns:
            A :class:`PricingInfo` with tier details and payment methods.
        """
        data = self._request("GET", "/api/pricing", auth_required=False)
        return PricingInfo.from_dict(data)
