"""Exception classes for the xProof SDK."""


class XProofError(Exception):
    """Base exception for all xProof SDK errors."""

    def __init__(self, message: str, status_code: int = 0, response: object = None) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.response = response


class AuthenticationError(XProofError):
    """Raised when API key authentication fails (401/403)."""

    def __init__(self, message: str = "Invalid or missing API key", response: object = None) -> None:
        super().__init__(message, status_code=401, response=response)


class NotFoundError(XProofError):
    """Raised when a requested resource is not found (404)."""

    def __init__(self, message: str = "Resource not found", response: object = None) -> None:
        super().__init__(message, status_code=404, response=response)


class ValidationError(XProofError):
    """Raised when the request body fails server-side validation (400)."""

    def __init__(self, message: str = "Invalid request data", response: object = None) -> None:
        super().__init__(message, status_code=400, response=response)


class ConflictError(XProofError):
    """Raised when the file hash has already been certified (409)."""

    def __init__(self, message: str = "File already certified", certification_id: str = "", response: object = None) -> None:
        super().__init__(message, status_code=409, response=response)
        self.certification_id = certification_id


class RateLimitError(XProofError):
    """Raised when rate limits are exceeded (429)."""

    def __init__(self, message: str = "Rate limit exceeded", response: object = None) -> None:
        super().__init__(message, status_code=429, response=response)


class ServerError(XProofError):
    """Raised when the server returns a 5xx error."""

    def __init__(self, message: str = "Internal server error", status_code: int = 500, response: object = None) -> None:
        super().__init__(message, status_code=status_code, response=response)
