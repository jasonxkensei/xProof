export class XProofError extends Error {
  statusCode: number;
  response: Record<string, unknown> | null;

  constructor(
    message: string,
    statusCode = 0,
    response: Record<string, unknown> | null = null
  ) {
    super(message);
    this.name = "XProofError";
    this.statusCode = statusCode;
    this.response = response;
  }
}

export class AuthenticationError extends XProofError {
  constructor(
    message = "Invalid or missing API key",
    response: Record<string, unknown> | null = null
  ) {
    super(message, 401, response);
    this.name = "AuthenticationError";
  }
}

export class ValidationError extends XProofError {
  constructor(
    message = "Invalid request data",
    response: Record<string, unknown> | null = null
  ) {
    super(message, 400, response);
    this.name = "ValidationError";
  }
}

export class NotFoundError extends XProofError {
  constructor(
    message = "Resource not found",
    response: Record<string, unknown> | null = null
  ) {
    super(message, 404, response);
    this.name = "NotFoundError";
  }
}

export class ConflictError extends XProofError {
  certificationId: string;

  constructor(
    message = "File already certified",
    certificationId = "",
    response: Record<string, unknown> | null = null
  ) {
    super(message, 409, response);
    this.name = "ConflictError";
    this.certificationId = certificationId;
  }
}

export class RateLimitError extends XProofError {
  constructor(
    message = "Rate limit exceeded",
    response: Record<string, unknown> | null = null
  ) {
    super(message, 429, response);
    this.name = "RateLimitError";
  }
}

export class ServerError extends XProofError {
  constructor(
    message = "Internal server error",
    statusCode = 500,
    response: Record<string, unknown> | null = null
  ) {
    super(message, statusCode, response);
    this.name = "ServerError";
  }
}
