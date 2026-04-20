import { describe, it, expect } from "vitest";
import {
  XProofError,
  AuthenticationError,
  ValidationError,
  NotFoundError,
  ConflictError,
  RateLimitError,
  ServerError,
} from "../src/errors.js";

describe("XProofError", () => {
  it("sets message, statusCode, and response", () => {
    const err = new XProofError("something went wrong", 503, { detail: "oops" });
    expect(err.message).toBe("something went wrong");
    expect(err.statusCode).toBe(503);
    expect(err.response).toEqual({ detail: "oops" });
    expect(err.name).toBe("XProofError");
  });

  it("defaults statusCode to 0 and response to null", () => {
    const err = new XProofError("bare error");
    expect(err.statusCode).toBe(0);
    expect(err.response).toBeNull();
  });

  it("is an instance of Error", () => {
    expect(new XProofError("x")).toBeInstanceOf(Error);
  });
});

describe("AuthenticationError", () => {
  it("has statusCode 401 and name AuthenticationError", () => {
    const err = new AuthenticationError();
    expect(err.statusCode).toBe(401);
    expect(err.name).toBe("AuthenticationError");
    expect(err).toBeInstanceOf(XProofError);
  });

  it("accepts a custom message", () => {
    const err = new AuthenticationError("bad token");
    expect(err.message).toBe("bad token");
  });
});

describe("ValidationError", () => {
  it("has statusCode 400 and name ValidationError", () => {
    const err = new ValidationError();
    expect(err.statusCode).toBe(400);
    expect(err.name).toBe("ValidationError");
  });
});

describe("NotFoundError", () => {
  it("has statusCode 404", () => {
    expect(new NotFoundError().statusCode).toBe(404);
    expect(new NotFoundError().name).toBe("NotFoundError");
  });
});

describe("ConflictError", () => {
  it("has statusCode 409 and stores certificationId", () => {
    const err = new ConflictError("already certified", "cert-abc");
    expect(err.statusCode).toBe(409);
    expect(err.certificationId).toBe("cert-abc");
    expect(err.name).toBe("ConflictError");
  });

  it("defaults certificationId to empty string", () => {
    expect(new ConflictError().certificationId).toBe("");
  });
});

describe("RateLimitError", () => {
  it("has statusCode 429", () => {
    const err = new RateLimitError();
    expect(err.statusCode).toBe(429);
    expect(err.name).toBe("RateLimitError");
  });
});

describe("ServerError", () => {
  it("has statusCode 500 by default", () => {
    const err = new ServerError();
    expect(err.statusCode).toBe(500);
    expect(err.name).toBe("ServerError");
  });

  it("accepts a custom statusCode (e.g. 502)", () => {
    const err = new ServerError("bad gateway", 502);
    expect(err.statusCode).toBe(502);
  });
});
