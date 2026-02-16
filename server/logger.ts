import crypto from "crypto";
import { type Request, type Response, type NextFunction } from "express";

type LogLevel = "info" | "warn" | "error" | "debug";

interface LogEntry {
  timestamp: string;
  level: LogLevel;
  service: string;
  requestId?: string;
  route?: string;
  method?: string;
  message: string;
  metadata?: Record<string, any>;
}

const SERVICE_NAME = "xproof-api";

function formatLog(entry: LogEntry): string {
  return JSON.stringify(entry);
}

function createLogEntry(level: LogLevel, message: string, metadata?: Record<string, any>, requestId?: string, route?: string, method?: string): LogEntry {
  return {
    timestamp: new Date().toISOString(),
    level,
    service: SERVICE_NAME,
    ...(requestId && { requestId }),
    ...(route && { route }),
    ...(method && { method }),
    message,
    ...(metadata && Object.keys(metadata).length > 0 && { metadata }),
  };
}

export const logger = {
  info(message: string, metadata?: Record<string, any>) {
    const entry = createLogEntry("info", message, metadata);
    process.stdout.write(formatLog(entry) + "\n");
  },
  warn(message: string, metadata?: Record<string, any>) {
    const entry = createLogEntry("warn", message, metadata);
    process.stdout.write(formatLog(entry) + "\n");
  },
  error(message: string, metadata?: Record<string, any>) {
    const entry = createLogEntry("error", message, metadata);
    process.stderr.write(formatLog(entry) + "\n");
  },
  debug(message: string, metadata?: Record<string, any>) {
    if (process.env.NODE_ENV === "development") {
      const entry = createLogEntry("debug", message, metadata);
      process.stdout.write(formatLog(entry) + "\n");
    }
  },
  withRequest(req: Request) {
    const requestId = (req.res?.locals?.requestId as string) || undefined;
    const route = req.path;
    const method = req.method;
    return {
      info(message: string, metadata?: Record<string, any>) {
        const entry = createLogEntry("info", message, metadata, requestId, route, method);
        process.stdout.write(formatLog(entry) + "\n");
      },
      warn(message: string, metadata?: Record<string, any>) {
        const entry = createLogEntry("warn", message, metadata, requestId, route, method);
        process.stdout.write(formatLog(entry) + "\n");
      },
      error(message: string, metadata?: Record<string, any>) {
        const entry = createLogEntry("error", message, metadata, requestId, route, method);
        process.stderr.write(formatLog(entry) + "\n");
      },
    };
  },
};

export function requestIdMiddleware(req: Request, res: Response, next: NextFunction) {
  const requestId = crypto.randomUUID().slice(0, 8);
  res.locals.requestId = requestId;
  res.setHeader("X-Request-Id", requestId);
  next();
}

export function getRequestId(res: Response): string | undefined {
  return res.locals?.requestId as string | undefined;
}
