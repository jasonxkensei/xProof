import { createHash } from "crypto";
import { readFile } from "fs/promises";

export async function hashFile(path: string): Promise<string> {
  const data = await readFile(path);
  return createHash("sha256").update(data).digest("hex");
}

export function hashBuffer(data: Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

export function hashString(data: string): string {
  return createHash("sha256").update(data, "utf8").digest("hex");
}
