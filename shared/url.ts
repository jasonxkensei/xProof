import { z } from "zod";

/**
 * Returns true only if `value` parses as an absolute URL using the http or
 * https scheme. Rejects `javascript:`, `data:`, `vbscript:`, `file:`, etc.
 *
 * Used as defense-in-depth at the API boundary AND when rendering arbitrary
 * user-controlled hrefs on public pages, so a stored unsafe scheme cannot
 * become a stored XSS vector when rendered into an anchor `href`.
 */
export function isSafeHttpUrl(value: unknown): value is string {
  if (typeof value !== "string" || value.length === 0) return false;
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return false;
  }
  return parsed.protocol === "http:" || parsed.protocol === "https:";
}

/**
 * Returns the URL string when safe, otherwise `null`. Use directly in JSX:
 *   `<a href={safeHref(maybeUrl) ?? "#"}>`
 */
export function safeHref(value: unknown): string | null {
  return isSafeHttpUrl(value) ? value : null;
}

/**
 * Zod schema accepting only absolute http/https URLs. Replaces uses of
 * `z.string().url()` for any field that will later be rendered into an
 * anchor `href` on a public page.
 */
export const safeHttpUrlSchema = z
  .string()
  .max(2048)
  .refine(isSafeHttpUrl, {
    message: "URL must use http or https scheme",
  });
