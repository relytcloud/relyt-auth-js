import { RelytAuthError } from "./errors.js";

/** Plain http is only accepted for exact loopback host names (local development); everything else must be https. */
const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

function checkOrigin(u: URL, option: string): void {
  if (u.protocol === "https:") return;
  if (u.protocol === "http:" && LOOPBACK.has(u.hostname)) return;
  throw new RelytAuthError("config", { option });
}

function parse(s: unknown, option: string): URL {
  if (typeof s !== "string" || s === "") throw new RelytAuthError("config", { option });
  try {
    return new URL(s);
  } catch {
    throw new RelytAuthError("config", { option });
  }
}

/**
 * The issuer must be exactly one origin (`new URL(s).origin === s`): no trailing slash, no path, and nothing that URL
 * normalization would rewrite (case, default port), because the token's `iss` is compared to it verbatim.
 */
export function normalizeIssuer(s: unknown): string {
  const u = parse(s, "issuer");
  if (u.origin !== s) throw new RelytAuthError("config", { option: "issuer" });
  checkOrigin(u, "issuer");
  return u.origin;
}

/** jwksUrl may have any path, but its origin follows the same rule as the issuer. Returns the normalized href (used as cache key). */
export function normalizeJwksUrl(s: unknown): string {
  const u = parse(s, "jwksUrl");
  checkOrigin(u, "jwksUrl");
  return u.href;
}
