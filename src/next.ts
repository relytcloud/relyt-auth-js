// @relyt/auth/next: Next.js middleware entry. Web APIs + next/server only, usable in the edge runtime.
// Security notes:
// - The issuer comes only from configuration (options.issuer), never from the request's Host / X-Forwarded-Host; token iss/aud are compared to it verbatim.
// - Incoming x-relyt-* headers are always stripped, on success or failure; the middleware never forwards claim headers, route handlers re-verify with getClaims.
// - Tokens and cookie values never reach logs, responses or events.
import { NextResponse, type NextRequest } from "next/server.js";
import { TOKEN_TTL_S } from "./constants.js";
import { RelytAuthError } from "./errors.js";
import { normalizeIssuer } from "./issuer.js";
import { decodePayloadUnverified } from "./jwt-payload.js";
import { createVerifier, verifyToken, type VerifierOptions } from "./verify.js";
import type { RelytClaims } from "./claims.js";

/** Default cookie name shared by the middleware, getClaims and set/clearTokenCookie. */
export const DEFAULT_COOKIE_NAME = "__Host-relyt-at";
const STRIP_PREFIX = "x-relyt-";
/** Auth failure responses are never cacheable, so a shared cache cannot replay a 401 / redirect / 503 to a signed-in user. */
const NO_STORE = "no-store";

export interface AuthMiddlewareOptions extends VerifierOptions {
  /** Sign-in page; absolute URLs are used as-is, relative paths are resolved against the request URL. */
  signInUrl: string;
  /** Strings match by path-segment prefix; RegExps are tested against the pathname. */
  publicPaths?: Array<string | RegExp>;
  /** Default "/api/". */
  apiPrefix?: string;
  /** Default "__Host-relyt-at". */
  cookieName?: string;
  /** Default true; false ⇒ API paths accept bearer tokens only. */
  cookieOnApi?: boolean;
}

/** JWKS unavailable (code "jwks_unavailable"): handlers should answer 503. */
export class RelytAuthUnavailableError extends RelytAuthError {
  constructor() {
    super("jwks_unavailable");
    this.name = "RelytAuthUnavailableError";
  }
}

function bearer(h: Headers): string | null {
  const v = h.get("authorization");
  if (v === null) return null;
  const m = /^Bearer[ ]+(\S+)[ ]*$/i.exec(v);
  return m ? m[1]! : null;
}

/** The cookie value if the name occurs exactly once in the Cookie header; multiple occurrences ⇒ null (prevents shadowing via cookies injected from a sibling subdomain). */
function cookie(h: Headers, name: string): string | null {
  const raw = h.get("cookie");
  if (raw === null) return null;
  const hits: string[] = [];
  for (const part of raw.split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    if (part.slice(0, i).trim() === name) hits.push(part.slice(i + 1).trim());
  }
  if (hits.length !== 1 || hits[0] === "") return null;
  return hits[0]!;
}

/** A present Authorization header is authoritative: non-Bearer / malformed ⇒ no token, with no fallback to the cookie. */
function readToken(h: Headers, name: string, allowCookie: boolean): string | null {
  if (h.has("authorization")) return bearer(h);
  return allowCookie ? cookie(h, name) : null;
}

function cookieNameOf(v: unknown): string {
  if (v === undefined) return DEFAULT_COOKIE_NAME;
  if (typeof v !== "string" || !/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(v)) throw new RelytAuthError("config", { option: "cookieName" });
  return v;
}

/**
 * Normalizes `next`: decode first (failure ⇒ "/"); after decoding, any C0 control character / DEL (URL parsing strips \t\n\r, so "/\t/evil.com" would become "//evil.com"; spaces are allowed since the origin check below still applies),
 * a leading // or /\, any \, no leading /, or a cross-origin result when resolved against a placeholder origin ⇒ "/".
 */
export function safeNext(pathAndSearch: string): string {
  let d: string;
  try {
    d = decodeURIComponent(pathAndSearch);
  } catch {
    return "/";
  }
  if (/[\x00-\x1f\x7f]/.test(d)) return "/";
  if (!d.startsWith("/") || d.startsWith("//") || d.includes("\\")) return "/";
  try {
    if (new URL(d, "https://n.invalid").origin !== "https://n.invalid") return "/";
  } catch {
    return "/";
  }
  return pathAndSearch;
}

function segPrefix(path: string, p: string): boolean {
  const base = p.endsWith("/") ? p.slice(0, -1) : p;
  if (base === "") return path === "/"; // "/" means the root path only, not "every path"
  return path === base || path.startsWith(base + "/");
}

function isPublic(path: string, list: Array<string | RegExp>): boolean {
  return list.some((p) => (typeof p === "string" ? segPrefix(path, p) : new RegExp(p.source, p.flags.replace(/[gy]/g, "")).test(path)));
}

export function createAuthMiddleware(o: AuthMiddlewareOptions): (req: NextRequest) => Promise<NextResponse> {
  if (typeof o !== "object" || o === null) throw new RelytAuthError("config", { option: "issuer" });
  normalizeIssuer(o.issuer);
  const verify = createVerifier(o);
  if (typeof o.signInUrl !== "string" || o.signInUrl === "") throw new RelytAuthError("config", { option: "signInUrl" });
  try {
    new URL(o.signInUrl, "https://placeholder.invalid");
  } catch {
    throw new RelytAuthError("config", { option: "signInUrl" });
  }
  const signInUrl = o.signInUrl;
  const apiPrefix = o.apiPrefix ?? "/api/";
  if (typeof apiPrefix !== "string" || !apiPrefix.startsWith("/")) throw new RelytAuthError("config", { option: "apiPrefix" });
  /** "/api/" also covers the bare path "/api". */
  const apiBare = apiPrefix.length > 1 && apiPrefix.endsWith("/") ? apiPrefix.slice(0, -1) : null;
  const cookieName = cookieNameOf(o.cookieName);
  const cookieOnApi = o.cookieOnApi ?? true;
  const publicPaths = o.publicPaths ?? [];

  return async (req) => {
    const headers = new Headers();
    req.headers.forEach((v, k) => {
      if (!k.toLowerCase().startsWith(STRIP_PREFIX)) headers.set(k, v);
    });
    const pass = () => NextResponse.next({ request: { headers } });
    const path = req.nextUrl.pathname;
    if (isPublic(path, publicPaths)) return pass();

    const api = path.startsWith(apiPrefix) || path === apiBare || (req.headers.get("accept") ?? "").toLowerCase().includes("application/json");
    const token = readToken(req.headers, cookieName, !api || cookieOnApi);
    let failure: "none" | "invalid" | "unavailable" = "none";
    if (token !== null) {
      try {
        await verify(token);
        return pass();
      } catch (e) {
        failure = e instanceof RelytAuthError && e.code === "jwks_unavailable" ? "unavailable" : "invalid";
      }
    }
    if (failure === "unavailable") {
      return NextResponse.json({ error: "auth_unavailable" }, { status: 503, headers: { "retry-after": "2", "cache-control": NO_STORE } });
    }
    if (api) {
      const www = failure === "none" ? "Bearer" : 'Bearer error="invalid_token"';
      return NextResponse.json({ error: "unauthorized" }, { status: 401, headers: { "www-authenticate": www, "cache-control": NO_STORE } });
    }
    const target = new URL(signInUrl, req.nextUrl.href);
    target.searchParams.set("next", safeNext(path + req.nextUrl.search));
    const method = req.method.toUpperCase();
    const res = NextResponse.redirect(target, method === "GET" || method === "HEAD" ? 307 : 303);
    res.headers.set("cache-control", NO_STORE);
    return res;
  };
}

/**
 * Reads claims in a route handler: takes the token from the bearer header (preferred) or the cookie and verifies it again; never reads x-relyt-*.
 * `cookie` defaults to true; false ⇒ Authorization only (matches the middleware's `cookieOnApi: false`).
 * Missing / invalid / other-tenant token ⇒ null; JWKS unavailable ⇒ throws RelytAuthUnavailableError by default, `onUnavailable: "null"` ⇒ null.
 */
export async function getClaims(
  req: Request,
  o: VerifierOptions & { cookieName?: string },
  opts: { onUnavailable?: "throw" | "null"; cookie?: boolean } = {},
): Promise<RelytClaims | null> {
  const token = readToken(req.headers, cookieNameOf(o?.cookieName), opts.cookie ?? true);
  if (token === null) {
    normalizeIssuer(o?.issuer); // validate the config even without a token, so a misconfiguration is not hidden behind null
    return null;
  }
  try {
    return await verifyToken(token, o);
  } catch (e) {
    if (!(e instanceof RelytAuthError)) throw e;
    if (e.code === "jwks_unavailable") {
      if ((opts.onUnavailable ?? "throw") === "null") return null;
      throw new RelytAuthUnavailableError();
    }
    if (e.code === "invalid_token" || e.code === "invalid_claims") return null;
    throw e;
  }
}

/** Reads the payload `exp` only (no verification: the cookie is written by the server that just obtained the token, Max-Age is only a lifetime cap). */
function expOf(token: string): number | null {
  const exp = decodePayloadUnverified(token)?.exp;
  return typeof exp === "number" && Number.isFinite(exp) ? exp : null;
}

const MAX_COOKIE_BYTES = 4000;
const COOKIE_ATTRS = { path: "/", secure: true, httpOnly: true, sameSite: "lax" } as const;

/** Writes the token cookie: Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=min(TOKEN_TTL_S, exp − now); remaining ≤ 0 ⇒ clears it instead. */
export function setTokenCookie(res: NextResponse, token: string, o: { cookieName?: string } = {}): void {
  const name = cookieNameOf(o.cookieName);
  const exp = expOf(token);
  const left = exp === null ? 0 : Math.floor(exp - Date.now() / 1000);
  if (left <= 0) return clearTokenCookie(res, o);
  const maxAge = Math.min(TOKEN_TTL_S, left);
  // Browsers cap a single cookie at about 4096 bytes and silently drop larger ones ⇒ sign-in "succeeds" but no token ever arrives; fail loudly on the server instead.
  const serialized = `${name}=${token}; Path=/; Max-Age=${maxAge}; Secure; HttpOnly; SameSite=Lax`;
  if (new TextEncoder().encode(serialized).length > MAX_COOKIE_BYTES) throw new RelytAuthError("config", { option: "cookieSize" });
  res.cookies.set(name, token, { ...COOKIE_ATTRS, maxAge });
}

/** Clears the token cookie (sign-out must call this server-side: the cookie is HttpOnly, browser JS cannot clear it). */
export function clearTokenCookie(res: NextResponse, o: { cookieName?: string } = {}): void {
  res.cookies.set(cookieNameOf(o.cookieName), "", { ...COOKIE_ATTRS, maxAge: 0 });
}
