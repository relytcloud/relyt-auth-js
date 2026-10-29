// Cross-site social sign-in. Web APIs only.
// Handoff codes, PKCE verifiers and session tokens never reach errors, events or logs.
import { retryAfterMs, type AuthClient } from "./client.js";
import { RelytAuthError } from "./errors.js";
import { normalizeIssuer } from "./issuer.js";
import { num } from "./options.js";

/** sessionStorage key: one pending sign-in record `{v, mode, base, t}` (single use, removed when read by complete). */
export const SOCIAL_PKCE_STORAGE_KEY = "relyt.auth.social.pkce";

export type SocialResponseMode = "fragment" | "query";

export interface StartSocialSignInOptions {
  /** `https://<authHost>`, same rules as createAuthClient. */
  authUrl: string;
  provider: string;
  /** Must match the callback URL registered in the console verbatim (exact match, no wildcards). */
  callbackURL: string;
  errorCallbackURL?: string;
  newUserCallbackURL?: string;
  /** Default fragment (the code never reaches server logs / Referer). */
  responseMode?: SocialResponseMode;
}

export interface CompleteSocialSignInOptions {
  authUrl: string;
  /** Called with the session token (bearer mode); the app stores it and provides it via createAuthClient's sessionToken. */
  onSessionToken: (t: string) => void;
  /** Given ⇒ clear() is called before delivering the new token, dropping JWTs cached for the previous identity. */
  client?: AuthClient;
  fetch?: typeof fetch;
  timeoutMs?: number;
}

export interface ExchangeHandoffCodeOptions {
  authUrl: string;
  code: string;
  codeVerifier: string;
  fetch?: typeof fetch;
  timeoutMs?: number;
}

const CODE_RE = /^[A-Za-z0-9_-]{43}$/;
const OAUTH_ERROR_RE = /^[a-z0-9_]{1,64}$/;
const MODES: ReadonlySet<string> = new Set(["fragment", "query"]);
const CODE_PARAM = "relyt_code";
const ERROR_PARAM = "error";
/** Parameters the callback page must remove from the address bar (code, error and its description). */
const STRIP_PARAMS = [CODE_PARAM, ERROR_PARAM, "error_description"] as const;

const cfg = (option: string) => new RelytAuthError("config", { option });

function base64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function authBase(s: unknown): string {
  try {
    return normalizeIssuer(s);
  } catch {
    throw cfg("authUrl");
  }
}

const optStr = (v: unknown, option: string): string | undefined => {
  if (v === undefined) return undefined;
  if (typeof v !== "string" || v === "") throw cfg(option);
  return v;
};

export interface SocialStart {
  /** Full URL of the auth host's sign-in start endpoint (navigate the top-level window to it). */
  url: string;
  /** PKCE verifier; submitted verbatim on exchange, never logged. */
  codeVerifier: string;
}

/** Validates options, generates verifier and S256 challenge, builds the start URL; touches no storage and does not navigate. */
async function buildStart(o: StartSocialSignInOptions): Promise<SocialStart & { base: string; mode: SocialResponseMode }> {
  if (typeof o !== "object" || o === null) throw cfg("authUrl");
  const base = authBase(o.authUrl);
  const provider = optStr(o.provider, "provider");
  const callbackURL = optStr(o.callbackURL, "callbackURL");
  if (provider === undefined) throw cfg("provider");
  if (callbackURL === undefined) throw cfg("callbackURL");
  const errorCallbackURL = optStr(o.errorCallbackURL, "errorCallbackURL");
  const newUserCallbackURL = optStr(o.newUserCallbackURL, "newUserCallbackURL");
  const mode = o.responseMode ?? "fragment";
  if (!MODES.has(mode)) throw cfg("responseMode");

  const raw = new Uint8Array(32);
  globalThis.crypto.getRandomValues(raw);
  const codeVerifier = base64url(raw);
  const challenge = base64url(
    new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(codeVerifier))),
  );

  const q = new URLSearchParams();
  q.set("provider", provider);
  q.set("callbackURL", callbackURL);
  if (errorCallbackURL !== undefined) q.set("errorCallbackURL", errorCallbackURL);
  if (newUserCallbackURL !== undefined) q.set("newUserCallbackURL", newUserCallbackURL);
  q.set("code_challenge", challenge);
  q.set("code_challenge_method", "S256");
  q.set("response_mode", mode);
  return { url: `${base}/api/auth/relyt/social/start?${q.toString()}`, codeVerifier, base, mode };
}

/**
 * Pure builder (works in browsers and Node): returns the start URL and the verifier; the caller keeps the verifier and navigates.
 * Used for the server-proxied flow: the server generates it, binds the verifier to its own session, and redeems the code with exchangeHandoffCode after the callback.
 */
export async function createSocialStart(o: StartSocialSignInOptions): Promise<SocialStart> {
  const { url, codeVerifier } = await buildStart(o);
  return { url, codeVerifier };
}

/** Browser entry: build → store the pending record → navigate the top-level window to the auth host. */
export async function startSocialSignIn(o: StartSocialSignInOptions): Promise<void> {
  const { url, codeVerifier: v, base, mode } = await buildStart(o);
  try {
    globalThis.sessionStorage.setItem(SOCIAL_PKCE_STORAGE_KEY, JSON.stringify({ v, mode, base, t: Date.now() }));
  } catch {
    throw cfg("sessionStorage");
  }
  globalThis.location.assign(url);
}

interface Pending {
  v: string;
  mode: SocialResponseMode;
  base: string;
  t: number;
}

/** Lifetime of a pending record: older records are treated as missing. */
const PENDING_TTL_MS = 10 * 60 * 1000;

/** Takes and removes the pending record (single use); unreadable / invalid ⇒ null. */
function takePending(): Pending | null {
  let raw: string | null = null;
  try {
    raw = globalThis.sessionStorage.getItem(SOCIAL_PKCE_STORAGE_KEY);
    globalThis.sessionStorage.removeItem(SOCIAL_PKCE_STORAGE_KEY);
  } catch {
    return null;
  }
  if (raw === null) return null;
  try {
    const p = JSON.parse(raw) as { v?: unknown; mode?: unknown; base?: unknown; t?: unknown } | null;
    if (
      p && typeof p.v === "string" && CODE_RE.test(p.v) && typeof p.mode === "string" && MODES.has(p.mode) &&
      typeof p.base === "string" && typeof p.t === "number" && Number.isFinite(p.t)
    ) {
      return { v: p.v, mode: p.mode as SocialResponseMode, base: p.base, t: p.t };
    }
  } catch {
    /* a corrupt record is treated as missing */
  }
  return null;
}

/** (1) read the URL (2) remove code / error from the address bar; runs before anything else, including option validation. */
function readAndCleanUrl(): { fromQuery: string[]; fromFrag: string[]; err: string | null } {
  const url = new URL(globalThis.location.href);
  const frag = new URLSearchParams(url.hash.startsWith("#") ? url.hash.slice(1) : url.hash);
  const fromQuery = url.searchParams.getAll(CODE_PARAM);
  const fromFrag = frag.getAll(CODE_PARAM);
  const err = url.searchParams.get(ERROR_PARAM) ?? frag.get(ERROR_PARAM);
  let changed = false;
  if (STRIP_PARAMS.some((k) => url.searchParams.has(k))) {
    for (const k of STRIP_PARAMS) url.searchParams.delete(k);
    changed = true;
  }
  if (STRIP_PARAMS.some((k) => frag.has(k))) {
    for (const k of STRIP_PARAMS) frag.delete(k);
    const rest = frag.toString();
    url.hash = rest === "" ? "" : `#${rest}`;
    changed = true;
  }
  if (changed) globalThis.history.replaceState(globalThis.history.state, "", url.href);
  return { fromQuery, fromFrag, err };
}

/** The complete() call in progress: concurrent calls share one promise, reset when it settles (success or failure). */
let inFlight: Promise<void> | null = null;

/**
 * Call on the registered callback page: clean the address bar → validate options → take the verifier → exchange → deliver the session token.
 * Re-entrant: a call while one is in progress (e.g. React StrictMode's double effect) returns the same promise, so the code is exchanged
 * and the token delivered exactly once; options passed to the later call are ignored.
 */
export function completeSocialSignIn(o: CompleteSocialSignInOptions): Promise<void> {
  if (inFlight !== null) return inFlight;
  const p = runComplete(o).finally(() => {
    if (inFlight === p) inFlight = null;
  });
  inFlight = p;
  return p;
}

async function runComplete(o: CompleteSocialSignInOptions): Promise<void> {
  const { fromQuery, fromFrag, err } = readAndCleanUrl();
  if (typeof o !== "object" || o === null) throw cfg("authUrl");
  const base = authBase(o.authUrl);
  if (typeof o.onSessionToken !== "function") throw cfg("onSessionToken");
  const timeoutMs = num(o.timeoutMs, 15_000, "timeoutMs", (n) => Number.isInteger(n) && n >= 1_000 && n <= 60_000);

  // (3) take and remove the record (single use).
  const pending = takePending();
  // (4) error callback (checked before the missing-record check).
  if (err !== null) {
    throw new RelytAuthError("oauth_error", { retryable: false, oauthError: OAUTH_ERROR_RE.test(err) ? err : "unknown" });
  }
  // (5) no record started in this browser session ⇒ never exchange (defends against planted codes, i.e. login CSRF).
  if (pending === null) throw new RelytAuthError("no_pending_sign_in", { retryable: false });
  // (5') the record must have been started for the same auth host and not be expired; otherwise treat it as missing, no separate error code.
  if (pending.base !== base || Date.now() - pending.t > PENDING_TTL_MS) {
    throw new RelytAuthError("no_pending_sign_in", { retryable: false });
  }
  // (6) take the code only from the location named by the record's mode; exactly one, well-formed.
  const codes = pending.mode === "fragment" ? fromFrag : fromQuery;
  const code = codes.length === 1 ? codes[0] : undefined;
  if (code === undefined || !CODE_RE.test(code)) throw new RelytAuthError("missing_code", { retryable: false });

  const { sessionToken } = await exchange(base, code, pending.v, o.fetch, timeoutMs);
  o.client?.clear();
  o.onSessionToken(sessionToken);
}

/** Server-side proxy (Node / Next route handler): no Origin header, exchanges directly. */
export async function exchangeHandoffCode(o: ExchangeHandoffCodeOptions): Promise<{ sessionToken: string }> {
  if (typeof o !== "object" || o === null) throw cfg("authUrl");
  const base = authBase(o.authUrl);
  if (typeof o.code !== "string" || o.code === "") throw cfg("code");
  if (typeof o.codeVerifier !== "string" || o.codeVerifier === "") throw cfg("codeVerifier");
  const timeoutMs = num(o.timeoutMs, 15_000, "timeoutMs", (n) => Number.isInteger(n) && n >= 1_000 && n <= 60_000);
  return exchange(base, o.code, o.codeVerifier, o.fetch, timeoutMs);
}

/** Single POST, no retry (codes are single use); status → error code mapping is documented in the README. */
async function exchange(
  base: string,
  code: string,
  codeVerifier: string,
  f: typeof fetch | undefined,
  timeoutMs: number,
): Promise<{ sessionToken: string }> {
  const doFetch: typeof fetch = f ?? ((input, init) => globalThis.fetch(input, init));
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), timeoutMs);
  let res: Response;
  try {
    res = await doFetch(`${base}/api/auth/relyt/exchange`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ code, code_verifier: codeVerifier }),
      credentials: "omit",
      signal: ac.signal,
    });
    await res.text().catch(() => "");
  } catch {
    throw new RelytAuthError("network", { retryable: false });
  } finally {
    clearTimeout(timer);
  }
  const s = res.status;
  if (s === 200) {
    const t = res.headers.get("set-auth-token");
    if (t === null || t === "") throw new RelytAuthError("bad_response", { status: 200, retryable: false });
    return { sessionToken: t };
  }
  if (s === 400) throw new RelytAuthError("invalid_handoff_code", { status: s, retryable: false });
  // 403 is only reachable by non-browser callers that send their own Origin: in a browser an unregistered origin fails the CORS preflight first, which surfaces as network.
  if (s === 403) throw new RelytAuthError("invalid_origin", { status: s, retryable: false });
  if (s === 429) {
    // Reuses the client's parser (integer seconds / IMF-fixdate, clamped to [0, 10] s, invalid ⇒ 2 s); header missing ⇒ omitted.
    const ra = res.headers.get("retry-after");
    const retryAfterS = ra === null ? undefined : retryAfterMs(ra) / 1000;
    throw new RelytAuthError("rate_limited", { status: s, retryable: false, ...(retryAfterS === undefined ? {} : { retryAfterS }) });
  }
  if (s === 503) throw new RelytAuthError("unavailable", { status: s, retryable: false });
  throw new RelytAuthError("bad_response", { status: s, retryable: false });
}
