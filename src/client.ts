// Client-side token cache. Uses Web APIs only (browser / Node / edge runtime).
// The client only carries tokens, it never trusts them: no signature check here; verification happens server-side in verifyToken.
import { TOKEN_TTL_S } from "./constants.js";
import { RelytAuthError, type AuthEvent } from "./errors.js";
import { normalizeIssuer } from "./issuer.js";
import { decodePayloadUnverified } from "./jwt-payload.js";
import { num } from "./options.js";

export interface AuthClientOptions {
  /** `https://<authHost>`: no trailing slash, no path (same rule as the issuer). */
  authUrl: string;
  /** Set ⇒ bearer mode (`Authorization: Bearer`, `credentials: "omit"`); unset ⇒ cookie mode. */
  sessionToken?: () => string | null | Promise<string | null>;
  /** Called when the response carries a `set-auth-token` header. */
  onSessionToken?: (t: string) => void;
  /** Refresh lead time in seconds; default 120, must be within [10, 600]. */
  refreshAheadS?: number;
  fetch?: typeof fetch;
  /** Per-request timeout in integer milliseconds; default 15_000, must be within [1_000, 60_000]. A timeout counts as `network` and is not retried. */
  timeoutMs?: number;
  onEvent?: (e: AuthEvent) => void;
}

export interface AuthClient {
  getToken(): Promise<string>;
  peekToken(): string | null;
  getSession(): Promise<unknown | null>;
  clear(): void;
}

/** Retry only on "503 with a readable Retry-After", at most 3 retries (4 requests in total). */
const MAX_RETRIES = 3;
const RA_MAX_S = 10;
const RA_INVALID_S = 2;
const IMF_FIXDATE = /^[A-Za-z]{3}, \d{2} [A-Za-z]{3} \d{4} \d{2}:\d{2}:\d{2} GMT$/;

/** Sentinel used when racing the session-token provider against the timeout (only ever resolves, never rejects, so no unhandled rejection). */
const ABORTED: unique symbol = Symbol("aborted");
/** Provider threw / produced an invalid header value: no `cause`, so the original TypeError message cannot leak the session token. */
const unauth = () => new RelytAuthError("unauthenticated", { retryable: false });

/** Retry-After → milliseconds: integer seconds or IMF-fixdate (relative to the local clock), clamped to [0, 10] s; invalid ⇒ 2 s. */
export function retryAfterMs(raw: string): number {
  const s = raw.trim();
  let sec: number;
  if (/^\d+$/.test(s)) sec = Number(s);
  else if (IMF_FIXDATE.test(s) && !Number.isNaN(Date.parse(s))) sec = (Date.parse(s) - Date.now()) / 1000;
  else sec = RA_INVALID_S;
  return Math.round(Math.min(RA_MAX_S, Math.max(0, sec)) * 1000);
}

/** Returns `exp − iat` in seconds; undecodable or outside (0, TOKEN_TTL_S] ⇒ null (reported as bad_response, never cached). */
function lifetimeS(token: unknown): number | null {
  if (typeof token !== "string") return null;
  const payload = decodePayloadUnverified(token);
  if (payload === null) return null;
  const { iat, exp } = payload;
  if (typeof iat !== "number" || typeof exp !== "number") return null;
  const d = exp - iat;
  return Number.isFinite(d) && d > 0 && d <= TOKEN_TTL_S ? d : null;
}

export function createAuthClient(o: AuthClientOptions): AuthClient {
  if (typeof o !== "object" || o === null) throw new RelytAuthError("config", { option: "authUrl" });
  let base: string;
  try {
    base = normalizeIssuer(o.authUrl);
  } catch {
    throw new RelytAuthError("config", { option: "authUrl" });
  }
  const refreshAheadMs = num(o.refreshAheadS, 120, "refreshAheadS", (n) => n >= 10 && n <= 600) * 1000;
  const timeoutMs = num(o.timeoutMs, 15_000, "timeoutMs", (n) => Number.isInteger(n) && n >= 1_000 && n <= 60_000);
  const doFetch: typeof fetch = o.fetch ?? ((input, init) => globalThis.fetch(input, init));

  let cache: { token: string; expiresAtLocal: number } | null = null;
  let inflight: Promise<string> | null = null;
  let gen = 0;
  /** One per generation: aborted by clear() to cancel pending backoff waits. */
  let genAc = new AbortController();

  const emit = (e: AuthEvent) => {
    try {
      o.onEvent?.(e);
    } catch {
      /* a throwing callback must not affect token retrieval */
    }
  };

  /** Generation-guarded write: results of a generation that predates clear() are never stored. */
  const store = (g: number, token: string, d: number, receivedAt: number) => {
    if (g === gen) cache = { token, expiresAtLocal: receivedAt + d * 1000 };
  };

  /**
   * Sends one request and reads the whole body. The timeout uses AbortController + setTimeout, equivalent to
   * `AbortSignal.timeout(timeoutMs)` but clearable on completion; any rejection (including timeout / TypeError) ⇒ network, no retry.
   */
  async function request(path: string): Promise<{ res: Response; body: string; receivedAt: number }> {
    // Start the timer first: the time spent in sessionToken() counts towards timeoutMs.
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), timeoutMs);
    try {
      const headers = new Headers();
      let credentials: RequestCredentials = "include";
      if (o.sessionToken) {
        credentials = "omit";
        const provider = o.sessionToken;
        const aborted = new Promise<typeof ABORTED>((r) => ac.signal.addEventListener("abort", () => r(ABORTED), { once: true }));
        let st: string | null | typeof ABORTED;
        try {
          st = await Promise.race([Promise.resolve().then(() => provider()), aborted]);
        } catch {
          throw unauth();
        }
        if (st === ABORTED) throw new RelytAuthError("network");
        if (typeof st === "string" && st !== "") {
          try {
            headers.set("authorization", `Bearer ${st}`);
          } catch {
            throw unauth();
          }
        }
      }
      try {
        const res = await doFetch(`${base}${path}`, { method: "GET", headers, credentials, signal: ac.signal });
        const receivedAt = Date.now();
        const body = await res.text();
        return { res, body, receivedAt };
      } catch {
        throw new RelytAuthError("network");
      }
    } finally {
      clearTimeout(timer);
    }
  }

  /** Backoff wait; an abort triggered by clear() clears the timer and rejects with unauthenticated. */
  const sleep = (ms: number, signal: AbortSignal) =>
    new Promise<void>((resolve, reject) => {
      if (signal.aborted) return reject(unauth());
      const onAbort = () => {
        clearTimeout(t);
        reject(unauth());
      };
      const t = setTimeout(() => {
        signal.removeEventListener("abort", onAbort);
        resolve();
      }, ms);
      signal.addEventListener("abort", onAbort, { once: true });
    });

  async function refresh(g: number): Promise<string> {
    const signal = genAc.signal;
    for (let attempt = 0; ; attempt++) {
      if (g !== gen) throw new RelytAuthError("unauthenticated", { retryable: false });
      const { res, body, receivedAt } = await request("/api/auth/token");
      if (res.status === 200) {
        let token: unknown;
        try {
          token = (JSON.parse(body) as { token?: unknown } | null)?.token;
        } catch {
          token = undefined;
        }
        const d = lifetimeS(token);
        if (d === null) {
          emit({ type: "token_refresh", code: "bad_response", status: 200, attempt });
          throw new RelytAuthError("bad_response", { status: 200 });
        }
        store(g, token as string, d, receivedAt);
        emit({ type: "token_refresh", status: 200, attempt });
        return token as string;
      }
      if (res.status === 401 || res.status === 403) {
        if (g === gen) cache = null;
        emit({ type: "token_refresh", code: "unauthenticated", status: res.status, attempt });
        throw new RelytAuthError("unauthenticated", { status: res.status });
      }
      if (res.status === 503) {
        // Decided by the response header only, never by the body code. If CORS hides the header, get() is null ⇒ no retry.
        const ra = res.headers.get("retry-after");
        if (ra !== null && attempt < MAX_RETRIES) {
          if (g !== gen) throw unauth();
          emit({ type: "retry", status: 503, attempt: attempt + 1 });
          await sleep(retryAfterMs(ra), signal);
          continue;
        }
        emit({ type: "token_refresh", code: "unavailable", status: 503, attempt });
        throw new RelytAuthError("unavailable", { status: 503, retryable: ra !== null });
      }
      emit({ type: "token_refresh", code: "bad_response", status: res.status, attempt });
      throw new RelytAuthError("bad_response", { status: res.status, retryable: false });
    }
  }

  return {
    getToken(): Promise<string> {
      if (cache && cache.expiresAtLocal - Date.now() > refreshAheadMs) return Promise.resolve(cache.token);
      if (inflight) return inflight;
      const p = refresh(gen).finally(() => {
        if (inflight === p) inflight = null;
      });
      inflight = p;
      return p;
    },

    peekToken(): string | null {
      return cache && cache.expiresAtLocal > Date.now() ? cache.token : null;
    },

    async getSession(): Promise<unknown | null> {
      const g = gen;
      const { res, body, receivedAt } = await request("/api/auth/get-session");
      if (res.status === 401 || res.status === 403) {
        if (g === gen) cache = null;
        return null;
      }
      if (res.status === 503) throw new RelytAuthError("unavailable", { status: 503, retryable: res.headers.get("retry-after") !== null });
      if (res.status !== 200) throw new RelytAuthError("bad_response", { status: res.status, retryable: false });
      let data: unknown;
      try {
        data = JSON.parse(body);
      } catch {
        throw new RelytAuthError("bad_response", { status: 200 });
      }
      const st = res.headers.get("set-auth-token");
      if (g === gen && st !== null && st !== "" && o.onSessionToken) {
        try {
          o.onSessionToken(st);
        } catch {
          /* a throwing application callback must not affect the result */
        }
      }
      if (data === null) {
        if (g === gen) cache = null;
        return null;
      }
      const jwt = res.headers.get("set-auth-jwt");
      const d = lifetimeS(jwt);
      if (jwt !== null && d !== null) store(g, jwt, d, receivedAt);
      return data;
    },

    clear(): void {
      cache = null;
      inflight = null;
      gen += 1;
      genAc.abort();
      genAc = new AbortController();
    },
  };
}
