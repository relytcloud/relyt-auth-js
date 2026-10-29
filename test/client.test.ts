// Client: createAuthClient.
// Only setTimeout / clearTimeout / Date are faked; fetch is a scriptable stub, Responses are real Web API objects.
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SignJWT, generateKeyPair } from "jose";
import { createAuthClient, type AuthClientOptions } from "../src/client.js";
import { RelytAuthError, type AuthEvent } from "../src/errors.js";
import { assertNoLeak, expectReject, seenTokens } from "./helpers/expect.js";

const AUTH = "https://t1.auth.example.com";
const T0 = Date.UTC(2026, 9, 27, 0, 0, 0);
const S = () => Math.floor(Date.now() / 1000);
const b64u = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
let seq = 0;
/** Unsigned three-segment JWT (the client does not verify signatures); a random signature segment makes every token unique and long enough. */
function jwt(iat: number, exp: number): string {
  seq += 1;
  const sig = Buffer.from(`sig-${seq}-${Math.random()}-${"x".repeat(40)}`).toString("base64url");
  return `${b64u({ alg: "EdDSA", kid: "k1" })}.${b64u({ sub: "user-1", iat, exp, n: seq })}.${sig}`;
}
const fresh = (ttl = 900, skewS = 0) => jwt(S() - skewS, S() - skewS + ttl);

interface Call { url: string; init: RequestInit; at: number }
type Handler = (n: number, init: RequestInit) => Response | Promise<Response>;
function stub(h: Handler) {
  const calls: Call[] = [];
  const f = (async (input: RequestInfo | URL, init: RequestInit = {}) => {
    calls.push({ url: String(input), init, at: Date.now() });
    return h(calls.length, init);
  }) as typeof fetch;
  return { f, calls };
}
const tokenRes = (token: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify({ token }), { status: 200, headers: { "content-type": "application/json", ...headers } });
const status = (s: number, ra?: string, body = '{"error":"x"}') =>
  new Response(body, { status: s, headers: ra === undefined ? {} : { "retry-after": ra } });
const delay = <T>(ms: number, v: () => T) => new Promise<T>((r) => setTimeout(() => r(v()), ms));
const hang = (init: RequestInit) =>
  new Promise<Response>((_, rej) => init.signal?.addEventListener("abort", () => rej(new DOMException("timeout", "TimeoutError"))));
function deferred() {
  let resolve!: (r: Response) => void;
  const p = new Promise<Response>((r) => (resolve = r));
  return { p, resolve };
}
function track<T>(p: Promise<T>) {
  const t = { settled: false, value: undefined as T | undefined, error: undefined as unknown, p };
  p.then((v) => ((t.settled = true), (t.value = v)), (e) => ((t.settled = true), (t.error = e)));
  return t;
}
const events: AuthEvent[] = [];
const mk = (f: typeof fetch, o: Partial<AuthClientOptions> = {}) =>
  createAuthClient({ authUrl: AUTH, fetch: f, onEvent: (e) => events.push(e), ...o });
const EVENT_KEYS = new Set(["type", "code", "status", "attempt", "kid", "issuer"]);

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
  vi.setSystemTime(T0);
  events.length = 0;
});
afterEach(() => {
  for (const e of events) for (const k of Object.keys(e)) expect(EVENT_KEYS.has(k), `event key ${k}`).toBe(true);
  vi.useRealTimers();
});
afterAll(() => {
  // Non-vacuity for the leak check: a token / session token really went through the failure paths
  expect(seenTokens.length).toBeGreaterThanOrEqual(6);
});

/** First obtain and cache a valid token A (request #1). */
async function primed(h: Handler, o: Partial<AuthClientOptions> = {}) {
  const A = fresh();
  const s = stub((n, init) => (n === 1 ? tokenRes(A) : h(n, init)));
  const c = mk(s.f, o);
  expect(await c.getToken()).toBe(A);
  return { A, c, calls: s.calls };
}

describe("basic token retrieval and credential modes", () => {
  it("cookie mode: GET {authUrl}/api/auth/token, credentials include, no Authorization", async () => {
    const A = fresh();
    const s = stub(() => tokenRes(A));
    const c = mk(s.f);
    expect(await c.getToken()).toBe(A);
    expect(s.calls).toHaveLength(1);
    expect(s.calls[0]!.url).toBe(`${AUTH}/api/auth/token`);
    expect(s.calls[0]!.init.method ?? "GET").toBe("GET");
    expect(s.calls[0]!.init.credentials).toBe("include");
    expect(new Headers(s.calls[0]!.init.headers).get("authorization")).toBeNull();
    expect(c.peekToken()).toBe(A);
    expect(vi.getTimerCount()).toBe(0); // the timeout timer is cleared once the request settles
  });

  it("bearer mode: Authorization: Bearer <st>, credentials omit (sync and async providers)", async () => {
    for (const st of [() => "st", async () => "st"]) {
      const s = stub(() => tokenRes(fresh()));
      await mk(s.f, { sessionToken: st }).getToken();
      expect(new Headers(s.calls[0]!.init.headers).get("authorization")).toBe("Bearer st");
      expect(s.calls[0]!.init.credentials).toBe("omit");
    }
  });

  it("sessionToken returns null ⇒ no Authorization, still omit (no fallback to cookie mode)", async () => {
    const s = stub(() => status(401));
    await expectReject(mk(s.f, { sessionToken: () => null }).getToken(), "unauthenticated", "n/a-token", events);
    expect(new Headers(s.calls[0]!.init.headers).get("authorization")).toBeNull();
    expect(s.calls[0]!.init.credentials).toBe("omit");
  });

  it("the client does not verify: an EdDSA token signed by any key is cached anyway, and no JWKS is fetched", async () => {
    const { privateKey } = await generateKeyPair("EdDSA", { crv: "Ed25519" });
    const T = await new SignJWT({ sub: "u" }).setProtectedHeader({ alg: "EdDSA", kid: "nobody" })
      .setIssuedAt(S()).setExpirationTime(S() + 900).sign(privateKey);
    const s = stub(() => tokenRes(T));
    const c = mk(s.f);
    expect(await c.getToken()).toBe(T);
    expect(await c.getToken()).toBe(T);
    expect(s.calls.map((x) => x.url)).toEqual([`${AUTH}/api/auth/token`]);
  });
});

describe("caching and early refresh", () => {
  it("lifetime 900: cache used at 779 s, refreshed at 781 s", async () => {
    const A = fresh();
    let B = "";
    const s = stub((n) => (n === 1 ? tokenRes(A) : tokenRes((B = fresh()))));
    const c = mk(s.f);
    expect(await c.getToken()).toBe(A);
    vi.advanceTimersByTime(779_000);
    expect(await c.getToken()).toBe(A);
    expect(s.calls).toHaveLength(1);
    vi.advanceTimersByTime(2_000);
    const got = await c.getToken();
    expect(s.calls).toHaveLength(2);
    expect(got).toBe(B);
    expect(got).not.toBe(A);
  });

  it("peekToken() is null once locally expired (never hands out an expired token)", async () => {
    const A = fresh();
    const c = mk(stub(() => tokenRes(A)).f);
    await c.getToken();
    vi.advanceTimersByTime(899_000);
    expect(c.peekToken()).toBe(A);
    vi.advanceTimersByTime(1_000);
    expect(c.peekToken()).toBeNull();
  });

  it.each([600, -600])("local clock skewed by %i s: decision point unchanged (receive time + (exp−iat))", async (skew) => {
    const A = fresh(900, skew);
    const s = stub((n) => (n === 1 ? tokenRes(A) : tokenRes(fresh(900, skew))));
    const c = mk(s.f);
    expect(await c.getToken()).toBe(A);
    vi.advanceTimersByTime(779_000);
    expect(await c.getToken()).toBe(A);
    expect(s.calls).toHaveLength(1);
    vi.advanceTimersByTime(2_000);
    await c.getToken();
    expect(s.calls).toHaveLength(2);
  });

  it.each([901, 0, -5])("exp−iat = %i ⇒ bad_response, not cached (peek keeps the old value)", async (ttl) => {
    const bad = jwt(S(), S() + ttl);
    const { A, c, calls } = await primed(() => tokenRes(bad));
    vi.advanceTimersByTime(781_000);
    await expectReject(c.getToken(), "bad_response", bad, events);
    expect(calls).toHaveLength(2);
    expect(c.peekToken()).toBe(A);
  });

  it("exp−iat = 900 is cached normally", async () => {
    const T = jwt(S(), S() + 900);
    const s = stub(() => tokenRes(T));
    const c = mk(s.f);
    expect(await c.getToken()).toBe(T);
    expect(c.peekToken()).toBe(T);
    await c.getToken();
    expect(s.calls).toHaveLength(1);
  });
});

describe("single flight and generations", () => {
  it("10 concurrent calls send 1 request; a later refresh can send again after it settles", async () => {
    const s = stub(() => delay(50, () => tokenRes(fresh())));
    const c = mk(s.f);
    const ps = Array.from({ length: 10 }, () => c.getToken());
    await vi.advanceTimersByTimeAsync(50);
    const r = await Promise.all(ps);
    expect(s.calls).toHaveLength(1);
    expect(new Set(r).size).toBe(1);
    vi.advanceTimersByTime(781_000);
    const p = c.getToken();
    await vi.advanceTimersByTimeAsync(50);
    expect(await p).not.toBe(r[0]);
    expect(s.calls).toHaveLength(2);
  });

  it("10 concurrent calls and the refresh returns 401 ⇒ all unauthenticated; the failure is not cached", async () => {
    const s = stub((n) => (n === 1 ? delay(50, () => status(401)) : tokenRes(fresh())));
    const c = mk(s.f);
    const ps = Array.from({ length: 10 }, () => track(c.getToken()));
    await vi.advanceTimersByTimeAsync(50);
    for (const t of ps) {
      expect(t.settled).toBe(true);
      expect((t.error as RelytAuthError).code).toBe("unauthenticated");
    }
    expect(s.calls).toHaveLength(1);
    await c.getToken();
    expect(s.calls).toHaveLength(2);
  });

  it("clear() while a refresh is in flight ⇒ the original caller gets the result, but the cache is not written", async () => {
    const d = deferred();
    const s = stub((n) => (n === 1 ? d.p : tokenRes(fresh())));
    const c = mk(s.f);
    const p = c.getToken();
    c.clear();
    const A = fresh();
    d.resolve(tokenRes(A));
    expect(await p).toBe(A);
    expect(c.peekToken()).toBeNull();
    await c.getToken();
    expect(s.calls).toHaveLength(2);
  });

  it("calling again right after clear() ⇒ a 2nd request; the old in-flight one settling later does not overwrite the new token", async () => {
    const d1 = deferred();
    const d2 = deferred();
    const s = stub((n) => (n === 1 ? d1.p : d2.p));
    const c = mk(s.f);
    const p1 = c.getToken();
    c.clear();
    const p2 = c.getToken();
    await vi.advanceTimersByTimeAsync(0);
    expect(s.calls).toHaveLength(2);
    const A = fresh();
    const B = fresh();
    d2.resolve(tokenRes(B));
    expect(await p2).toBe(B);
    d1.resolve(tokenRes(A));
    expect(await p1).toBe(A);
    expect(c.peekToken()).toBe(B);
  });
});

describe("retries and timeouts", () => {
  it("503(RA=2)×3 → 200 ⇒ success, exactly 4 requests, gaps of exactly 2000 ms", async () => {
    const A = fresh();
    const s = stub((n) => (n <= 3 ? status(503, "2") : tokenRes(A)));
    const c = mk(s.f);
    const t = track(c.getToken());
    await vi.advanceTimersByTimeAsync(10_000);
    expect(t.value).toBe(A);
    expect(s.calls.map((x) => x.at - T0)).toEqual([0, 2000, 4000, 6000]);
    expect(events.filter((e) => e.type === "retry").map((e) => e.attempt)).toEqual([1, 2, 3]);
  });

  it("503(RA=2)×4 ⇒ unavailable/retryable/503, exactly 4 requests, no background retries afterwards", async () => {
    const s = stub(() => status(503, "2"));
    const c = mk(s.f);
    const t = track(c.getToken());
    await vi.advanceTimersByTimeAsync(10_000);
    const e = t.error as RelytAuthError;
    expect(e).toBeInstanceOf(RelytAuthError);
    expect([e.code, e.retryable, e.status]).toEqual(["unavailable", true, 503]);
    expect(s.calls).toHaveLength(4);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(s.calls).toHaveLength(4);
  });

  it("503 without RA / 429(RA=1) / network error ⇒ 1 request each", async () => {
    const a = stub(() => status(503));
    const ea = await expectReject(mk(a.f).getToken(), "unavailable", "n/a-token", events);
    expect([ea.retryable, a.calls.length]).toEqual([false, 1]);
    const b = stub(() => status(429, "1"));
    const tb = track(mk(b.f).getToken());
    await vi.advanceTimersByTimeAsync(5_000);
    expect(tb.error).toBeInstanceOf(RelytAuthError);
    expect(b.calls).toHaveLength(1);
    const n = stub(() => Promise.reject(new TypeError("Failed to fetch")));
    const tn = track(mk(n.f).getToken());
    await vi.advanceTimersByTimeAsync(5_000);
    expect((tn.error as RelytAuthError).code).toBe("network");
    expect(n.calls).toHaveLength(1);
    expect(vi.getTimerCount()).toBe(0); // no timer left behind
  });

  it.each([[2], [3]])("each attempt hangs 8 s then 503(RA=2), attempt %i+1 returns 200 ⇒ total elapsed time", async (fails) => {
    const s = stub((n) => delay(8_000, () => (n <= fails ? status(503, "2") : tokenRes(fresh()))));
    const t = track(mk(s.f).getToken());
    let ms = 0;
    while (!t.settled && ms < 60_000) {
      await vi.advanceTimersByTimeAsync(500);
      ms += 500;
    }
    expect(typeof t.value).toBe("string");
    const [lo, hi] = fails === 3 ? [36_000, 40_000] : [26_000, 30_000];
    expect(ms).toBeGreaterThanOrEqual(lo);
    expect(ms).toBeLessThanOrEqual(hi);
  });

  it.each([
    ["0", 0],
    ["999", 10_000],
    ["abc", 2_000],
    ["+5s", 5_000],
    ["-5s", 0],
  ])("Retry-After %s ⇒ gap of %i ms", async (ra, gap) => {
    const v = ra === "+5s" ? new Date(T0 + 5_000).toUTCString() : ra === "-5s" ? new Date(T0 - 5_000).toUTCString() : ra;
    const s = stub((n) => (n === 1 ? status(503, v) : tokenRes(fresh())));
    const t = track(mk(s.f).getToken());
    await vi.advanceTimersByTimeAsync(15_000);
    expect(typeof t.value).toBe("string");
    expect(s.calls[1]!.at - s.calls[0]!.at).toBe(gap);
  });

  it("clear() during a retry wait ⇒ no further retries, ends with unauthenticated", async () => {
    const s = stub(() => status(503, "2"));
    const c = mk(s.f);
    const t = track(c.getToken());
    await vi.advanceTimersByTimeAsync(1_000);
    c.clear();
    // the backoff is cancellable: ends right after clear() (without waiting for Retry-After's 2 s) and leaves no timer behind
    await vi.advanceTimersByTimeAsync(1);
    expect(t.settled).toBe(true);
    expect((t.error as RelytAuthError).code).toBe("unauthenticated");
    expect(vi.getTimerCount()).toBe(0);
    await vi.advanceTimersByTimeAsync(30_000);
    expect(s.calls).toHaveLength(1);
  });

  it("CORS hides retry-after (headers.get is null) ⇒ no retry, body code ignored; control: with the header it retries", async () => {
    // This relies on the auth service exposing retry-after via CORS (Access-Control-Expose-Headers): if the browser cannot read it, the client does not retry.
    const body = '{"error":"db_unavailable"}';
    const a = stub(() => status(503, undefined, body));
    const ea = await expectReject(mk(a.f).getToken(), "unavailable", "n/a-token", events);
    expect([ea.retryable, a.calls.length]).toEqual([false, 1]);
    const b = stub((n) => (n === 1 ? status(503, "1", body) : tokenRes(fresh())));
    const tb = track(mk(b.f).getToken());
    await vi.advanceTimersByTimeAsync(5_000);
    expect(typeof tb.value).toBe("string");
    expect(b.calls).toHaveLength(2);
  });

  it("timeoutMs defaults to 15 s ⇒ network, no retry; timeoutMs 3000 ⇒ 3 s; the request carries a signal", async () => {
    const s = stub((_, init) => hang(init));
    const t = track(mk(s.f).getToken());
    await vi.advanceTimersByTimeAsync(14_999);
    expect(t.settled).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect((t.error as RelytAuthError).code).toBe("network");
    expect(s.calls[0]!.init.signal).toBeInstanceOf(AbortSignal);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(s.calls).toHaveLength(1);
    const s3 = stub((_, init) => hang(init));
    const t3 = track(mk(s3.f, { timeoutMs: 3000 }).getToken());
    await vi.advanceTimersByTimeAsync(2_999);
    expect(t3.settled).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect((t3.error as RelytAuthError).code).toBe("network");
  });
});

describe("failures and caching", () => {
  it.each([401, 403])("%i ⇒ unauthenticated, and a still-valid cache is cleared", async (code) => {
    const { A, c } = await primed(() => status(code));
    vi.advanceTimersByTime(781_000);
    expect(c.peekToken()).toBe(A);
    await expectReject(c.getToken(), "unauthenticated", A, events);
    expect(c.peekToken()).toBeNull();
  });

  it.each([
    ["{}", () => new Response("{}", { status: 200 })],
    ["not JSON", () => new Response("<html>oops</html>", { status: 200 })],
    ["not three segments", () => tokenRes("not-a-jwt-but-a-long-opaque-session-like-string")],
    ["undecodable payload", () => tokenRes("aaaaaaaaaa.%%%%%%%%%%.bbbbbbbbbb")],
    ["token not a string", () => tokenRes(12345)],
  ])("200 but %s ⇒ bad_response, old cache kept", async (_n, r) => {
    const { A, c } = await primed(r);
    vi.advanceTimersByTime(781_000);
    await expectReject(c.getToken(), "bad_response", "not-a-jwt-but-a-long-opaque-session-like-string", events);
    expect(c.peekToken()).toBe(A);
  });

  it("refresh 503×4 with 60 s left in the cache ⇒ throws instead of falling back to the old token; peek still returns it", async () => {
    const { A, c } = await primed(() => status(503, "2"));
    vi.advanceTimersByTime(840_000);
    const t = track(c.getToken());
    await vi.advanceTimersByTimeAsync(10_000);
    expect((t.error as RelytAuthError).code).toBe("unavailable");
    expect(t.value).toBeUndefined();
    expect(c.peekToken()).toBe(A);
  });
});

describe("getSession", () => {
  const sessionRes = (headers: Record<string, string>, body: unknown = { session: { id: "s1" }, user: { id: "u1" } }) =>
    new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json", ...headers } });

  it("set-auth-jwt fills the cache, saving one /token call; set-auth-token goes to the callback exactly once", async () => {
    const J = fresh();
    const s = stub((n) => (n === 1 ? sessionRes({ "set-auth-jwt": J, "set-auth-token": "sess-tok" }) : tokenRes(fresh())));
    const got: string[] = [];
    const c = mk(s.f, { onSessionToken: (t) => got.push(t) });
    expect(await c.getSession()).toEqual({ session: { id: "s1" }, user: { id: "u1" } });
    expect(s.calls[0]!.url).toBe(`${AUTH}/api/auth/get-session`);
    expect(await c.getToken()).toBe(J);
    expect(s.calls).toHaveLength(1);
    expect(got).toEqual(["sess-tok"]);
  });

  it("no set-auth-jwt ⇒ getToken goes to /token as usual", async () => {
    const s = stub((n) => (n === 1 ? sessionRes({}) : tokenRes(fresh())));
    const c = mk(s.f);
    await c.getSession();
    await c.getToken();
    expect(s.calls.map((x) => x.url)).toEqual([`${AUTH}/api/auth/get-session`, `${AUTH}/api/auth/token`]);
  });

  it("get-session body null (signed out) ⇒ null and cache cleared", async () => {
    const { c } = await primed(() => sessionRes({}, null));
    expect(await c.getSession()).toBeNull();
    expect(c.peekToken()).toBeNull();
  });

  it("clear() while get-session is in flight ⇒ onSessionToken not called, cache not written", async () => {
    const d = deferred();
    const s = stub(() => d.p);
    const got: string[] = [];
    const c = mk(s.f, { onSessionToken: (t) => got.push(t) });
    const t = track(c.getSession());
    await vi.advanceTimersByTimeAsync(0);
    expect(s.calls).toHaveLength(1);
    c.clear();
    d.resolve(sessionRes({ "set-auth-token": "sess-tok", "set-auth-jwt": fresh() }));
    await vi.advanceTimersByTimeAsync(0);
    expect(t.settled).toBe(true);
    expect(got).toEqual([]);
    expect(c.peekToken()).toBeNull();
  });

  it.each([401, 403])("get-session %i ⇒ null and cache cleared", async (code) => {
    const { c } = await primed(() => status(code));
    expect(await c.getSession()).toBeNull();
    expect(c.peekToken()).toBeNull();
  });

  it.each([
    ["503 with Retry-After", () => status(503, "2"), "unavailable", true],
    ["503 without Retry-After", () => status(503), "unavailable", false],
    ["500", () => status(500), "bad_response", false],
    ["429", () => status(429, "1"), "bad_response", false],
    ["200 not JSON", () => new Response("<html>oops</html>", { status: 200 }), "bad_response", false],
  ] as const)("get-session %s ⇒ %s / retryable %s, 1 request only, no retry", async (_n, r, code, retryable) => {
    const s = stub(() => r());
    const t = track(mk(s.f).getSession());
    await vi.advanceTimersByTimeAsync(30_000);
    expect((t.error as RelytAuthError).code).toBe(code);
    expect((t.error as RelytAuthError).retryable).toBe(retryable);
    expect(s.calls).toHaveLength(1);
  });

  it.each([
    ["garbage", () => "garbage-not-a-jwt-at-all-xxxxxxxx"],
    ["exp−iat = 901", () => fresh(901)],
  ])("set-auth-jwt %s ⇒ ignored, existing cache not overwritten", async (_n, j) => {
    const { A, c, calls } = await primed(() => sessionRes({ "set-auth-jwt": j() }));
    expect(await c.getSession()).toEqual({ session: { id: "s1" }, user: { id: "u1" } });
    expect(c.peekToken()).toBe(A);
    expect(calls).toHaveLength(2);
  });

  it("bearer mode: get-session carries Authorization, credentials omit; sessionToken returns '' ⇒ no Authorization", async () => {
    const s = stub(() => sessionRes({}));
    await mk(s.f, { sessionToken: () => "st" }).getSession();
    expect(new Headers(s.calls[0]!.init.headers).get("authorization")).toBe("Bearer st");
    expect(s.calls[0]!.init.credentials).toBe("omit");
    await mk(s.f, { sessionToken: () => "" }).getSession();
    expect(new Headers(s.calls[1]!.init.headers).get("authorization")).toBeNull();
    expect(s.calls[1]!.init.credentials).toBe("omit");
  });
});

describe("option validation", () => {
  it.each(["https://h.example.com/", "https://h.example.com/auth", "http://evil.example.com", "", "HTTPS://h.example.com"])(
    "authUrl %s ⇒ config",
    (u) => {
      let err: unknown;
      try {
        createAuthClient({ authUrl: u });
      } catch (e) {
        err = e;
      }
      expect((err as RelytAuthError).code).toBe("config");
      expect((err as RelytAuthError).option).toBe("authUrl");
    },
  );
  it.each([
    ["refreshAheadS", 9],
    ["refreshAheadS", 601],
    ["timeoutMs", 999],
    ["timeoutMs", 60_001],
    ["timeoutMs", 1500.5],
    ["refreshAheadS", Number.NaN],
  ])("%s = %s ⇒ config", (k, v) => {
    expect(() => createAuthClient({ authUrl: AUTH, [k]: v })).toThrow(RelytAuthError);
  });
  it("refreshAheadS = 10 / 600, timeoutMs = 1000 / 60000 are valid", () => {
    for (const o of [{ refreshAheadS: 10 }, { refreshAheadS: 600 }, { timeoutMs: 1000 }, { timeoutMs: 60_000 }])
      expect(() => createAuthClient({ authUrl: AUTH, ...o })).not.toThrow();
  });
});

describe("errors and events never contain the token / session token", () => {
  it("retries exhausted, 401 and bad response body paths", async () => {
    const st = Array.from({ length: 40 }, () => "abcdefghijklmnopqrstuvwxyz0123456789"[Math.floor(Math.random() * 36)]).join("");
    const surfaces = (e: unknown) => {
      const x = e as RelytAuthError;
      return [x.message, JSON.stringify(x), String(x.stack ?? ""), JSON.stringify(events)];
    };
    // retries exhausted (503)
    const a = stub(() => status(503, "0"));
    const ta = track(mk(a.f, { sessionToken: () => st }).getToken());
    await vi.advanceTimersByTimeAsync(1_000);
    assertNoLeak(st, surfaces(ta.error));
    // 401
    const { A, c } = await primed(() => status(401), { sessionToken: () => st });
    vi.advanceTimersByTime(781_000);
    const e8 = await expectReject(c.getToken(), "unauthenticated", A, events);
    assertNoLeak(st, surfaces(e8));
    // bad response body: a "token" inside it must not reach the error either
    const junk = `junk-${st}`;
    const n = stub(() => tokenRes(junk));
    const e9 = await expectReject(mk(n.f, { sessionToken: () => st }).getToken(), "bad_response", junk, events);
    assertNoLeak(st, surfaces(e9));
    expect(events.length).toBeGreaterThan(3);
  });
});

describe("status mapping and the sessionToken provider", () => {
  it.each([
    [429, () => status(429, "1")],
    [500, () => status(500)],
    [502, () => status(502)],
    [204, () => new Response(null, { status: 204 })],
  ])("/token %i ⇒ bad_response, retryable false, 1 request only", async (code, r) => {
    const s = stub(() => r());
    const t = track(mk(s.f).getToken());
    await vi.advanceTimersByTimeAsync(30_000);
    const e = t.error as RelytAuthError;
    expect([e.code, e.retryable, e.status]).toEqual(["bad_response", false, code]);
    expect(s.calls).toHaveLength(1);
  });

  const rand40 = () => Array.from({ length: 40 }, () => "abcdefghijklmnopqrstuvwxyz0123456789"[Math.floor(Math.random() * 36)]).join("");

  it.each([
    ["contains CR/LF", (st: string) => () => `x\r\n${st}`],
    ["contains NUL", (st: string) => () => `x\u0000${st}`],
    ["throws synchronously", (st: string) => () => { throw new Error(`boom ${st}`); }],
    ["rejects asynchronously", (st: string) => () => Promise.reject(new Error(`boom ${st}`))],
  ])("sessionToken %s ⇒ unauthenticated, no cause, no leak, no request", async (_n, mkProvider) => {
    const st = rand40();
    const s = stub(() => tokenRes(fresh()));
    const c = mk(s.f, { sessionToken: mkProvider(st) as AuthClientOptions["sessionToken"] });
    const e = await expectReject(c.getToken(), "unauthenticated", st, events);
    expect(e.retryable).toBe(false);
    expect((e as { cause?: unknown }).cause).toBeUndefined();
    assertNoLeak(st, [e.message, JSON.stringify(e), String(e.stack ?? ""), JSON.stringify(events)]);
    expect(s.calls).toHaveLength(0);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("sessionToken never settles ⇒ ends with network after timeoutMs, no request, no timer left", async () => {
    const s = stub(() => tokenRes(fresh()));
    const t = track(mk(s.f, { sessionToken: () => new Promise<string>(() => {}) }).getToken());
    await vi.advanceTimersByTimeAsync(14_999);
    expect(t.settled).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect((t.error as RelytAuthError).code).toBe("network");
    expect(s.calls).toHaveLength(0);
    expect(vi.getTimerCount()).toBe(0);
  });
});
