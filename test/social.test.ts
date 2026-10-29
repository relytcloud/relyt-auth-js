// Cross-site social sign-in helpers. Hand-written fake location / history / sessionStorage; WebCrypto is Node's real implementation.
import { createServer, type IncomingHttpHeaders } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { RelytAuthError } from "../src/errors.js";
import {
  SOCIAL_PKCE_STORAGE_KEY as KEY,
  completeSocialSignIn,
  createSocialStart,
  exchangeHandoffCode,
  startSocialSignIn,
} from "../src/social.js";
import { assertNoLeak } from "./helpers/expect.js";

const AUTH = "https://t1.auth.example.com";
const APP = "https://app.example.com/cb";
// RFC 7636 Appendix B (expected values taken from the RFC text, not from the code under test).
const RFC_OCTETS = [116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173, 187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83, 132, 141, 121];
const RFC_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const RFC_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const CODE = "C0deC0deC0deC0deC0deC0deC0deC0deC0deC0deC0d"; // 43 chars
const VERIFIER = "VerifierVerifierVerifierVerifierVerifier123"; // 43 chars
const TOKEN = "sessTokenSecretValue-0123456789abcdef";
expect(CODE).toHaveLength(43);
expect(VERIFIER).toHaveLength(43);

let log: string[];
let store: Map<string, string>;
let loc: { href: string; assign: (u: string) => void };
let assigned: string[];

function env(href: string) {
  log = [];
  store = new Map();
  assigned = [];
  loc = { href, assign: (u: string) => (log.push("assign"), assigned.push(u)) };
  vi.stubGlobal("location", loc);
  vi.stubGlobal("history", {
    state: { s: 1 },
    replaceState: (_s: unknown, _t: string, u: string) => {
      log.push("replace");
      loc.href = u;
    },
  });
  vi.stubGlobal("sessionStorage", {
    getItem: (k: string) => store.get(k) ?? null,
    setItem: (k: string, v: string) => void store.set(k, v),
    removeItem: (k: string) => (log.push("remove"), void store.delete(k)),
  });
}
const TTL_MS = 10 * 60 * 1000; // pending-record lifetime, written out independently of the implementation
const pend = (mode = "fragment", v = VERIFIER, extra: Record<string, unknown> = {}) =>
  store.set(KEY, JSON.stringify({ v, mode, base: AUTH, t: Date.now(), ...extra }));

interface Call { url: string; init: RequestInit }
function stub(mk: () => Response | Promise<Response>) {
  const calls: Call[] = [];
  const f = (async (input: RequestInfo | URL, init: RequestInit = {}) => {
    log.push("fetch");
    calls.push({ url: String(input), init });
    return mk();
  }) as typeof fetch;
  return { f, calls };
}
const ok = () => new Response("{}", { status: 200, headers: { "set-auth-token": TOKEN } });

async function rejects(p: Promise<unknown>, code: string): Promise<RelytAuthError> {
  let e: unknown;
  try {
    await p;
  } catch (x) {
    e = x;
  }
  expect(e).toBeInstanceOf(RelytAuthError);
  const r = e as RelytAuthError;
  expect(r.code).toBe(code);
  for (const secret of [CODE, VERIFIER, TOKEN, RFC_VERIFIER]) {
    assertNoLeak(secret, [r.message, JSON.stringify(r), String((r as { cause?: unknown }).cause ?? ""), String(r.stack ?? "")]);
  }
  return r;
}

beforeEach(() => env(APP));
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("startSocialSignIn", () => {
  it("RFC 7636 Appendix B vector: stored verifier and the S256 challenge in the URL", async () => {
    vi.spyOn(globalThis.crypto, "getRandomValues").mockImplementation(<T extends ArrayBufferView | null>(a: T): T => {
      (a as unknown as Uint8Array).set(RFC_OCTETS);
      return a;
    });
    await startSocialSignIn({ authUrl: AUTH, provider: "google", callbackURL: APP });
    const before = Date.now();
    const rec0 = JSON.parse(store.get(KEY)!);
    expect(rec0).toEqual({ v: RFC_VERIFIER, mode: "fragment", base: AUTH, t: expect.any(Number) });
    expect(rec0.t).toBeGreaterThan(before - 60_000);
    expect(rec0.t).toBeLessThanOrEqual(before);
    const q = new URL(assigned[0]!).searchParams;
    expect(q.get("code_challenge")).toBe(RFC_CHALLENGE);
    expect(q.get("code_challenge_method")).toBe("S256");
  });

  it("URL shape: prefix, each parameter exactly once, unset optionals absent, fragment by default; real randomness", async () => {
    await startSocialSignIn({ authUrl: AUTH, provider: "github", callbackURL: APP });
    expect(assigned).toHaveLength(1);
    expect(assigned[0]!.startsWith(`${AUTH}/api/auth/relyt/social/start?`)).toBe(true);
    const q = new URL(assigned[0]!).searchParams;
    expect([...new Set(q.keys())].sort()).toEqual(["callbackURL", "code_challenge", "code_challenge_method", "provider", "response_mode"]);
    for (const k of q.keys()) expect(q.getAll(k), k).toHaveLength(1);
    expect(q.get("provider")).toBe("github");
    expect(q.get("callbackURL")).toBe(APP);
    expect(q.get("response_mode")).toBe("fragment");
    const v1 = JSON.parse(store.get(KEY)!).v as string;
    expect(v1).toMatch(/^[A-Za-z0-9_-]{43}$/);

    await startSocialSignIn({
      authUrl: AUTH, provider: "google", callbackURL: APP, errorCallbackURL: `${APP}/err`, newUserCallbackURL: `${APP}/new`, responseMode: "query",
    });
    const q2 = new URL(assigned[1]!).searchParams;
    for (const k of q2.keys()) expect(q2.getAll(k), k).toHaveLength(1);
    expect(q2.get("errorCallbackURL")).toBe(`${APP}/err`);
    expect(q2.get("newUserCallbackURL")).toBe(`${APP}/new`);
    expect(q2.get("response_mode")).toBe("query");
    const rec = JSON.parse(store.get(KEY)!);
    expect(rec.mode).toBe("query");
    expect(rec.v).not.toBe(v1);
    // the challenge matches the stored verifier (recomputed independently with WebCrypto)
    const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rec.v)));
    expect(q2.get("code_challenge")).toBe(Buffer.from(d).toString("base64url"));
  });

  it("config error: no navigation, nothing stored", async () => {
    const bad: Array<[Record<string, unknown>, string]> = [
      [{ authUrl: "https://t1.auth.example.com/", provider: "google", callbackURL: APP }, "authUrl"],
      [{ authUrl: AUTH, provider: "", callbackURL: APP }, "provider"],
      [{ authUrl: AUTH, provider: "google" }, "callbackURL"],
      [{ authUrl: AUTH, provider: "google", callbackURL: APP, responseMode: "form_post" }, "responseMode"],
    ];
    for (const [o, option] of bad) {
      const e = await rejects(startSocialSignIn(o as never), "config");
      expect(e.option).toBe(option);
    }
    expect(assigned).toEqual([]);
    expect(store.size).toBe(0);
  });
});

describe("createSocialStart (pure builder)", () => {
  const rfc = () =>
    vi.spyOn(globalThis.crypto, "getRandomValues").mockImplementation(<T extends ArrayBufferView | null>(a: T): T => {
      (a as unknown as Uint8Array).set(RFC_OCTETS);
      return a;
    });

  it("RFC vector + works without browser globals (Node): touches no storage, does not navigate", async () => {
    rfc();
    vi.stubGlobal("sessionStorage", undefined);
    vi.stubGlobal("location", undefined);
    const r = await createSocialStart({ authUrl: AUTH, provider: "google", callbackURL: APP });
    expect(r.codeVerifier).toBe(RFC_VERIFIER);
    expect(r.url.startsWith(`${AUTH}/api/auth/relyt/social/start?`)).toBe(true);
    const q = new URL(r.url).searchParams;
    expect(q.get("code_challenge")).toBe(RFC_CHALLENGE);
    expect(q.get("code_challenge_method")).toBe("S256");
    expect([...new Set(q.keys())].sort()).toEqual(["callbackURL", "code_challenge", "code_challenge_method", "provider", "response_mode"]);
    for (const k of q.keys()) expect(q.getAll(k), k).toHaveLength(1);
    expect(q.get("provider")).toBe("google");
    expect(q.get("callbackURL")).toBe(APP);
    expect(q.get("response_mode")).toBe("fragment");
    expect(assigned).toEqual([]);
    expect(store.size).toBe(0);
  });

  it("verbatim equivalent to startSocialSignIn: one optional parameter at a time", async () => {
    rfc();
    const variants: Array<[Record<string, string>, string, string]> = [
      [{ errorCallbackURL: `${APP}/err` }, "errorCallbackURL", `${APP}/err`],
      [{ newUserCallbackURL: `${APP}/new` }, "newUserCallbackURL", `${APP}/new`],
      [{ responseMode: "query" }, "response_mode", "query"],
    ];
    for (const [extra, key, want] of variants) {
      env(APP);
      const o = { authUrl: AUTH, provider: "github", callbackURL: APP, ...extra };
      const r = await createSocialStart(o as never);
      await startSocialSignIn(o as never);
      expect(assigned).toEqual([r.url]);
      expect(JSON.parse(store.get(KEY)!).v).toBe(r.codeVerifier);
      const q = new URL(r.url).searchParams;
      expect(q.getAll(key), key).toEqual([want]);
      for (const k of q.keys()) expect(q.getAll(k), k).toHaveLength(1);
    }
  });

  it("config errors still report the option", async () => {
    const e = await rejects(createSocialStart({ authUrl: AUTH, provider: "google", callbackURL: APP, responseMode: "form_post" } as never), "config");
    expect(e.option).toBe("responseMode");
  });
});

describe("completeSocialSignIn", () => {
  it("fragment: replaceState before fetch; request shape; clear before delivering the token", async () => {
    env(`${APP}?keep=1#relyt_code=${CODE}`);
    pend();
    const s = stub(ok);
    const got: string[] = [];
    const client = { clear: () => log.push("clear"), getToken: vi.fn(), peekToken: vi.fn(), getSession: vi.fn() };
    await completeSocialSignIn({ authUrl: AUTH, fetch: s.f, client, onSessionToken: (t) => (log.push("token"), got.push(t)) });
    expect(log.indexOf("replace")).toBeGreaterThanOrEqual(0);
    expect(log.indexOf("replace")).toBeLessThan(log.indexOf("remove"));
    expect(log.indexOf("replace")).toBeLessThan(log.indexOf("fetch"));
    expect(log.filter((x) => x === "clear")).toHaveLength(1); // non-vacuity: if indexOf were -1 the next line would always pass
    expect(log.indexOf("clear")).toBeLessThan(log.indexOf("token"));
    expect(loc.href).toBe(`${APP}?keep=1`);
    expect(s.calls).toHaveLength(1);
    const { url, init } = s.calls[0]!;
    expect(url).toBe(`${AUTH}/api/auth/relyt/exchange`);
    expect(init.method).toBe("POST");
    expect(init.credentials).toBe("omit");
    expect(new Headers(init.headers).has("origin")).toBe(false);
    expect(JSON.parse(String(init.body))).toEqual({ code: CODE, code_verifier: VERIFIER });
    expect(got).toEqual([TOKEN]);
  });

  it("single use: storage empty after completion, calling again on the same URL does not exchange again", async () => {
    env(`${APP}#relyt_code=${CODE}`);
    pend();
    const s = stub(ok);
    await completeSocialSignIn({ authUrl: AUTH, fetch: s.f, onSessionToken: () => {} });
    expect(store.has(KEY)).toBe(false);
    loc.href = `${APP}#relyt_code=${CODE}`;
    await rejects(completeSocialSignIn({ authUrl: AUTH, fetch: s.f, onSessionToken: () => {} }), "no_pending_sign_in");
    expect(s.calls).toHaveLength(1);
  });

  it("two concurrent calls (React StrictMode) ⇒ 1 fetch, both succeed, token delivered once", async () => {
    env(`${APP}#relyt_code=${CODE}`);
    pend();
    const s = stub(ok);
    const tok = vi.fn();
    const p1 = completeSocialSignIn({ authUrl: AUTH, fetch: s.f, onSessionToken: tok });
    const p2 = completeSocialSignIn({ authUrl: AUTH, fetch: s.f, onSessionToken: tok });
    await expect(Promise.all([p1, p2])).resolves.toEqual([undefined, undefined]);
    expect(s.calls).toHaveLength(1);
    expect(tok).toHaveBeenCalledTimes(1);
    expect(tok).toHaveBeenCalledWith(TOKEN);
    // reset in finally: a later call is a brand-new call (no record ⇒ no_pending_sign_in), not a reuse of the old promise
    loc.href = `${APP}#relyt_code=${CODE}`;
    await rejects(completeSocialSignIn({ authUrl: AUTH, fetch: s.f, onSessionToken: tok }), "no_pending_sign_in");
    expect(s.calls).toHaveLength(1);
  });

  it("no stored verifier ⇒ no request, address bar still cleaned", async () => {
    env(`${APP}#relyt_code=${CODE}`);
    const s = stub(ok);
    const tok = vi.fn();
    await rejects(completeSocialSignIn({ authUrl: AUTH, fetch: s.f, onSessionToken: tok }), "no_pending_sign_in");
    expect(s.calls).toHaveLength(0);
    expect(tok).not.toHaveBeenCalled();
    expect(log).toContain("replace");
    expect(loc.href).toBe(APP);
  });

  it("query mode reads the query; mode mismatch / duplicate / malformed ⇒ missing_code and 0 fetches", async () => {
    env(`${APP}?relyt_code=${CODE}&x=2`);
    pend("query");
    const s = stub(ok);
    await completeSocialSignIn({ authUrl: AUTH, fetch: s.f, onSessionToken: () => {} });
    expect(s.calls).toHaveLength(1);
    expect(loc.href).toBe(`${APP}?x=2`);

    const s2 = stub(ok);
    for (const [href, mode] of [
      [`${APP}?relyt_code=${CODE}`, "fragment"],
      [`${APP}#relyt_code=${CODE}`, "query"],
      [`${APP}#relyt_code=${CODE}&relyt_code=${CODE}`, "fragment"],
      [`${APP}#relyt_code=${CODE}x`, "fragment"],
      [`${APP}#relyt_code=${CODE.slice(0, 42)}!`, "fragment"],
    ] as const) {
      env(href);
      pend(mode);
      await rejects(completeSocialSignIn({ authUrl: AUTH, fetch: s2.f, onSessionToken: () => {} }), "missing_code");
      expect(loc.href).not.toContain("relyt_code");
      expect(store.has(KEY)).toBe(false);
    }
    expect(s2.calls).toHaveLength(0);
  });

  it("error callback ⇒ oauth_error (value filtered), record removed, 0 fetches", async () => {
    const s = stub(ok);
    for (const [raw, want] of [["access_denied", "access_denied"], ["<script>", "unknown"], ["A".repeat(10), "unknown"]] as const) {
      env(`${APP}/err?error=${encodeURIComponent(raw)}&keep=1`);
      pend();
      const e = await rejects(completeSocialSignIn({ authUrl: AUTH, fetch: s.f, onSessionToken: () => {} }), "oauth_error");
      expect(e.oauthError).toBe(want);
      expect(store.has(KEY)).toBe(false);
      expect(loc.href).toBe(`${APP}/err?keep=1`);
    }
    expect(s.calls).toHaveLength(0);
  });

  it("error_description is removed from both query and fragment", async () => {
    const s = stub(ok);
    for (const href of [
      `${APP}/err?error=access_denied&error_description=Bad%20thing&keep=1`,
      `${APP}/err?keep=1#error=access_denied&error_description=Bad%20thing`,
    ]) {
      env(href);
      pend();
      await rejects(completeSocialSignIn({ authUrl: AUTH, fetch: s.f, onSessionToken: () => {} }), "oauth_error");
      expect(loc.href).toBe(`${APP}/err?keep=1`);
    }
    expect(s.calls).toHaveLength(0);
  });

  it("record with mismatched / missing base or older than 10 minutes ⇒ no_pending_sign_in, 0 fetches", async () => {
    const s = stub(ok);
    for (const extra of [{ base: "https://t2.auth.example.com" }, { base: undefined }, { t: Date.now() - TTL_MS - 1_000 }, { t: "x" }]) {
      env(`${APP}#relyt_code=${CODE}`);
      pend("fragment", VERIFIER, extra);
      await rejects(completeSocialSignIn({ authUrl: AUTH, fetch: s.f, onSessionToken: () => {} }), "no_pending_sign_in");
      expect(store.has(KEY)).toBe(false);
      expect(loc.href).toBe(APP);
    }
    expect(s.calls).toHaveLength(0);
    // non-vacuity: a record of the same shape, unexpired and with a matching base, does exchange
    env(`${APP}#relyt_code=${CODE}`);
    pend("fragment", VERIFIER, { t: Date.now() - TTL_MS + 5_000 });
    await completeSocialSignIn({ authUrl: AUTH, fetch: s.f, onSessionToken: () => {} });
    expect(s.calls).toHaveLength(1);
  });

  it("status mapping, exactly 1 fetch each (no retry)", async () => {
    const cases: Array<[() => Response | Promise<Response>, string, Partial<RelytAuthError>]> = [
      [() => new Response('{"code":"INVALID_HANDOFF_CODE"}', { status: 400 }), "invalid_handoff_code", { status: 400 }],
      [() => new Response('{"code":"INVALID_ORIGIN"}', { status: 403 }), "invalid_origin", { status: 403 }],
      [() => new Response("{}", { status: 429, headers: { "retry-after": "7" } }), "rate_limited", { retryAfterS: 7 }],
      // same parser as client.ts retryAfterMs (invalid ⇒ 2 s, clamped to ≤ 10 s, IMF-fixdate); header missing ⇒ undefined
      [() => new Response("{}", { status: 429, headers: { "retry-after": "soon" } }), "rate_limited", { retryAfterS: 2 }],
      [() => new Response("{}", { status: 429, headers: { "retry-after": "120" } }), "rate_limited", { retryAfterS: 10 }],
      [() => new Response("{}", { status: 429 }), "rate_limited", { retryAfterS: undefined }],
      [() => new Response("{}", { status: 503, headers: { "retry-after": "1" } }), "unavailable", { status: 503 }],
      [() => new Response("{}", { status: 500 }), "bad_response", { status: 500 }],
      [() => new Response("{}", { status: 200 }), "bad_response", { status: 200 }],
      [() => Promise.reject(new TypeError(`failed ${CODE} ${VERIFIER}`)), "network", {}],
    ];
    for (const [mk, code, extra] of cases) {
      env(`${APP}#relyt_code=${CODE}`);
      pend();
      const s = stub(mk);
      const tok = vi.fn();
      const e = await rejects(completeSocialSignIn({ authUrl: AUTH, fetch: s.f, onSessionToken: tok }), code);
      for (const [k, v] of Object.entries(extra)) expect((e as unknown as Record<string, unknown>)[k], `${code}.${k}`).toBe(v);
      expect(e.retryable).toBe(false);
      expect(s.calls, code).toHaveLength(1);
      expect(tok).not.toHaveBeenCalled();
    }
  });

  it("timeout ⇒ network (1 fetch)", async () => {
    env(`${APP}#relyt_code=${CODE}`);
    pend();
    const s = stub(() => new Promise<Response>(() => {}));
    const hang = (async (input: RequestInfo | URL, init: RequestInit = {}) => {
      void s.f(input, init);
      return new Promise<Response>((_, rej) => init.signal?.addEventListener("abort", () => rej(new DOMException("t", "AbortError"))));
    }) as typeof fetch;
    await rejects(completeSocialSignIn({ authUrl: AUTH, fetch: hang, timeoutMs: 1_000, onSessionToken: () => {} }), "network");
    expect(s.calls).toHaveLength(1);
  });

  it("config: onSessionToken is required", async () => {
    env(`${APP}#relyt_code=${CODE}`);
    pend();
    const e = await rejects(completeSocialSignIn({ authUrl: AUTH } as never), "config");
    expect(e.option).toBe("onSessionToken");
    // clean the address bar first, then validate options: a config error must not leave the code in the address bar
    expect(loc.href).toBe(APP);
    expect(log).toContain("replace");
  });
});

describe("exchangeHandoffCode (server-side proxy)", () => {
  it("real node:http: POST, no origin header, JSON body, returns the token", async () => {
    let seen: { method?: string; headers?: IncomingHttpHeaders; body?: string } = {};
    const srv = createServer((req, res) => {
      let b = "";
      req.on("data", (c) => (b += c));
      req.on("end", () => {
        seen = { method: req.method, headers: req.headers, body: b };
        res.setHeader("set-auth-token", TOKEN);
        res.end("{}");
      });
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    try {
      const port = (srv.address() as AddressInfo).port;
      const r = await exchangeHandoffCode({ authUrl: `http://localhost:${port}`, code: CODE, codeVerifier: VERIFIER });
      expect(r).toEqual({ sessionToken: TOKEN });
      expect(seen.method).toBe("POST");
      expect(seen.headers && "origin" in seen.headers).toBe(false);
      expect(seen.headers?.["content-type"]).toBe("application/json");
      expect(JSON.parse(seen.body!)).toEqual({ code: CODE, code_verifier: VERIFIER });
    } finally {
      await new Promise((r) => srv.close(r));
    }
  });

  it("error mapping and config validation", async () => {
    const s = stub(() => new Response("{}", { status: 400 }));
    await rejects(exchangeHandoffCode({ authUrl: AUTH, code: CODE, codeVerifier: VERIFIER, fetch: s.f }), "invalid_handoff_code");
    expect(s.calls).toHaveLength(1);
    expect((await rejects(exchangeHandoffCode({ authUrl: AUTH, code: "", codeVerifier: VERIFIER, fetch: s.f }), "config")).option).toBe("code");
    expect((await rejects(exchangeHandoffCode({ authUrl: AUTH, code: CODE, codeVerifier: "", fetch: s.f }), "config")).option).toBe("codeVerifier");
    expect(s.calls).toHaveLength(1);
  });
});
