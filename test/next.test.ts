// @relyt/auth/next. Driven by real NextRequest / NextResponse, real keys and signatures, and a local JWKS server.
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { NextRequest, NextResponse } from "next/server.js";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { RelytAuthError, type AuthEvent } from "../src/errors.js";
import { TOKEN_TTL_S } from "../src/constants.js";
import {
  DEFAULT_COOKIE_NAME,
  RelytAuthUnavailableError,
  clearTokenCookie,
  createAuthMiddleware,
  getClaims,
  safeNext,
  setTokenCookie,
  type AuthMiddlewareOptions,
} from "../src/next.js";
import { assertNoLeak } from "./helpers/expect.js";
import { b64u, baseClaims, closeAll, issuerFixture, nowS, sign, type IssuerFixture } from "./helpers/issuer.js";

const APP = "https://app.example";
const SIGN_IN = "https://app.example/sign-in";
const C = "__Host-relyt-at";

let fx: IssuerFixture;
let down: IssuerFixture;
let good: string;
let other: string;

beforeAll(async () => {
  fx = await issuerFixture();
  down = await issuerFixture();
  down.setMode("500");
  good = await sign(fx);
  other = await sign(fx, undefined, { sub: "user-2" });
});
afterAll(closeAll);
afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

const opts = (o: Partial<AuthMiddlewareOptions> = {}): AuthMiddlewareOptions => ({ issuer: fx.issuer, signInUrl: SIGN_IN, ...o });
const req = (path: string, h: Record<string, string> = {}, method = "GET") => new NextRequest(APP + path, { headers: h, method });
const overrides = (r: Response) => (r.headers.get("x-middleware-override-headers") ?? "").split(",").filter(Boolean);
const hdrs = (r: Response) => { const a: Array<[string, string]> = []; r.headers.forEach((v, k) => a.push([k, v])); return a; };
const passed = (r: Response) => r.headers.get("x-middleware-next") === "1";

async function expect401(r: Response, wwwAuth: string): Promise<void> {
  expect(r.status).toBe(401);
  expect(await r.clone().json()).toEqual({ error: "unauthorized" });
  expect(r.headers.get("www-authenticate")).toBe(wwwAuth);
  expect(r.headers.get("cache-control")).toBe("no-store"); // auth failure responses are never cacheable
}

describe("bearer", () => {
  it("valid bearer ⇒ passes, x-relyt-claims not forwarded; getClaims gets the same sub", async () => {
    const r = await createAuthMiddleware(opts())(req("/api/x", { authorization: `Bearer ${good}` }));
    expect(passed(r)).toBe(true);
    expect(r.status).toBe(200);
    expect(overrides(r)).toContain("authorization"); // non-vacuity: the override list is really there
    expect([...overrides(r), ...hdrs(r).map(([k]) => k)].filter((k) => k.includes("x-relyt"))).toEqual([]);
    const c = await getClaims(req("/api/x", { authorization: `Bearer ${good}` }), { issuer: fx.issuer });
    expect(c?.sub).toBe("user-1");
  });
});

describe("cookie", () => {
  it("cookie only ⇒ passes; cookieName is honoured", async () => {
    expect(passed(await createAuthMiddleware(opts())(req("/dash", { cookie: `${C}=${good}` })))).toBe(true);
    expect(passed(await createAuthMiddleware(opts({ cookieName: "x" }))(req("/api/a", { cookie: `x=${good}` })))).toBe(true);
    // with cookieName:"x" the default name is no longer read
    await expect401(await createAuthMiddleware(opts({ cookieName: "x" }))(req("/api/a", { cookie: `${C}=${good}` })), "Bearer");
  });
  it("same cookie name twice ⇒ treated as no token (middleware and getClaims)", async () => {
    const cookie = `a=1; ${C}=${good}; ${C}=${other}`;
    await expect401(await createAuthMiddleware(opts())(req("/api/x", { cookie })), "Bearer");
    expect(await getClaims(req("/api/x", { cookie }), { issuer: fx.issuer })).toBeNull();
    // control: removing the duplicate lets it pass
    expect(passed(await createAuthMiddleware(opts())(req("/api/x", { cookie: `a=1; ${C}=${good}` })))).toBe(true);
  });
  it("cookieOnApi:false ⇒ API accepts bearer only, pages still accept the cookie; default true", async () => {
    const mw = createAuthMiddleware(opts({ cookieOnApi: false }));
    await expect401(await mw(req("/api/x", { cookie: `${C}=${good}` })), "Bearer");
    expect(passed(await mw(req("/api/x", { authorization: `Bearer ${good}` })))).toBe(true);
    expect(passed(await mw(req("/dash", { cookie: `${C}=${good}` })))).toBe(true);
    expect(passed(await createAuthMiddleware(opts())(req("/api/x", { cookie: `${C}=${good}` })))).toBe(true);
  });
});

describe("header takes precedence", () => {
  it("header and cookie differ ⇒ header used", async () => {
    const h = { authorization: `Bearer ${other}`, cookie: `${C}=${good}` };
    expect((await getClaims(req("/api/x", h), { issuer: fx.issuer }))?.sub).toBe("user-2");
    // bad header, good cookie ⇒ still judged by the header (401 invalid_token), no fallback to the cookie
    await expect401(await createAuthMiddleware(opts())(req("/api/x", { authorization: "Bearer bad.bad.bad", cookie: `${C}=${good}` })), 'Bearer error="invalid_token"');
  });
});

describe("a present Authorization header is authoritative", () => {
  it.each(["Basic dXNlcjpwYXNz", "Bearer", "Bearer a b", "", "token x"])("authorization=%j + valid cookie ⇒ no token, no fallback to the cookie", async (a) => {
    const h = { authorization: a, cookie: `${C}=${good}` };
    expect(passed(await createAuthMiddleware(opts())(req("/dash", h)))).toBe(false);
    expect((await createAuthMiddleware(opts())(req("/dash", h))).status).toBe(307);
    await expect401(await createAuthMiddleware(opts())(req("/api/x", h)), "Bearer");
    expect(await getClaims(req("/x", h), { issuer: fx.issuer })).toBeNull();
  });
  it("control: no Authorization header ⇒ the cookie is used", async () => {
    expect(passed(await createAuthMiddleware(opts())(req("/dash", { cookie: `${C}=${good}` })))).toBe(true);
  });
});

describe("failure responses", () => {
  it("API: no token ⇒ exactly Bearer; bad token ⇒ invalid_token; Accept json also counts as API", async () => {
    const mw = createAuthMiddleware(opts());
    await expect401(await mw(req("/api/x")), "Bearer");
    await expect401(await mw(req("/api/x", { authorization: "Bearer abc.def.ghi" })), 'Bearer error="invalid_token"');
    await expect401(await mw(req("/dash", { accept: "application/json" })), "Bearer");
  });
  it("pages: GET 307, HEAD 307, POST 303, next is a relative path", async () => {
    const mw = createAuthMiddleware(opts());
    const g = await mw(req("/dash?a=1"));
    expect(g.status).toBe(307);
    expect(g.headers.get("location")).toBe(`${SIGN_IN}?next=%2Fdash%3Fa%3D1`);
    expect(g.headers.get("cache-control")).toBe("no-store"); // auth failure responses are never cacheable
    expect((await mw(req("/dash", {}, "HEAD"))).status).toBe(307);
    const p = await mw(req("/dash", {}, "POST"));
    expect(p.status).toBe(303);
    expect(p.headers.get("location")).toBe(`${SIGN_IN}?next=%2Fdash`);
    expect(p.headers.get("cache-control")).toBe("no-store");
  });
  it("relative signInUrl ⇒ resolved to an absolute URL against the request URL", async () => {
    const r = await createAuthMiddleware(opts({ signInUrl: "/sign-in" }))(req("/dash"));
    expect(r.headers.get("location")).toBe(`${APP}/sign-in?next=%2Fdash`);
  });
});

describe("apiPrefix also matches the bare path", () => {
  it("/api ⇒ 401; /apix ⇒ 307; with apiPrefix /v1/, /v1 ⇒ 401", async () => {
    await expect401(await createAuthMiddleware(opts())(req("/api")), "Bearer");
    expect((await createAuthMiddleware(opts())(req("/apix"))).status).toBe(307);
    await expect401(await createAuthMiddleware(opts({ apiPrefix: "/v1/" }))(req("/v1")), "Bearer");
  });
});

describe("x-relyt-* stripped", () => {
  const forged = { "x-relyt-claims": b64u(JSON.stringify({ sub: "admin" })), "X-Relyt-Foo": "1", "x-other": "keep" };
  it("valid token ⇒ the override list contains no x-relyt-*", async () => {
    const r = await createAuthMiddleware(opts())(req("/api/x", { ...forged, authorization: `Bearer ${good}` }));
    expect(passed(r)).toBe(true);
    expect(overrides(r)).toContain("x-other");
    expect(overrides(r).filter((k) => k.startsWith("x-relyt-"))).toEqual([]);
    expect(r.headers.get("x-middleware-request-x-relyt-claims")).toBeNull();
  });
  it("public path ⇒ passes and x-relyt-* is removed (present on the original request)", async () => {
    const q = req("/public/a", forged);
    expect(q.headers.get("x-relyt-claims")).not.toBeNull();
    const r = await createAuthMiddleware(opts({ publicPaths: ["/public"] }))(q);
    expect(passed(r)).toBe(true);
    expect(overrides(r)).toContain("x-other");
    expect(overrides(r).filter((k) => k.startsWith("x-relyt-"))).toEqual([]);
  });
});

describe("failure reasons are not distinguished", () => {
  it.each([
    ["expired", { exp: nowS() - 600, iat: nowS() - 900 }],
    ["other tenant", { iss: "https://other.example", aud: "https://other.example" }],
  ])("%s ⇒ 401 invalid_token / page 307", async (_n, o) => {
    const t = await sign(fx, undefined, o);
    const mw = createAuthMiddleware(opts());
    const a = await mw(req("/api/x", { authorization: `Bearer ${t}` }));
    await expect401(a, 'Bearer error="invalid_token"');
    expect((await mw(req("/dash", { cookie: `${C}=${t}` }))).status).toBe(307);
  });
  it("HS256 ⇒ 401", async () => {
    const hs = `${b64u(JSON.stringify({ alg: "HS256", kid: "kid1" }))}.${b64u(JSON.stringify({ sub: "x", iss: fx.issuer, aud: fx.issuer }))}.${b64u("sig-sig-sig")}`;
    await expect401(await createAuthMiddleware(opts())(req("/api/x", { authorization: `Bearer ${hs}` })), 'Bearer error="invalid_token"');
  });
});

describe("JWKS unavailable", () => {
  it("both API and pages get 503 + retry-after: 2", async () => {
    const t = await sign(down);
    const mw = createAuthMiddleware(opts({ issuer: down.issuer }));
    for (const r of [await mw(req("/api/x", { authorization: `Bearer ${t}` })), await mw(req("/dash", { cookie: `${C}=${t}` }))]) {
      expect(r.status).toBe(503);
      expect(r.headers.get("retry-after")).toBe("2");
      expect(r.headers.get("cache-control")).toBe("no-store"); // auth failure responses are never cacheable
      expect(await r.json()).toEqual({ error: "auth_unavailable" });
    }
  });
});

describe("open redirect", () => {
  it.each(["//evil.com/x", "/\\evil.com", "/%2F%2Fevil.com", "/%5Cevil.com", "/%E0%A4%A"])("%s ⇒ next=/", async (p) => {
    const r = await createAuthMiddleware(opts())(new NextRequest(APP + p));
    expect(r.status).toBe(307);
    const loc = new URL(r.headers.get("location")!);
    expect(loc.origin + loc.pathname).toBe(SIGN_IN);
    expect(loc.searchParams.get("next")).toBe("/");
  });
  it.each(["/\t/evil.com", "/\n/evil.com", "/%09/evil.com", "/%0d%0a/evil.com", "/\\evil.com", "//evil.com"])("safeNext(%j) called directly ⇒ /", (p) => {
    expect(safeNext(p)).toBe("/");
  });
  it.each(["/a\tb", "/a%00b", "/a%7Fb", "/a%1Fb"])("safeNext(%j) called directly: same-origin but contains a control character ⇒ / (pins the control-character check on its own)", (p) => {
    expect(safeNext(p)).toBe("/");
  });
  it.each(["/docs/my%20page", "/a b", "/ /evil.com"])("safeNext(%j) called directly: a space is not a control character, kept as-is and still same-origin after parsing", (p) => {
    expect(safeNext(p)).toBe(p);
    expect(new URL(safeNext(p), "https://app.example").origin).toBe("https://app.example");
  });
  it("direct-call control: a same-origin relative path is kept as-is", () => {
    expect(safeNext("/a/b?c=1")).toBe("/a/b?c=1");
  });
  it("control: /a/b?c=1 kept as-is; a query string on signInUrl is preserved", async () => {
    const r = await createAuthMiddleware(opts({ signInUrl: `${SIGN_IN}?x=1` }))(req("/a/b?c=1"));
    const loc = new URL(r.headers.get("location")!);
    expect(loc.searchParams.get("x")).toBe("1");
    expect(loc.searchParams.get("next")).toBe("/a/b?c=1");
  });
});

describe("getClaims", () => {
  it("bearer / cookie ⇒ claims; missing / bad / other tenant ⇒ null", async () => {
    const o = { issuer: fx.issuer };
    expect((await getClaims(req("/x", { authorization: `Bearer ${good}` }), o))?.sub).toBe("user-1");
    expect((await getClaims(new Request(APP + "/x", { headers: { cookie: `${C}=${good}` } }), o))?.sub).toBe("user-1");
    expect(await getClaims(req("/x"), o)).toBeNull();
    expect(await getClaims(req("/x", { authorization: "Bearer a.b.c" }), o)).toBeNull();
    const foreign = await sign(fx, undefined, { iss: "https://other.example" });
    expect(await getClaims(req("/x", { authorization: `Bearer ${foreign}` }), o)).toBeNull();
  });
  it("JWKS unavailable: throws RelytAuthUnavailableError by default; onUnavailable:null ⇒ null; both emit events", async () => {
    const t = await sign(down);
    const ev: AuthEvent[] = [];
    const o = { issuer: down.issuer, onEvent: (e: AuthEvent) => ev.push(e) };
    const q = () => req("/x", { authorization: `Bearer ${t}` });
    let err: unknown;
    await getClaims(q(), o).catch((e) => (err = e));
    expect(err).toBeInstanceOf(RelytAuthUnavailableError);
    expect(err).toBeInstanceOf(RelytAuthError);
    expect((err as RelytAuthError).code).toBe("jwks_unavailable");
    expect(await getClaims(q(), o, { onUnavailable: "null" })).toBeNull();
    expect(ev.filter((e) => e.code === "jwks_unavailable")).toHaveLength(2);
    assertNoLeak(t, [JSON.stringify(err), String((err as Error).message), JSON.stringify(ev)]);
  });
  it("shares the remote key set with the middleware: getClaims adds no JWKS requests", async () => {
    const f = await issuerFixture();
    const t = await sign(f);
    expect(passed(await createAuthMiddleware(opts({ issuer: f.issuer }))(req("/x", { authorization: `Bearer ${t}` })))).toBe(true);
    const n = f.requests();
    expect(n).toBeGreaterThan(0);
    expect((await getClaims(req("/x", { authorization: `Bearer ${t}` }), { issuer: f.issuer }))?.sub).toBe("user-1");
    expect(f.requests()).toBe(n);
  });
  it("config errors still throw config (not swallowed as null)", async () => {
    await expect(getClaims(req("/x", { authorization: `Bearer ${good}` }), { issuer: "https://x.example/" })).rejects.toMatchObject({ code: "config" });
  });
});

describe("tokens without kid (documented in the README)", () => {
  it("while two keys overlap ⇒ rejected (null / 401); accepted with a single key (non-vacuity)", async () => {
    const two = await issuerFixture({ kids: ["k1", "k2"] });
    const t2 = await sign(two, undefined, { kid: "k1", header: { kid: undefined } });
    expect(JSON.parse(Buffer.from(t2.split(".")[0]!, "base64url").toString()).kid).toBeUndefined();
    expect(await getClaims(req("/x", { authorization: `Bearer ${t2}` }), { issuer: two.issuer })).toBeNull();
    await expect401(await createAuthMiddleware(opts({ issuer: two.issuer }))(req("/api/x", { authorization: `Bearer ${t2}` })), 'Bearer error="invalid_token"');
    const one = await issuerFixture();
    const t1 = await sign(one, undefined, { header: { kid: undefined } });
    expect((await getClaims(req("/x", { authorization: `Bearer ${t1}` }), { issuer: one.issuer }))?.sub).toBe("user-1");
  });
});

describe("getClaims { cookie: false }", () => {
  it("cookie:false accepts Authorization only; the default true still reads the cookie", async () => {
    const o = { issuer: fx.issuer };
    expect(await getClaims(req("/api/x", { cookie: `${C}=${good}` }), o, { cookie: false })).toBeNull();
    expect((await getClaims(req("/api/x", { authorization: `Bearer ${good}` }), o, { cookie: false }))?.sub).toBe("user-1");
    expect((await getClaims(req("/api/x", { cookie: `${C}=${good}` }), o))?.sub).toBe("user-1");
    expect((await getClaims(req("/api/x", { cookie: `${C}=${good}` }), o, { cookie: true }))?.sub).toBe("user-1");
  });
});

describe("publicPaths", () => {
  it("strings match by segment prefix, RegExp, /api/public does not match /api/publicity", async () => {
    const mw = createAuthMiddleware(opts({ publicPaths: ["/api/public", /^\/health$/] }));
    expect(passed(await mw(req("/api/public")))).toBe(true);
    expect(passed(await mw(req("/api/public/a")))).toBe(true);
    expect(passed(await mw(req("/health")))).toBe(true);
    await expect401(await mw(req("/api/publicity")), "Bearer");
    expect((await mw(req("/healthz"))).status).toBe(307);
  });
});

describe("publicPaths \"/\" only covers the root path", () => {
  it("publicPaths [\"/\"]: / is public, /admin still 307, /api/x still 401", async () => {
    const mw = createAuthMiddleware(opts({ publicPaths: ["/"] }));
    expect(passed(await mw(req("/")))).toBe(true);
    const r = await mw(req("/admin"));
    expect(r.status).toBe(307);
    await expect401(await mw(req("/api/x")), "Bearer");
  });
});

describe("forged header bypass", () => {
  const forged = b64u(JSON.stringify({ sub: "admin", role: "authenticated", iss: "x", aud: "x", exp: nowS() + 900, iat: nowS(), cv: 1, app_role: null }));
  it("forged header only ⇒ null; forged header + valid bearer ⇒ the token's sub", async () => {
    const o = { issuer: fx.issuer };
    expect(await getClaims(req("/x", { "x-relyt-claims": forged }), o)).toBeNull();
    expect((await getClaims(req("/x", { "x-relyt-claims": forged, authorization: `Bearer ${good}` }), o))?.sub).toBe("user-1");
  });
});

describe("writing the cookie", () => {
  const attrs = (res: NextResponse) => {
    const sc = res.headers.get("set-cookie") ?? "";
    const [nv, ...rest] = sc.split(";").map((s) => s.trim());
    const m = new Map(rest.map((a) => { const [k, v = ""] = a.split("="); return [k!.toLowerCase(), v.toLowerCase()]; }));
    return { nv: nv!, m };
  };
  it("setTokenCookie: all attributes, Max-Age = exp − now (≤ TOKEN_TTL_S)", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
    vi.setSystemTime(new Date("2026-10-27T00:00:00Z"));
    const t = await sign(fx, undefined, { iat: nowS() - 600, exp: nowS() + 300 });
    const res = NextResponse.next();
    setTokenCookie(res, t);
    const { nv, m } = attrs(res);
    expect(nv).toBe(`${C}=${t}`);
    expect(m.get("path")).toBe("/");
    expect(m.has("secure")).toBe(true);
    expect(m.has("httponly")).toBe(true);
    expect(m.get("samesite")).toBe("lax");
    expect(m.get("max-age")).toBe("300");
    expect(m.has("domain")).toBe(false);
    // remaining lifetime above the TTL ⇒ clamped to TOKEN_TTL_S
    const long = await sign(fx, undefined, { exp: nowS() + 5000 });
    const r2 = NextResponse.next();
    setTokenCookie(r2, long, { cookieName: "x" });
    expect(attrs(r2).nv).toBe(`x=${long}`);
    expect(attrs(r2).m.get("max-age")).toBe(String(TOKEN_TTL_S));
    expect(vi.getTimerCount()).toBe(0);
  });
  it("expired / no exp / not a JWT ⇒ no token written, cleared instead", async () => {
    for (const t of [await sign(fx, undefined, { exp: nowS() - 1, iat: nowS() - 100 }), await sign(fx, undefined, { exp: null }), "not-a-jwt"]) {
      const res = NextResponse.next();
      setTokenCookie(res, t);
      const { nv, m } = attrs(res);
      expect(nv).toBe(`${C}=`);
      expect(m.get("max-age")).toBe("0");
    }
  });
  it("empty signature segment / non-ASCII claims (shares decodePayloadUnverified with the client)", async () => {
    // Built at runtime so the source stays ASCII-only: two CJK ideographs.
    const t = await sign(fx, { ...baseClaims(), name: String.fromCodePoint(0x5f20, 0x4e09) }, { exp: nowS() + 300 });
    const ok = NextResponse.next();
    setTokenCookie(ok, t);
    expect(attrs(ok).nv).toBe(`${C}=${t}`);
    const [h, p] = t.split(".");
    const res = NextResponse.next();
    setTokenCookie(res, `${h}.${p}.`);
    expect(attrs(res).nv).toBe(`${C}=`);
    expect(attrs(res).m.get("max-age")).toBe("0");
  });
  it("over 4000 bytes when serialized ⇒ throws RelytAuthError(config), no cookie written, error does not contain the token", async () => {
    const big = await sign(fx, { ...baseClaims(), pad: "x".repeat(3200) }, { exp: nowS() + 300 });
    expect(big.length).toBeGreaterThan(4000);
    const res = NextResponse.next();
    let err: unknown;
    try {
      setTokenCookie(res, big);
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(RelytAuthError);
    expect((err as RelytAuthError).code).toBe("config");
    expect(JSON.stringify(err) + String(err) + String((err as Error).stack)).not.toContain(big.split(".")[1]!.slice(0, 40));
    expect(res.headers.get("set-cookie")).toBeNull();
    // control: a token just below the limit is written as usual
    const ok = await sign(fx, { ...baseClaims(), pad: "x".repeat(2400) }, { exp: nowS() + 300 });
    const r2 = NextResponse.next();
    setTokenCookie(r2, ok);
    expect(attrs(r2).nv).toBe(`${C}=${ok}`);
  });
  it("clearTokenCookie: same name, Path=/, Secure, HttpOnly, SameSite=Lax, Max-Age=0; cookieName is honoured", () => {
    const res = NextResponse.next();
    clearTokenCookie(res);
    const { nv, m } = attrs(res);
    expect(nv).toBe(`${C}=`);
    expect(m.get("path")).toBe("/");
    expect(m.has("secure")).toBe(true);
    expect(m.has("httponly")).toBe(true);
    expect(m.get("samesite")).toBe("lax");
    expect(m.get("max-age")).toBe("0");
    const r2 = NextResponse.next();
    clearTokenCookie(r2, { cookieName: "x" });
    expect(attrs(r2).nv).toBe("x=");
  });
  it("src/client*.ts never writes document.cookie", () => {
    const dir = new URL("../src", import.meta.url).pathname;
    const files = readdirSync(dir).filter((f) => f.startsWith("client") && f.endsWith(".ts"));
    expect(files.length).toBeGreaterThan(0);
    for (const f of files) expect(readFileSync(join(dir, f), "utf8")).not.toMatch(/document\.cookie/);
  });
});

describe("default cookieName in all three places", () => {
  it("literal __Host-relyt-at", async () => {
    expect(DEFAULT_COOKIE_NAME).toBe("__Host-relyt-at");
    expect(passed(await createAuthMiddleware(opts())(req("/dash", { cookie: `__Host-relyt-at=${good}` })))).toBe(true);
    expect((await getClaims(req("/x", { cookie: `__Host-relyt-at=${good}` }), { issuer: fx.issuer }))?.sub).toBe("user-1");
    const a = NextResponse.next();
    setTokenCookie(a, good);
    expect(a.headers.get("set-cookie")).toMatch(/^__Host-relyt-at=/);
    const b = NextResponse.next();
    clearTokenCookie(b);
    expect(b.headers.get("set-cookie")).toMatch(/^__Host-relyt-at=;/);
  });
});

describe("configuration", () => {
  it.each([[{ signInUrl: "" }], [{ signInUrl: 1 as unknown as string }], [{ issuer: "https://x.example/" }], [{ apiPrefix: "api" }]])("%j ⇒ config", (o) => {
    expect(() => createAuthMiddleware(opts(o))).toThrow(RelytAuthError);
  });
  it("issuer comes from configuration, not Host: a different Host header does not affect verification", async () => {
    const r = await createAuthMiddleware(opts())(req("/api/x", { authorization: `Bearer ${good}`, host: "evil.example" }));
    expect(passed(r)).toBe(true);
  });
});

describe("leaks", () => {
  const surfaces = async (r: Response) => [await r.clone().text(), JSON.stringify(hdrs(r))];
  it("failure responses and onEvent contain no token, console called 0 times", async () => {
    const spies = (["log", "info", "warn", "error", "debug"] as const).map((k) => vi.spyOn(console, k).mockImplementation(() => {}));
    const ev: AuthEvent[] = [];
    const expired = await sign(fx, undefined, { exp: nowS() - 600, iat: nowS() - 900 });
    const dt = await sign(down);
    const mw = createAuthMiddleware(opts({ onEvent: (e) => ev.push(e) }));
    const mwDown = createAuthMiddleware(opts({ issuer: down.issuer, onEvent: (e) => ev.push(e) }));
    const cases: Array<[string, Response]> = [
      [expired, await mw(req("/api/x", { authorization: `Bearer ${expired}` }))],
      [expired, await mw(req("/dash?t=1", { cookie: `${C}=${expired}` }))],
      [dt, await mwDown(req("/api/x", { authorization: `Bearer ${dt}` }))],
      [dt, await mwDown(req("/dash", { cookie: `${C}=${dt}` }))],
    ];
    expect(ev.length).toBeGreaterThanOrEqual(4); // non-vacuity
    for (const [t, r] of cases) {
      expect(r.status).toBeGreaterThanOrEqual(300);
      assertNoLeak(t, [...(await surfaces(r)), JSON.stringify(ev)]);
    }
    for (const s of spies) expect(s).not.toHaveBeenCalled();
  });
  it("after passing, overrides and response headers contain no x-relyt-* and no signature segment", async () => {
    const r = await createAuthMiddleware(opts())(req("/dash", { cookie: `${C}=${good}`, "x-relyt-claims": "f" }));
    expect(passed(r)).toBe(true);
    const keys = [...hdrs(r).map(([k]) => k)];
    expect(keys.filter((k) => k.includes("x-relyt-"))).toEqual([]);
    const sig = good.split(".")[2]!;
    expect(sig.length).toBeGreaterThan(8);
    // the forwarded cookie header naturally contains the token; no other response header may contain the signature segment
    const others = hdrs(r).filter(([k]) => k !== "x-middleware-request-cookie");
    expect(JSON.stringify(others).includes(sig)).toBe(false);
  });
});

