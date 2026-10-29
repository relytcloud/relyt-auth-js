import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SignJWT, createRemoteJWKSet, jwtVerify } from "jose";
import { createVerifier, verifyToken, mapJoseError, JwksUnavailable } from "../src/verify.js";
import { RelytAuthError, type AuthEvent } from "../src/errors.js";
import { baseClaims, b64u, closeAll, issuerFixture, makeKey, nowS, sign } from "./helpers/issuer.js";
import { expectReject, seenTokens } from "./helpers/expect.js";

const T0 = new Date("2026-10-27T00:00:00Z");
beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(T0);
});
afterEach(async () => {
  vi.useRealTimers();
  await closeAll();
});
const advance = (s: number) => vi.setSystemTime(Date.now() + s * 1000);

describe("valid token", () => {
  it("returns the claims unchanged; JWKS fetched once, still once after 10 more verifications", async () => {
    const fx = await issuerFixture();
    const v = createVerifier({ issuer: fx.issuer });
    const t = await sign(fx);
    const c = await v(t);
    expect(c.sub).toBe("user-1");
    expect(c.cv).toBe(1);
    expect(c.o?.perms).toEqual(["project:read"]);
    expect(c.iss).toBe(fx.issuer);
    expect(fx.requests()).toBe(1);
    for (let i = 0; i < 10; i++) await v(t);
    expect(fx.requests()).toBe(1);
  });
});

describe("algorithm pinning", () => {
  it("alg:none", async () => {
    const fx = await issuerFixture();
    const body = { ...baseClaims(), sub: "u", iss: fx.issuer, aud: fx.issuer, iat: nowS(), exp: nowS() + 900 };
    const t = `${b64u(JSON.stringify({ alg: "none", kid: "kid1" }))}.${b64u(JSON.stringify(body))}.`;
    await expectReject(createVerifier({ issuer: fx.issuer })(t), "invalid_token", t);
  });

  it("HS256 with the HMAC key = OKP public key x", async () => {
    const fx = await issuerFixture();
    const x = Buffer.from(String(fx.keys.get("kid1")!.publicJwk.x), "base64url");
    const t = await new SignJWT({ ...baseClaims(), sub: "u", iss: fx.issuer, aud: fx.issuer, iat: nowS(), exp: nowS() + 900 })
      .setProtectedHeader({ alg: "HS256", kid: "kid1" })
      .sign(new Uint8Array(x));
    await expectReject(createVerifier({ issuer: fx.issuer })(t), "invalid_token", t);
  });

  for (const alg of ["ES256", "RS256"]) {
    it(`${alg} correctly signed with the key in the JWKS ⇒ rejected (precondition: calling jose directly with ${alg} allowed verifies it)`, async () => {
      const fx = await issuerFixture();
      const k = await makeKey("other1", alg);
      fx.keys.set("other1", k);
      fx.published.push(k.publicJwk);
      const t = await sign(fx, baseClaims(), { kid: "other1" });
      const direct = await jwtVerify(t, createRemoteJWKSet(new URL(fx.jwksUrl)), { algorithms: [alg] });
      expect(direct.payload.sub).toBe("user-1");
      await expectReject(createVerifier({ issuer: fx.issuer })(t), "invalid_token", t);
    });
  }

  it("jku / x5u / embedded jwk headers are not followed; B's request count stays 0", async () => {
    const a = await issuerFixture();
    const b = await issuerFixture({ kids: ["evil"] });
    const evil = b.keys.get("evil")!;
    const tokens = [
      await sign(b, baseClaims(), { key: evil, iss: a.issuer, aud: a.issuer, header: { jku: b.jwksUrl } }),
      await sign(b, baseClaims(), { key: evil, iss: a.issuer, aud: a.issuer, header: { x5u: b.jwksUrl } }),
      await sign(b, baseClaims(), { key: evil, iss: a.issuer, aud: a.issuer, header: { jwk: evil.publicJwk } }),
    ];
    const va = createVerifier({ issuer: a.issuer });
    for (const t of tokens) await expectReject(va(t), "invalid_token", t);
    expect(b.requests()).toBe(0);
    // Non-vacuity: the signature itself is valid (B's JWKS verifies it when iss is not checked)
    for (const t of tokens) await jwtVerify(t, createRemoteJWKSet(new URL(b.jwksUrl)), { algorithms: ["EdDSA"] });
  });

  it("alg: Ed25519 (RFC 9864 name), correctly signed with the same key ⇒ rejected", async () => {
    const fx = await issuerFixture();
    const t = await sign(fx, baseClaims(), { alg: "Ed25519" });
    await jwtVerify(t, createRemoteJWKSet(new URL(fx.jwksUrl)), { algorithms: ["Ed25519"] }); // precondition: the signature is valid
    await expectReject(createVerifier({ issuer: fx.issuer })(t), "invalid_token", t);
  });
});

describe("cross-tenant", () => {
  it("a child tenant's token is rejected by the parent verifier and accepted by the child verifier", async () => {
    const a = await issuerFixture();
    const b = await issuerFixture();
    const t = await sign(b);
    await expectReject(createVerifier({ issuer: a.issuer })(t), "invalid_token", t);
    expect((await createVerifier({ issuer: b.issuer })(t)).iss).toBe(b.issuer);
  });

  it("same key published at two issuers: a token with B's iss is rejected by verifier(A)", async () => {
    const a = await issuerFixture();
    const b = await issuerFixture();
    a.published.splice(0, a.published.length, b.keys.get("kid1")!.publicJwk);
    const t = await sign(b, baseClaims(), { aud: a.issuer }); // only iss differs (aud is exactly A), pinning the issuer option
    await jwtVerify(t, createRemoteJWKSet(new URL(a.jwksUrl)), { algorithms: ["EdDSA"] }); // precondition: A's JWKS verifies the signature
    await expectReject(createVerifier({ issuer: a.issuer })(t), "invalid_token", t);
  });

  it("iss=A, aud=B rejected; aud [B] rejected, [A,B] accepted (jose accepts arrays that contain it)", async () => {
    const a = await issuerFixture();
    const b = await issuerFixture();
    const v = createVerifier({ issuer: a.issuer });
    for (const aud of [b.issuer, [b.issuer]]) {
      const t = await sign(a, baseClaims(), { aud });
      await expectReject(v(t), "invalid_token", t);
    }
    expect((await v(await sign(a, baseClaims(), { aud: [a.issuer, b.issuer] }))).sub).toBe("user-1");
  });
});

describe("time", () => {
  it("exp / nbf / iat tolerance of 30 s", async () => {
    const fx = await issuerFixture();
    const v = createVerifier({ issuer: fx.issuer });
    const n = nowS();
    const bad = [
      await sign(fx, baseClaims(), { iat: n - 600, exp: n - 31 }),
      await sign(fx, { ...baseClaims(), nbf: n + 31 }),
      await sign(fx, baseClaims(), { iat: n + 31, exp: n + 31 + 900 }),
    ];
    for (const t of bad) await expectReject(v(t), "invalid_token", t);
    await v(await sign(fx, baseClaims(), { iat: n - 600, exp: n - 29 }));
    await v(await sign(fx, { ...baseClaims(), nbf: n + 29 }));
  });

  it("exp−iat post-check: 901/0/−1 rejected, 900 accepted; missing exp / iat / sub each rejected", async () => {
    const fx = await issuerFixture();
    const v = createVerifier({ issuer: fx.issuer });
    const n = nowS();
    for (const life of [901, 0, -1]) {
      const t = await sign(fx, baseClaims(), { iat: n, exp: n + life });
      await expectReject(v(t), "invalid_token", t);
    }
    await v(await sign(fx, baseClaims(), { iat: n, exp: n + 900 }));
    for (const o of [{ exp: null }, { iat: null, exp: n + 900 }, { sub: null }]) {
      const t = await sign(fx, baseClaims(), o);
      await expectReject(v(t), "invalid_token", t);
    }
  });

  it("clockToleranceS > 60 ⇒ config", () => {
    let e: unknown;
    try {
      createVerifier({ issuer: "https://h.example", clockToleranceS: 120 });
    } catch (x) {
      e = x;
    }
    expect((e as RelytAuthError).code).toBe("config");
    expect(() => createVerifier({ issuer: "https://h.example", clockToleranceS: 60 })).not.toThrow();
  });
});

describe("JWKS cache", () => {
  it("a new kid triggers one refetch after the cooldown and is accepted", async () => {
    const fx = await issuerFixture();
    const v = createVerifier({ issuer: fx.issuer });
    await v(await sign(fx));
    const k2 = await makeKey("kid2");
    fx.keys.set("kid2", k2);
    fx.published.push(k2.publicJwk);
    advance(31);
    await v(await sign(fx, baseClaims(), { kid: "kid2" }));
    expect(fx.requests()).toBe(2);
  });

  it("an unknown kid within the cooldown sends no request; +1 after it", async () => {
    const fx = await issuerFixture();
    const v = createVerifier({ issuer: fx.issuer });
    await v(await sign(fx));
    const k3 = await makeKey("kid3");
    fx.keys.set("kid3", k3);
    const t = await sign(fx, baseClaims(), { kid: "kid3" });
    await expectReject(v(t), "invalid_token", t);
    expect(fx.requests()).toBe(1);
    advance(31);
    const t2 = await sign(fx, baseClaims(), { kid: "kid3" });
    await expectReject(v(t2), "invalid_token", t2);
    expect(fx.requests()).toBe(2);
  });

  it("rotation: old kid still accepted at iat+899; after revocation + cacheMaxAge, a fresh token with the old kid is rejected", async () => {
    const fx = await issuerFixture();
    const k2 = await makeKey("kid2");
    fx.keys.set("kid2", k2);
    fx.published.push(k2.publicJwk);
    const v = createVerifier({ issuer: fx.issuer });
    const old = await sign(fx);
    await v(old);
    advance(899);
    await v(old);
    fx.published.splice(0, 1); // revoke kid1
    advance(301);
    const fresh = await sign(fx);
    await expectReject(v(fresh), "invalid_token", fresh);
    expect(fx.requests()).toBeGreaterThanOrEqual(2);
  });

  it("500 / hanging timeout ⇒ jwks_unavailable; accepted again after recovery", async () => {
    const fx = await issuerFixture();
    const t = await sign(fx);
    const events: AuthEvent[] = [];
    const v = createVerifier({ issuer: fx.issuer, timeoutMs: 200, onEvent: (e) => events.push(e) });
    fx.setMode("500");
    await expectReject(v(t), "jwks_unavailable", t, events);
    fx.setMode("hang");
    const started = performance.now();
    await expectReject(v(t), "jwks_unavailable", t, events);
    expect(performance.now() - started).toBeLessThan(3000);
    fx.setMode("ok");
    expect((await v(t)).sub).toBe("user-1");
    expect(events.filter((e) => e.type === "verify_failed").map((e) => e.code)).toEqual(["jwks_unavailable", "jwks_unavailable"]);
  });

  it("default timeoutMs = 5 s: a hanging JWKS ⇒ jwks_unavailable within [4.5, 7) s", async () => {
    const fx = await issuerFixture();
    fx.setMode("hang");
    const t = await sign(fx);
    const started = performance.now();
    await expectReject(createVerifier({ issuer: fx.issuer })(t), "jwks_unavailable", t);
    const ms = performance.now() - started;
    expect(ms).toBeGreaterThanOrEqual(4500);
    expect(ms).toBeLessThan(7000);
  }, 10_000);

  it("empty / non-string token ⇒ invalid_token, JWKS not fetched", async () => {
    const fx = await issuerFixture();
    const v = createVerifier({ issuer: fx.issuer });
    await expect(v("")).rejects.toMatchObject({ code: "invalid_token" });
    await expect(v(undefined as never)).rejects.toMatchObject({ code: "invalid_token" });
    expect(fx.requests()).toBe(0);
  });

  it("only the remote key set is cached: key = jwksUrl + cooldown + timeout", async () => {
    const fx = await issuerFixture();
    const t = await sign(fx);
    await createVerifier({ issuer: fx.issuer })(t);
    await createVerifier({ issuer: fx.issuer })(t);
    await verifyToken(t, { issuer: fx.issuer });
    expect(fx.requests()).toBe(1);
    await createVerifier({ issuer: fx.issuer, timeoutMs: 4000 })(t);
    expect(fx.requests()).toBe(2);
    await createVerifier({ issuer: fx.issuer, cooldownMs: 10_000 })(t);
    expect(fx.requests()).toBe(3);
  });

  it("different jwksUrls get separate entries", async () => {
    const a = await issuerFixture();
    const b = await issuerFixture();
    b.published.splice(0, 1, a.keys.get("kid1")!.publicJwk);
    const t = await sign(a);
    await verifyToken(t, { issuer: a.issuer });
    await verifyToken(t, { issuer: a.issuer, jwksUrl: b.jwksUrl });
    expect([a.requests(), b.requests()]).toEqual([1, 1]);
  });

  for (const order of [[0, 30], [30, 0]] as const) {
    it(`same key set, clockToleranceS ${order.join("→")} applies per call`, async () => {
      const fx = await issuerFixture();
      const n = nowS();
      const t = await sign(fx, baseClaims(), { iat: n - 300, exp: n - 10 });
      for (const tol of order) {
        if (tol === 0) await expectReject(verifyToken(t, { issuer: fx.issuer, clockToleranceS: 0 }), "invalid_token", t);
        else expect((await verifyToken(t, { issuer: fx.issuer, clockToleranceS: 30 })).sub).toBe("user-1");
      }
      expect(fx.requests()).toBe(1);
    });
  }

  it("the 65th key evicts the oldest entry (LRU 64)", async () => {
    const fx = await issuerFixture();
    const t = await sign(fx);
    const cfg = (i: number) => ({ issuer: fx.issuer, timeoutMs: 1000 + i });
    for (let i = 0; i < 65; i++) await verifyToken(t, cfg(i));
    expect(fx.requests()).toBe(65);
    await verifyToken(t, cfg(64));
    await verifyToken(t, cfg(1));
    expect(fx.requests()).toBe(65);
    await verifyToken(t, cfg(0));
    expect(fx.requests()).toBe(66); // 0 re-enters the cache; the evicted one is 2, the least recently used (1 was just accessed)
    await verifyToken(t, cfg(1));
    expect(fx.requests()).toBe(66);
    await verifyToken(t, cfg(2));
    expect(fx.requests()).toBe(67);
  });
});

describe("jose error mapping (one row per mapping)", () => {
  it("one end-to-end case each", async () => {
    const fx = await issuerFixture();
    const v = createVerifier({ issuer: fx.issuer });
    const good = await sign(fx);
    const sig = good.split(".");
    const flipped = `${sig[0]}.${sig[1]}.${sig[2]!.startsWith("A") ? "B" : "A"}${sig[2]!.slice(1)}`;
    const notJsonPayload = `${sig[0]}.${b64u("not-json-payload-xxxx")}.${sig[2]}`;
    const n = nowS();
    const cases: Array<[string, string]> = [
      [flipped, "invalid_token"], // ERR_JWS_SIGNATURE_VERIFICATION_FAILED
      ["aaaaaaaa.bbbbbbbbbb", "invalid_token"], // ERR_JWS_INVALID
      [notJsonPayload, "invalid_token"], // ERR_JWS_SIGNATURE_VERIFICATION_FAILED / ERR_JWT_INVALID
      [await sign(fx, baseClaims(), { iat: n - 900, exp: n - 100 }), "invalid_token"], // ERR_JWT_EXPIRED
      [await sign(fx, baseClaims(), { iss: "https://other.example" }), "invalid_token"], // ERR_JWT_CLAIM_VALIDATION_FAILED
    ];
    for (const [t, code] of cases) await expectReject(v(t), code, t);
    const k9 = await makeKey("kid9");
    fx.keys.set("kid9", k9);
    const miss = await sign(fx, baseClaims(), { kid: "kid9" });
    await expectReject(v(miss), "invalid_token", miss); // ERR_JWKS_NO_MATCHING_KEY

    for (const mode of ["notjson", "500"] as const) {
      const f2 = await issuerFixture();
      f2.setMode(mode);
      const t = await sign(f2);
      await expectReject(createVerifier({ issuer: f2.issuer })(t), "jwks_unavailable", t);
    }
    const f3 = await issuerFixture();
    f3.setMode("hang");
    const t3 = await sign(f3);
    await expectReject(createVerifier({ issuer: f3.issuer, timeoutMs: 200 })(t3), "jwks_unavailable", t3); // ERR_JWKS_TIMEOUT
    const f4 = await issuerFixture();
    const t4 = await sign(f4);
    await f4.close(); // connection refused ⇒ fetch rejects
    await expectReject(createVerifier({ issuer: f4.issuer })(t4), "jwks_unavailable", t4);
  });

  it("mapJoseError as a pure function: every mapped code and an unknown error", () => {
    const inv = [
      "ERR_JWS_SIGNATURE_VERIFICATION_FAILED", "ERR_JWS_INVALID", "ERR_JWT_INVALID", "ERR_JOSE_ALG_NOT_ALLOWED",
      "ERR_JOSE_NOT_SUPPORTED", "ERR_JWT_EXPIRED", "ERR_JWT_CLAIM_VALIDATION_FAILED", "ERR_JWKS_NO_MATCHING_KEY",
      "ERR_JWKS_MULTIPLE_MATCHING_KEYS",
    ];
    for (const code of inv) expect(mapJoseError({ code }).code, code).toBe("invalid_token");
    for (const code of ["ERR_JWKS_TIMEOUT", "ERR_JWKS_INVALID"]) expect(mapJoseError({ code }).code, code).toBe("jwks_unavailable");
    expect(mapJoseError(new JwksUnavailable()).code).toBe("jwks_unavailable");
    expect(mapJoseError(new Error("x")).code).toBe("invalid_token");
    expect(mapJoseError({ code: "ERR_FOO" }).code).toBe("invalid_token");
    expect(mapJoseError(undefined).code).toBe("invalid_token");
    expect(mapJoseError(new Error("x")).message).toBe("invalid token");
    expect(mapJoseError({ code: "ERR_JWKS_TIMEOUT" }).message).toBe("signing keys unavailable");
    expect(mapJoseError({ code: "ERR_JWKS_TIMEOUT" }).retryable).toBe(true);
    expect(mapJoseError({ code: "ERR_JWT_EXPIRED" }).retryable).toBe(false);
  });
});

describe("payload shape", () => {
  const cases: Array<[string, Record<string, unknown>, boolean]> = [
    ["minimal payload", { role: "authenticated", app_role: null, cv: 0 }, true],
    ["role", { ...baseClaims(), role: "service_role" }, false],
    ["cv as string", { ...baseClaims(), cv: "1" }, false],
    ["cv 1.5", { ...baseClaims(), cv: 1.5 }, false],
    ["app_role as number", { ...baseClaims(), app_role: 1 }, false],
    ["app_role as string", { ...baseClaims(), app_role: "admin" }, true],
    ["perms null", { ...baseClaims(), o: { id: "o", slug: "s", role: "member", perms: null } }, true],
    ["perms as string", { ...baseClaims(), o: { id: "o", slug: "s", role: "member", perms: "a:b" } }, false],
    ["perms [1]", { ...baseClaims(), o: { id: "o", slug: "s", role: "member", perms: [1] } }, false],
    ["o missing slug", { ...baseClaims(), o: { id: "o", role: "member", perms: null } }, false],
    ["o is null", { ...baseClaims(), o: null }, false],
    ["act ok", { ...baseClaims(), act: { sub: "u" } }, true],
    ["act {}", { ...baseClaims(), act: {} }, false],
  ];
  for (const [name, claims, ok] of cases) {
    it(name, async () => {
      const fx = await issuerFixture();
      const t = await sign(fx, claims);
      const v = createVerifier({ issuer: fx.issuer });
      if (ok) expect((await v(t)).role).toBe("authenticated");
      else await expectReject(v(t), "invalid_claims", t);
    });
  }

  it("non-string sub ⇒ invalid_claims", async () => {
    const fx = await issuerFixture();
    const k = fx.keys.get("kid1")!;
    const t = await new SignJWT({ ...baseClaims(), sub: 42, iss: fx.issuer, aud: fx.issuer, iat: nowS(), exp: nowS() + 900 } as never)
      .setProtectedHeader({ alg: "EdDSA", kid: "kid1" })
      .sign(k.privateKey);
    await expectReject(createVerifier({ issuer: fx.issuer })(t), "invalid_claims", t);
  });

  it("returns a new object; unknown fields preserved", async () => {
    const fx = await issuerFixture();
    const v = createVerifier({ issuer: fx.issuer });
    const t = await sign(fx, { ...baseClaims(), future: { x: 1 } });
    const c1 = await v(t);
    expect(c1.future).toEqual({ x: 1 });
    c1.o!.perms!.push("evil:write");
    (c1 as Record<string, unknown>).role = "service_role";
    const c2 = await v(t);
    expect(c2.o?.perms).toEqual(["project:read"]);
    expect(c2.role).toBe("authenticated");
  });
});

describe("configuration", () => {
  const cfgCode = (f: () => unknown) => {
    try {
      f();
    } catch (e) {
      return (e as RelytAuthError).code;
    }
    return "ok";
  };
  it("missing / empty issuer ⇒ config (createVerifier throws synchronously, verifyToken rejects)", async () => {
    expect(cfgCode(() => createVerifier({} as never))).toBe("config");
    expect(cfgCode(() => createVerifier({ issuer: "" }))).toBe("config");
    await expect(verifyToken("x", { issuer: "" })).rejects.toMatchObject({ code: "config" });
  });
  it("normalizeIssuer rules", () => {
    const bad = ["https://h/", "https://h/path", "https://H", "https://h:443", "ftp://h", "http://example.com",
      "http://localhost.evil.com", "http://127.0.0.2", "not a url"];
    for (const s of bad) expect(cfgCode(() => createVerifier({ issuer: s })), s).toBe("config");
    for (const s of ["https://h", "http://127.0.0.1:1234", "http://localhost:3000", "http://[::1]:1"])
      expect(cfgCode(() => createVerifier({ issuer: s })), s).toBe("ok");
  });
  it("jwksUrl: any path, origin follows the same rule", () => {
    const ok = (j: string) => cfgCode(() => createVerifier({ issuer: "https://h", jwksUrl: j }));
    expect(ok("https://keys.example/any/path.json")).toBe("ok");
    expect(ok("http://localhost:9/jwks")).toBe("ok");
    for (const j of ["http://example.com/jwks", "http://localhost.evil.com/jwks", "ftp://h/jwks", "nope"]) expect(ok(j), j).toBe("config");
  });
  it("other numeric options invalid ⇒ config", () => {
    for (const o of [{ clockToleranceS: -1 }, { maxTokenAgeS: 0 }, { cooldownMs: -1 }, { timeoutMs: 0 }, { timeoutMs: Number.NaN }, { timeoutMs: 1.5 }, { timeoutMs: 60_001 }, { cooldownMs: 1.5 }, { cooldownMs: Number.POSITIVE_INFINITY }])
      expect(cfgCode(() => createVerifier({ issuer: "https://h", ...o })), JSON.stringify(o)).toBe("config");
  });
});

afterAll(() => {
  // Non-vacuity: a long token really went through the failure paths
  expect(seenTokens.length).toBeGreaterThan(30);
  expect(seenTokens.filter((t) => t.length > 100).length).toBeGreaterThan(30);
});
