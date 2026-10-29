// Records the options verifyToken passes to the **real** jose jwtVerify (not via a pure helper function).
import { afterEach, describe, expect, it, vi } from "vitest";

const recorded: unknown[] = [];
vi.mock("jose", async (orig) => {
  const real = await orig<typeof import("jose")>();
  return {
    ...real,
    jwtVerify: (async (...args: Parameters<typeof real.jwtVerify>) => {
      recorded.push(args[2]);
      return real.jwtVerify(...args);
    }) as typeof real.jwtVerify,
  };
});

const { verifyToken } = await import("../src/verify.js");
const { closeAll, issuerFixture, sign } = await import("./helpers/issuer.js");

afterEach(async () => {
  recorded.length = 0;
  await closeAll();
});

describe("jwtVerify arguments", () => {
  it("defaults: maxTokenAge 900 (no extra margin), clockTolerance 30, EdDSA, iss = aud = issuer, requiredClaims", async () => {
    const fx = await issuerFixture();
    const c = await verifyToken(await sign(fx), { issuer: fx.issuer });
    expect(c.sub).toBe("user-1");
    expect(recorded).toHaveLength(1);
    const o = recorded[0] as Record<string, unknown>;
    expect(o.maxTokenAge).toBe(900);
    expect(o.clockTolerance).toBe(30);
    expect(o.algorithms).toEqual(["EdDSA"]);
    expect(o.issuer).toBe(fx.issuer);
    expect(o.audience).toBe(fx.issuer);
    expect(o.requiredClaims).toEqual(expect.arrayContaining(["exp", "iat", "sub"]));
  });

  it("maxTokenAgeS 600 ⇒ 600", async () => {
    const fx = await issuerFixture();
    await verifyToken(await sign(fx, undefined, { exp: Math.floor(Date.now() / 1000) + 600 }), { issuer: fx.issuer, maxTokenAgeS: 600 });
    expect((recorded[0] as Record<string, unknown>).maxTokenAge).toBe(600);
  });
});
