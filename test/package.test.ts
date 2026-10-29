// Package shape, forbidden non-Web APIs in src, build output resolvable through `exports`, and the auth service's token contract.
import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { CLAIM_KEYS, REGISTERED_CLAIM_KEYS } from "../src/claims.js";
import { MAX_CLOCK_TOLERANCE_S, TOKEN_TTL_S } from "../src/constants.js";
import { createVerifier } from "../src/verify.js";

const root = new URL("..", import.meta.url).pathname;
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));

describe("P1 package.json", () => {
  it("name, ESM, exports, exact dependencies, verbatim peer range, publish metadata", () => {
    expect(pkg.name).toBe("@relyt/auth");
    expect(pkg.private).toBeUndefined();
    expect(pkg.license).toBe("MIT");
    expect(pkg.repository).toEqual({ type: "git", url: "git+https://github.com/relytcloud/relyt-auth-js.git" });
    expect(pkg.publishConfig).toEqual({ access: "public" });
    expect(pkg.scripts.prepublishOnly).toBe("pnpm run build && pnpm run test");
    expect(pkg.type).toBe("module");
    expect(Object.keys(pkg.exports)).toEqual([".", "./next"]);
    expect(pkg.exports["."]).toEqual({ types: "./dist/index.d.ts", default: "./dist/index.js" });
    expect(pkg.exports["./next"]).toEqual({ types: "./dist/next.d.ts", default: "./dist/next.js" });
    expect(pkg.dependencies).toEqual({ jose: "6.2.13" });
    expect(pkg.peerDependencies).toEqual({ next: "^14.2.35 || >=15.5.28 <16" });
    expect(pkg.peerDependenciesMeta).toEqual({ next: { optional: true } });
    expect(pkg.devDependencies.next).toBe("15.5.28"); // tests run on the 15.x line; the same suite has also been run against 14.2.35
    expect(pkg.devDependencies.react).toBe("19.2.9");
    expect(pkg.devDependencies["react-dom"]).toBe("19.2.9");
    expect(pkg.scripts.build).toBe("tsc -p tsconfig.build.json");
    expect(pkg.scripts.test).toBe("tsc -p tsconfig.build.json && vitest run");
    expect(pkg.files).toEqual(["dist"]);
  });
});

const FORBIDDEN: Array<[string, RegExp]> = [
  ["node: import", /from\s+["']node:|import\s*\(?\s*["']node:/],
  ["require(", /\brequire\s*\(/],
  ["process.", /\bprocess\./],
  ["Buffer", /\bBuffer\b/],
  ["console.", /\bconsole\./],
];
export const scan = (src: string) => FORBIDDEN.filter(([, re]) => re.test(src)).map(([n]) => n);

function walk(d: string): string[] {
  return readdirSync(d).flatMap((f) => (statSync(join(d, f)).isDirectory() ? walk(join(d, f)) : [join(d, f)]));
}

describe("src uses Web APIs only", () => {
  it("scanner self-check (non-vacuity)", () => {
    expect(scan('import "node:fs";\nimport x from "node:fs";')).toContain("node: import");
    expect(scan("const b = Buffer.from('x'); console.log(process.env)")).toEqual(["process.", "Buffer", "console."]);
  });
  it("no hits in src/**/*.ts", () => {
    const files = walk(join(root, "src")).filter((f) => f.endsWith(".ts"));
    expect(files.length).toBeGreaterThanOrEqual(5);
    for (const f of files) expect(scan(readFileSync(f, "utf8")), f).toEqual([]);
  });
});

describe("build output (the test script builds first)", () => {
  it("both entries resolve dist through self-referencing exports and export the public symbols; dist has no test files", () => {
    const out = execFileSync(process.execPath, ["--input-type=module", "-e",
      'const a = await import("@relyt/auth"); const n = await import("@relyt/auth/next");' +
      'console.log(JSON.stringify({ a: Object.keys(a).sort(), n: Object.keys(n) }))'], { cwd: root, encoding: "utf8" });
    const r = JSON.parse(out);
    expect(r.a).toEqual(expect.arrayContaining(["CLAIM_KEYS", "REGISTERED_CLAIM_KEYS", "RelytAuthError", "createVerifier", "verifyToken"]));
    expect(r.n).toEqual(expect.arrayContaining(["createAuthMiddleware", "getClaims", "setTokenCookie", "clearTokenCookie", "RelytAuthUnavailableError", "DEFAULT_COOKIE_NAME"]));
    const dist = walk(join(root, "dist"));
    expect(dist.some((f) => f.endsWith("index.js"))).toBe(true);
    expect(dist.filter((f) => /\.test\./.test(f) || f.includes("/test/"))).toEqual([]);
  });
});

// The auth service's token contract. This package lives outside the service's repository, so the contract is pinned
// here as literals taken from the service (not from this package). When the service changes its claim set or token
// durations, these tests fail by design: update the values together with src/claims.ts and src/constants.ts.
const SERVICE_TOKEN_CLAIM_KEYS = ["role", "app_role", "o", "cv", "act"];
const SERVICE_REGISTERED_CLAIMS = ["sub", "iss", "aud", "exp", "iat"];
const SERVICE_TOKEN_TTL_S = 900;
const SERVICE_JWKS_GRACE_S = SERVICE_TOKEN_TTL_S + 60;

describe("claim keys match the auth service contract", () => {
  it("TOKEN_CLAIM_KEYS ↔ CLAIM_KEYS, REGISTERED_CLAIMS ↔ REGISTERED_CLAIM_KEYS", () => {
    const claim = SERVICE_TOKEN_CLAIM_KEYS;
    const reg = SERVICE_REGISTERED_CLAIMS;
    expect(claim).toHaveLength(5);
    expect(reg).toHaveLength(5);
    expect(new Set(CLAIM_KEYS)).toEqual(new Set(claim));
    expect(new Set(REGISTERED_CLAIM_KEYS)).toEqual(new Set(reg));
  });
});

describe("duration constants match the auth service contract", () => {
  it("TOKEN_TTL_S ↔ SDK TOKEN_TTL_S; JWKS_GRACE_S − TOKEN_TTL_S ↔ MAX_CLOCK_TOLERANCE_S", () => {
    const serviceTtl = SERVICE_TOKEN_TTL_S;
    const serviceGrace = SERVICE_JWKS_GRACE_S;
    expect(serviceTtl).toBeGreaterThan(0);
    expect(serviceGrace).toBeGreaterThan(serviceTtl);
    expect(TOKEN_TTL_S).toBe(serviceTtl);
    expect(MAX_CLOCK_TOLERANCE_S).toBe(serviceGrace - serviceTtl);
  });
  it("verification clockToleranceS is capped at MAX_CLOCK_TOLERANCE_S (60 valid, 61 ⇒ config)", () => {
    expect(() => createVerifier({ issuer: "https://h.example.com", clockToleranceS: MAX_CLOCK_TOLERANCE_S })).not.toThrow();
    expect(() => createVerifier({ issuer: "https://h.example.com", clockToleranceS: MAX_CLOCK_TOLERANCE_S + 1 })).toThrow(/configuration/);
  });
});
