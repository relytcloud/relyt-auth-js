// Test fixture: real keys, real signatures, a local node:http JWKS server. Test use only.
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { SignJWT, exportJWK, generateKeyPair, type CryptoKey, type JWK } from "jose";

export type JwksMode = "ok" | "500" | "hang" | "notjson";

export interface KeyEntry {
  kid: string;
  alg: string;
  privateKey: CryptoKey;
  publicJwk: JWK;
}

export interface IssuerFixture {
  issuer: string;
  jwksUrl: string;
  /** Public keys currently published (mutable: rotate / revoke keys). */
  published: JWK[];
  keys: Map<string, KeyEntry>;
  requests: () => number;
  setMode: (m: JwksMode) => void;
  close: () => Promise<void>;
}

export async function makeKey(kid: string, alg = "EdDSA"): Promise<KeyEntry> {
  const genAlg = alg === "Ed25519" ? "EdDSA" : alg;
  const { privateKey, publicKey } = await generateKeyPair(genAlg, { extractable: true });
  const publicJwk = { ...(await exportJWK(publicKey)), kid };
  return { kid, alg, privateKey, publicJwk };
}

const open = new Set<Server>();

export async function issuerFixture(o: { kids?: string[] } = {}): Promise<IssuerFixture> {
  const keys = new Map<string, KeyEntry>();
  for (const kid of o.kids ?? ["kid1"]) keys.set(kid, await makeKey(kid));
  const published: JWK[] = [...keys.values()].map((k) => k.publicJwk);
  let count = 0;
  let mode: JwksMode = "ok";
  const server = createServer((req, res) => {
    if (req.url !== "/.well-known/jwks.json") {
      res.statusCode = 404;
      res.end();
      return;
    }
    count++;
    if (mode === "hang") return; // never answer, until close
    if (mode === "500") {
      res.statusCode = 500;
      res.end("boom");
      return;
    }
    res.setHeader("content-type", "application/json");
    res.end(mode === "notjson" ? "<html>" : JSON.stringify({ keys: published }));
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  open.add(server);
  const issuer = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return {
    issuer,
    jwksUrl: `${issuer}/.well-known/jwks.json`,
    published,
    keys,
    requests: () => count,
    setMode: (m) => (mode = m),
    close: () => closeServer(server),
  };
}

function closeServer(s: Server): Promise<void> {
  open.delete(s);
  s.closeAllConnections();
  return new Promise((r) => s.close(() => r()));
}

export async function closeAll(): Promise<void> {
  await Promise.all([...open].map(closeServer));
}

export const nowS = () => Math.floor(Date.now() / 1000);

export interface SignOpts {
  kid?: string;
  key?: KeyEntry;
  alg?: string;
  iss?: string | null;
  aud?: string | string[] | null;
  iat?: number | null;
  exp?: number | null;
  sub?: string | null;
  header?: Record<string, unknown>;
}

export function baseClaims(): Record<string, unknown> {
  return { role: "authenticated", app_role: null, cv: 1, o: { id: "org1", slug: "acme", role: "owner", perms: ["project:read"] } };
}

/** Real signing with jose SignJWT. `null` = omit that claim. */
export async function sign(fx: IssuerFixture, claims: Record<string, unknown> = baseClaims(), o: SignOpts = {}): Promise<string> {
  const key = o.key ?? fx.keys.get(o.kid ?? "kid1");
  if (!key) throw new Error("no such kid");
  const iat = o.iat === undefined ? nowS() : o.iat;
  const body: Record<string, unknown> = { ...claims };
  const sub = o.sub === undefined ? "user-1" : o.sub;
  if (sub !== null) body.sub = sub;
  const iss = o.iss === undefined ? fx.issuer : o.iss;
  if (iss !== null) body.iss = iss;
  const aud = o.aud === undefined ? fx.issuer : o.aud;
  if (aud !== null) body.aud = aud;
  if (iat !== null) body.iat = iat;
  const exp = o.exp === undefined ? (iat ?? nowS()) + 900 : o.exp;
  if (exp !== null) body.exp = exp;
  return new SignJWT(body)
    .setProtectedHeader({ alg: o.alg ?? key.alg, kid: key.kid, ...o.header })
    .sign(key.privateKey);
}

export const b64u = (s: string | Uint8Array) => Buffer.from(s).toString("base64url");
