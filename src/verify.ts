/**
 * Server-side token verification. Web APIs only (jose's webapi build).
 * Fixed: algorithms ["EdDSA"] (not configurable), issuer = audience = the issuer given at construction (never derived from the token).
 */
import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from "jose";
import { checkClaimsShape, type RelytClaims } from "./claims.js";
import { RelytAuthError, type AuthEvent } from "./errors.js";
import { MAX_CLOCK_TOLERANCE_S, TOKEN_TTL_S } from "./constants.js";
import { normalizeIssuer, normalizeJwksUrl } from "./issuer.js";
import { num } from "./options.js";

export interface VerifierOptions {
  /** Expected value of both iss and aud. */
  issuer: string;
  /** Default `${issuer}/.well-known/jwks.json`; only changes where keys are fetched from. */
  jwksUrl?: string;
  /** Default 30, ≤ 60 (the JWKS keeps a retired key for only 60 s beyond the token TTL). */
  clockToleranceS?: number;
  /** Default 900. */
  maxTokenAgeS?: number;
  /** Default 30_000. */
  cooldownMs?: number;
  /** Default 5_000. */
  timeoutMs?: number;
  onEvent?: (e: AuthEvent) => void;
}

const ALGORITHMS = ["EdDSA"];
const REQUIRED_CLAIMS = ["exp", "iat", "sub"];
const CACHE_MAX_AGE_MS = 300_000;
// jose's createRemoteJWKSet requires integer milliseconds; a non-integer throws a synchronous TypeError that would surface as invalid_token (every request 401). The cap prevents setTimeout overflow.
const MAX_TIMEOUT_MS = 60_000;
const MAX_COOLDOWN_MS = 3_600_000;
const JWKS_CACHE_LIMIT = 64;

interface Resolved {
  issuer: string;
  jwksHref: string;
  clockToleranceS: number;
  maxTokenAgeS: number;
  cooldownMs: number;
  timeoutMs: number;
  onEvent?: (e: AuthEvent) => void;
}

function resolve(o: VerifierOptions): Resolved {
  if (typeof o !== "object" || o === null) throw new RelytAuthError("config", { option: "issuer" });
  const issuer = normalizeIssuer(o.issuer);
  const r: Resolved = {
    issuer,
    jwksHref: normalizeJwksUrl(o.jwksUrl ?? `${issuer}/.well-known/jwks.json`),
    clockToleranceS: num(o.clockToleranceS, 30, "clockToleranceS", (n) => n >= 0 && n <= MAX_CLOCK_TOLERANCE_S),
    maxTokenAgeS: num(o.maxTokenAgeS, TOKEN_TTL_S, "maxTokenAgeS", (n) => n > 0),
    cooldownMs: num(o.cooldownMs, 30_000, "cooldownMs", (n) => Number.isInteger(n) && n >= 0 && n <= MAX_COOLDOWN_MS),
    timeoutMs: num(o.timeoutMs, 5_000, "timeoutMs", (n) => Number.isInteger(n) && n > 0 && n <= MAX_TIMEOUT_MS),
  };
  if (o.onEvent !== undefined) r.onEvent = o.onEvent;
  return r;
}

/** Marker for a remote key set that failed while fetching keys (network / non-200 / non-JSON / timeout / invalid JWKS). */
export class JwksUnavailable extends Error {
  constructor() {
    super("jwks unavailable");
  }
}

const KID_MISS = new Set(["ERR_JWKS_NO_MATCHING_KEY", "ERR_JWKS_MULTIPLE_MATCHING_KEYS"]);
const JWKS_DOWN = new Set(["ERR_JWKS_TIMEOUT", "ERR_JWKS_INVALID"]);

/** Maps errors by `err.code`; anything unknown becomes invalid_token (fail closed). The jose error is not kept (its payload contains claims). */
export function mapJoseError(err: unknown): RelytAuthError {
  if (err instanceof RelytAuthError) return err;
  if (err instanceof JwksUnavailable) return new RelytAuthError("jwks_unavailable");
  const code = typeof err === "object" && err !== null ? (err as { code?: unknown }).code : undefined;
  if (typeof code === "string" && JWKS_DOWN.has(code)) return new RelytAuthError("jwks_unavailable");
  return new RelytAuthError("invalid_token");
}

/** Process-wide remote JWKS cache: caches the key sets only, keyed by jwksUrl + cooldown + timeout + cacheMaxAge; LRU of 64. */
const jwksCache = new Map<string, JWTVerifyGetKey>();

function remoteKeys(r: Resolved): JWTVerifyGetKey {
  const key = JSON.stringify([r.jwksHref, r.cooldownMs, r.timeoutMs, CACHE_MAX_AGE_MS]);
  const hit = jwksCache.get(key);
  if (hit) {
    jwksCache.delete(key);
    jwksCache.set(key, hit);
    return hit;
  }
  const remote = createRemoteJWKSet(new URL(r.jwksHref), {
    cooldownDuration: r.cooldownMs,
    cacheMaxAge: CACHE_MAX_AGE_MS,
    timeoutDuration: r.timeoutMs,
  });
  // kid miss ⇒ rethrow as-is (invalid_token); any failure to obtain the key set ⇒ JwksUnavailable (the middleware answers 503, not 401)
  const getKey: JWTVerifyGetKey = async (header, token) => {
    try {
      return await remote(header, token);
    } catch (e) {
      const code = typeof e === "object" && e !== null ? (e as { code?: unknown }).code : undefined;
      if (typeof code === "string" && KID_MISS.has(code)) throw e;
      if (code === "ERR_JOSE_NOT_SUPPORTED" || code === "ERR_JWK_INVALID") throw e;
      throw new JwksUnavailable();
    }
  };
  jwksCache.set(key, getKey);
  if (jwksCache.size > JWKS_CACHE_LIMIT) jwksCache.delete(jwksCache.keys().next().value as string);
  return getKey;
}

async function verifyWith(r: Resolved, token: unknown): Promise<RelytClaims> {
  try {
    if (typeof token !== "string" || token === "") throw new RelytAuthError("invalid_token");
    const { payload } = await jwtVerify(token, remoteKeys(r), {
      algorithms: ALGORITHMS,
      issuer: r.issuer,
      audience: r.issuer,
      requiredClaims: REQUIRED_CLAIMS,
      clockTolerance: r.clockToleranceS,
      maxTokenAge: r.maxTokenAgeS,
    });
    // Post-check: jose's maxTokenAge only bounds the age of iat, not the issued lifetime
    const life = (payload.exp as number) - (payload.iat as number);
    if (!(life > 0 && life <= r.maxTokenAgeS)) throw new RelytAuthError("invalid_token");
    if (!checkClaimsShape(payload)) throw new RelytAuthError("invalid_claims");
    return structuredClone(payload) as RelytClaims;
  } catch (e) {
    const err = mapJoseError(e);
    emit(r, { type: "verify_failed", code: err.code, issuer: r.issuer });
    throw err;
  }
}

function emit(r: Resolved, e: AuthEvent): void {
  try {
    r.onEvent?.(e);
  } catch {
    // an observer callback must not affect the verification result
  }
}

export function createVerifier(o: VerifierOptions): (token: string) => Promise<RelytClaims> {
  const r = resolve(o);
  return (token) => verifyWith(r, token);
}

/** Claim options are resolved on every call; remote key sets are reused per cache key. */
export async function verifyToken(token: string, o: VerifierOptions): Promise<RelytClaims> {
  return verifyWith(resolve(o), token);
}
