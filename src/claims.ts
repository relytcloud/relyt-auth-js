/**
 * Token payload type. Mirrors the claim set issued by the Relyt auth service; if the service adds or renames a
 * claim, update `CLAIM_KEYS` and `checkClaimsShape` in this file together.
 */
export interface RelytClaims {
  sub: string;
  iss: string;
  aud: string | string[];
  iat: number;
  exp: number;
  nbf?: number;
  role: "authenticated";
  app_role: string | null;
  cv: number;
  o?: { id: string; slug: string; role: string; perms: string[] | null };
  act?: { sub: string };
  /** Forward compatible: unknown extra claims are preserved as-is. */
  [extra: string]: unknown;
}

export const CLAIM_KEYS = ["role", "app_role", "o", "cv", "act"] as const;
export const REGISTERED_CLAIM_KEYS = ["sub", "iss", "aud", "exp", "iat"] as const;

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const isStr = (v: unknown): v is string => typeof v === "string";

/** Payload shape check only. Time and issuer checks are done by jose plus the post-checks in verify.ts. */
export function checkClaimsShape(p: Record<string, unknown>): boolean {
  if (!isStr(p.sub)) return false;
  if (p.role !== "authenticated") return false;
  if (!(p.app_role === null || isStr(p.app_role))) return false;
  if (!Number.isInteger(p.cv)) return false;
  if (p.o !== undefined) {
    const o = p.o;
    if (!isObj(o) || !isStr(o.id) || !isStr(o.slug) || !isStr(o.role)) return false;
    if (!(o.perms === null || (Array.isArray(o.perms) && o.perms.every(isStr)))) return false;
  }
  if (p.act !== undefined) {
    if (!isObj(p.act) || !isStr(p.act.sub)) return false;
  }
  return true;
}
