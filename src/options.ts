// Shared option validation (used by verify.ts, client.ts and social.ts).
import { RelytAuthError } from "./errors.js";

/** Numeric option: undefined ⇒ dflt; non-finite or failing `ok` ⇒ `config` (carries the option name only, never the value). */
export function num(v: unknown, dflt: number, option: string, ok: (n: number) => boolean): number {
  if (v === undefined) return dflt;
  if (typeof v !== "number" || !Number.isFinite(v) || !ok(v)) throw new RelytAuthError("config", { option });
  return v;
}
