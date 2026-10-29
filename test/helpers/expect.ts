import { expect } from "vitest";
import { RelytAuthError, type AuthEvent } from "../../src/errors.js";

/** Every failure path funnels through here: the code matches, and neither the error nor any event payload contains the token or any of its segments. */
export const seenTokens: string[] = [];

export async function expectReject(
  p: Promise<unknown>,
  code: string,
  token: string,
  events: AuthEvent[] = [],
): Promise<RelytAuthError> {
  let err: unknown;
  try {
    await p;
  } catch (e) {
    err = e;
  }
  expect(err, "expected rejection").toBeInstanceOf(RelytAuthError);
  const e = err as RelytAuthError;
  expect(e.code).toBe(code);
  assertNoLeak(token, [e.message, JSON.stringify(e), String((e as { cause?: unknown }).cause ?? ""), String(e.stack ?? ""), JSON.stringify(events)]);
  return e;
}

export function assertNoLeak(token: string, surfaces: string[]): void {
  seenTokens.push(token);
  const parts = [token, ...token.split(".")].filter((s) => s.length >= 8);
  for (const s of surfaces) for (const part of parts) expect(s.includes(part), "token fragment leaked").toBe(false);
}
