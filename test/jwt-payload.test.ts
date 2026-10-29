// The shared "read payload without verifying" helper used by client.ts and next.ts.
import { describe, expect, it } from "vitest";
import { decodePayloadUnverified } from "../src/jwt-payload.js";
import { b64u } from "./helpers/issuer.js";

const tok = (payload: string) => `${b64u('{"alg":"ES256"}')}.${b64u(payload)}.sig`;

describe("decodePayloadUnverified", () => {
  it("decodes non-ASCII claims as UTF-8", () => {
    // Built at runtime so the source stays ASCII-only: two CJK ideographs followed by Latin-1 text.
    const name = String.fromCodePoint(0x5f20, 0x4e09) + "·Zoë";
    const p = decodePayloadUnverified(tok(JSON.stringify({ name, exp: 1 })));
    expect(p).toEqual({ name, exp: 1 });
  });
  it.each([
    ["empty segment", `${b64u("{}")}..sig`],
    ["empty signature segment", `${b64u("{}")}.${b64u('{"exp":1}')}.`],
    ["two segments", `${b64u("{}")}.${b64u('{"exp":1}')}`],
    ["four segments", `a.${b64u('{"exp":1}')}.b.c`],
    ["not JSON", tok("not json")],
    ["array", tok("[1]")],
    ["null", tok("null")],
    ["number", tok("1")],
    ["not base64", "a.@@@.b"],
  ])("%s ⇒ null", (_n, t) => {
    expect(decodePayloadUnverified(t)).toBeNull();
  });
  it("non-string ⇒ null", () => {
    expect(decodePayloadUnverified(1 as unknown as string)).toBeNull();
  });
});
