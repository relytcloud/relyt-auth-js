// Reads a JWT payload without verifying it (shared by client.ts and next.ts).
// Only for local hints such as lifetime / Max-Age; trust decisions must go through verifyToken. Web APIs only (edge / browser).

/** Three non-empty segments and a base64url UTF-8 JSON object payload ⇒ that object; otherwise null. Never throws. */
export function decodePayloadUnverified(token: string): Record<string, unknown> | null {
  if (typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((p) => p === "")) return null;
  try {
    const b64 = parts[1]!.replace(/-/g, "+").replace(/_/g, "/");
    const bin = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
    const payload: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(bin, (c) => c.charCodeAt(0))));
    if (typeof payload !== "object" || payload === null || Array.isArray(payload)) return null;
    return payload as Record<string, unknown>;
  } catch {
    return null;
  }
}
