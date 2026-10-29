/** Unified SDK error. `message` is a fixed English phrase per code and never includes tokens, response bodies or URL query strings. */
export type RelytAuthErrorCode =
  | "unauthenticated"
  | "unavailable"
  | "network"
  | "bad_response"
  | "invalid_token"
  | "invalid_claims"
  | "jwks_unavailable"
  | "config"
  // cross-site social sign-in
  | "invalid_handoff_code"
  | "invalid_origin"
  | "rate_limited"
  | "no_pending_sign_in"
  | "missing_code"
  | "oauth_error";

const MESSAGES: Record<RelytAuthErrorCode, string> = {
  unauthenticated: "not authenticated",
  unavailable: "auth service unavailable",
  network: "network error",
  bad_response: "unexpected response from auth service",
  invalid_token: "invalid token",
  invalid_claims: "invalid token claims",
  jwks_unavailable: "signing keys unavailable",
  config: "invalid configuration",
  invalid_handoff_code: "invalid or expired sign-in code",
  invalid_origin: "origin not trusted by auth service",
  rate_limited: "too many requests",
  no_pending_sign_in: "no pending sign-in in this browser session",
  missing_code: "sign-in code missing from callback URL",
  oauth_error: "social sign-in failed",
};

const RETRYABLE: ReadonlySet<RelytAuthErrorCode> = new Set(["unavailable", "network", "jwks_unavailable"]);

export class RelytAuthError extends Error {
  readonly code: RelytAuthErrorCode;
  readonly retryable: boolean;
  readonly status?: number;
  /** `config` only: name of the offending option (option names are not secret). */
  readonly option?: string;
  /** `rate_limited` only: integer seconds from the `retry-after` response header (when present and valid). */
  readonly retryAfterS?: number;
  /** `oauth_error` only: the `error` value from the callback URL, filtered by `^[a-z0-9_]{1,64}$`, otherwise `"unknown"`. */
  readonly oauthError?: string;

  constructor(
    code: RelytAuthErrorCode,
    o: { retryable?: boolean; status?: number; option?: string; retryAfterS?: number; oauthError?: string } = {},
  ) {
    super(MESSAGES[code]);
    this.name = "RelytAuthError";
    this.code = code;
    this.retryable = o.retryable ?? RETRYABLE.has(code);
    if (o.status !== undefined) this.status = o.status;
    if (o.option !== undefined) this.option = o.option;
    if (o.retryAfterS !== undefined) this.retryAfterS = o.retryAfterS;
    if (o.oauthError !== undefined) this.oauthError = o.oauthError;
  }
}

/** Event payload: codes and counters only, never a token. */
export type AuthEvent = {
  type: "token_refresh" | "retry" | "verify_failed" | "jwks_fetch";
  code?: string;
  status?: number;
  attempt?: number;
  kid?: string;
  issuer?: string;
};
