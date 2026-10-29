# @relyt/auth

Token tooling for Relyt managed auth:

- server-side JWT verification: `createVerifier` / `verifyToken` (EdDSA only, keys from the auth host's remote JWKS);
- a token cache for browsers and Node: `createAuthClient`;
- a Next.js middleware entry: `@relyt/auth/next` (`createAuthMiddleware`, `getClaims`, `setTokenCookie`, `clearTokenCookie`);
- cross-site social sign-in helpers: `startSocialSignIn` / `completeSocialSignIn` (browser) and `createSocialStart` / `exchangeHandoffCode` (server-side proxy).

The package uses Web APIs only (`fetch`, WebCrypto, `URL`, …), so the main entry runs in browsers, Node and the Next.js edge runtime. Its only runtime dependency is [`jose`](https://github.com/panva/jose).

## Install

```sh
npm install @relyt/auth
# or
pnpm add @relyt/auth
```

Requirements:

- Node.js 20 or later (the test suite runs on Node 22 and 24; CI also builds and smoke-tests the package on Node 20);
- ESM only (`"type": "module"`); TypeScript types are included;
- `next` is an optional peer dependency, needed only for `@relyt/auth/next`. Supported: **`^14.2.35` or `>=15.5.28 <16`**. The test suite runs on Next 15.5.28.

## Verifying tokens on the server

```ts
import { createVerifier, verifyToken, RelytAuthError } from "@relyt/auth";

const verify = createVerifier({ issuer: "https://<authHost>" });

try {
  const claims = await verify(token); // RelytClaims: sub, iss, aud, iat, exp, role, app_role, cv, o?, act?
} catch (e) {
  if (e instanceof RelytAuthError && e.code === "jwks_unavailable") {
    // keys could not be fetched: answer 503, not 401
  }
  // invalid_token / invalid_claims ⇒ 401
}

// One-off form: options are resolved on every call; the remote key set is still shared per cache key.
const claims = await verifyToken(token, { issuer: "https://<authHost>" });
```

What is fixed and what is configurable:

- `algorithms` is pinned to `["EdDSA"]` and cannot be changed. `alg: none`, HMAC and other algorithms are rejected, and `jku` / `x5u` / embedded `jwk` headers are never followed.
- `issuer` is the expected value of **both** `iss` and `aud`. It must be exactly an origin (`https://host[:port]`, no trailing slash, no path, nothing URL normalization would rewrite) because the token's `iss` is compared to it verbatim. Plain `http` is accepted only for `localhost`, `127.0.0.1` and `[::1]`.
- `jwksUrl` defaults to `${issuer}/.well-known/jwks.json`; its origin follows the same rule as `issuer`.
- `clockToleranceS` defaults to 30 and must be ≤ 60 (after a key rotation, the auth host keeps the retired key in its JWKS for only 60 s beyond the token lifetime).
- `maxTokenAgeS` defaults to 900. On top of jose's `maxTokenAge` (which bounds the age of `iat`), the SDK also rejects tokens whose issued lifetime `exp − iat` is not in `(0, maxTokenAgeS]`.
- `cooldownMs` (default 30 000) and `timeoutMs` (default 5 000) control the remote JWKS fetch. The key set is cached per process (keyed by JWKS URL, cooldown and timeout, LRU of 64 entries) and kept for up to 5 minutes; an unknown `kid` triggers an earlier refetch, at most once per cooldown.
- `onEvent` receives `verify_failed` events (code and issuer only, never the token).
- Required claims: `exp`, `iat`, `sub`. The payload shape is checked as well (`role` must be `"authenticated"`, `cv` an integer, `o` / `act` well-formed when present); unknown extra claims are preserved.

## Client token cache: `createAuthClient`

```ts
import { createAuthClient } from "@relyt/auth";

// Cookie mode (same-site app): the browser sends the auth host's session cookie.
const client = createAuthClient({ authUrl: "https://<authHost>" });

// Bearer mode (cross-site app or Node): you store the session token and provide it.
let sessionToken: string | null = null;
const bearerClient = createAuthClient({
  authUrl: "https://<authHost>",
  sessionToken: () => sessionToken,
  onSessionToken: (t) => (sessionToken = t),
});

const jwt = await client.getToken(); // cached; refreshed `refreshAheadS` (default 120 s) before expiry
await fetch("/api/todos", { headers: { authorization: `Bearer ${jwt}` } });

client.peekToken(); // cached token if still valid locally, else null (never triggers a request)
await client.getSession(); // session object, or null when signed out; may prime the token cache
client.clear(); // sign-out: drops the cache and cancels in-flight refreshes and retry waits
```

- **The client only carries tokens; it never verifies them.** Trust decisions happen only on the server (`verifyToken` / `getClaims`).
- Concurrent `getToken()` calls share one request. A result that arrives after `clear()` is never written back to the cache.
- Retries: only a `503` with a readable `Retry-After` header is retried, at most 3 times, waiting `Retry-After` clamped to [0, 10] s (2 s when the value is invalid). Everything else fails immediately.
- **Worst-case latency of `getToken()` is 90 s**: at most 4 requests of `timeoutMs` (default 15 s) each, plus 3 backoff waits of at most 10 s (4 × 15 + 3 × 10).
- `refreshAheadS` must be within [10, 600]; `timeoutMs` must be an integer within [1 000, 60 000].

## Next.js: `@relyt/auth/next`

```ts
// middleware.ts
import { createAuthMiddleware } from "@relyt/auth/next";
export const middleware = createAuthMiddleware({
  issuer: process.env.RELYT_AUTH_ISSUER!, // "https://<authHost>", from configuration only
  signInUrl: "/sign-in",
  publicPaths: ["/sign-in", "/api/public", /^\/_next\//],
});
export const config = { matcher: ["/((?!_next/static|favicon.ico).*)"] };

// app/api/x/route.ts
import { getClaims, RelytAuthUnavailableError } from "@relyt/auth/next";
export async function GET(req: Request) {
  try {
    const c = await getClaims(req, { issuer: process.env.RELYT_AUTH_ISSUER! });
    if (!c) return new Response(null, { status: 401 });
    return Response.json({ sub: c.sub });
  } catch (e) {
    if (e instanceof RelytAuthUnavailableError) return new Response(null, { status: 503, headers: { "retry-after": "2" } });
    throw e;
  }
}
```

- **Where the token comes from**: first `Authorization: Bearer`, then the cookie `__Host-relyt-at` (change it with `cookieName`; the middleware, `getClaims` and `setTokenCookie` share the same default). A cookie name that occurs more than once is treated as no token. **A present `Authorization` header is authoritative**: if its value is not a valid `Bearer <token>` (e.g. `Basic …`, or empty), the request has no token and there is no fallback to the cookie. With `cookieOnApi: false`, API paths accept bearer tokens only; the route-side counterpart is `getClaims(req, o, { cookie: false })` (default `true`), which reads `Authorization` only.
- **Failure behaviour**: API paths (`apiPrefix`, default `/api/`; a prefix ending in `/` also covers the bare path `/api`; or any request whose `Accept` contains `application/json`) get 401 `{"error":"unauthorized"}`, with `WWW-Authenticate: Bearer` when there is no token and `Bearer error="invalid_token"` when the token is invalid. Pages get 307 for GET/HEAD and 303 for other methods, redirecting to `signInUrl?next=<relative path>` (if `next`, once decoded, contains a control character / DEL, starts with `//` or `/\`, contains `\`, or resolves cross-origin, it becomes `/`). When the JWKS is unavailable the answer is 503 `{"error":"auth_unavailable"}` with `Retry-After: 2`.
- **Claims are never forwarded**: the middleware strips every incoming `x-relyt-*` header and never writes claim headers. Route handlers must call `getClaims` themselves to re-verify (so a route missed by the matcher, or a bypassed middleware, never makes a forged header effective). By default `getClaims` throws `RelytAuthUnavailableError` when the JWKS is unavailable; pass `{ onUnavailable: "null" }` to get `null` instead.
- **The issuer comes from configuration, not from the request**: `issuer` is taken from the options only, never from `Host` / `X-Forwarded-Host`, and the token's `iss` / `aud` are compared to it verbatim. Only a relative `signInUrl` is resolved against the request URL (affecting just the redirect target's origin). **Use an absolute `signInUrl` in production**: a relative one is resolved against the request's `Host`, so a proxy that passes through a forged `Host` changes the redirect target. 401 / 307 / 303 / 503 responses all carry `Cache-Control: no-store`.
- **Only the server writes the cookie**: `setTokenCookie(res, token)` writes `HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=min(900, exp − now)` (an already expired token clears the cookie instead). Sign-out must call `clearTokenCookie(res)` on the server (same attributes plus `Max-Age=0`); browser JS cannot clear an HttpOnly cookie. `setTokenCookie` throws `RelytAuthError("config")` if the serialized cookie exceeds 4000 bytes (browsers silently drop oversized cookies).
- **The `__Host-` prefix requires `Secure`**: Safari refuses `__Host-` / `Secure` cookies on `http://localhost`, so develop locally over https, or use Chrome / Firefox.
- **CSRF**: cookie-authenticated APIs have a CSRF surface (`SameSite=Lax` blocks cross-site POSTs, but not same-site subdomains or side-effecting GETs). **Use bearer tokens for APIs and the cookie only for page navigation**; set `cookieOnApi: false` where needed.
- **Tokens without `kid`**: while the JWKS holds two keys (rotation overlap), a token without a `kid` header cannot select a key and is always rejected (401 / `null`).
- **Known limitation**: on a cold auth host (one that has not yet loaded the tenant's configuration), a busy / cold-read failure makes the CORS preflight of a non-simple cross-origin request itself return 503. The browser only sees a `TypeError` and cannot read `Retry-After`. By design the client does not retry network errors and fails immediately; in cookie mode the public 503 of the auth routes is likewise unreadable. Non-browser callers are not affected.

## Cross-site social sign-in: `startSocialSignIn` / `completeSocialSignIn`

When the app and the auth host are on different sites, social sign-in uses "auth host start endpoint + single-use handoff code + PKCE exchange" and does not rely on cross-site cookies.

```ts
import { createAuthClient, startSocialSignIn, completeSocialSignIn } from "@relyt/auth";

// Sign-in button: generates a PKCE verifier, stores it in sessionStorage, navigates the top-level window to the auth host
await startSocialSignIn({ authUrl, provider: "google", callbackURL: "https://app.example.com/auth/callback" });

// Callback page https://app.example.com/auth/callback
let sessionToken: string | null = null;
const client = createAuthClient({ authUrl, sessionToken: () => sessionToken, onSessionToken: (t) => (sessionToken = t) });
try {
  await completeSocialSignIn({ authUrl, client, onSessionToken: (t) => (sessionToken = t) });
} catch (e) {
  // RelytAuthError: oauth_error (e.oauthError) / no_pending_sign_in / missing_code /
  // invalid_handoff_code / invalid_origin / rate_limited (e.retryAfterS) / unavailable / network / bad_response
}
```

- `responseMode` defaults to `"fragment"` (the code arrives as `#relyt_code=` and never reaches server logs or the Referer); with `"query"` it arrives as `?relyt_code=`.
- The very first thing `completeSocialSignIn` does is remove `relyt_code` / `error` from the address bar with `history.replaceState`. The verifier is taken out once and deleted. If this tab has no pending sign-in record, it **never exchanges** the code (defending against planted codes) and throws `no_pending_sign_in`.
- The exchange is not retried: a code is valid for 60 s, single use, and invalidated on submission. After a failure, let the user click sign-in again.
- `completeSocialSignIn` is re-entrant: calling it again while one call is in progress (React StrictMode's double effect) returns the same promise, so the code is exchanged once and `onSessionToken` is called once. The pending record is bound to `authUrl` and valid for 10 minutes; a mismatched or expired record is handled as `no_pending_sign_in`.
- `e.retryAfterS` on `rate_limited` uses the same parser as `createAuthClient`: clamped to ≤ 10 s, 2 when the value is invalid, `undefined` when there is no `Retry-After` header.
- Server-side proxy (Node / Next route handler, query mode): start with the pure builder `createSocialStart` (touches neither sessionStorage nor location, works in browsers and Node) and exchange with `exchangeHandoffCode({ authUrl, code, codeVerifier })`, which returns `{ sessionToken }` and sends no Origin. Your server keeps the verifier and binds it to the initiating user's own session:

  ```ts
  // GET /login/google (server)
  const { url, codeVerifier } = await createSocialStart({ authUrl, provider: "google", callbackURL: "https://app.example.com/auth/callback", responseMode: "query" });
  session.relytVerifier = codeVerifier;           // store in your own server-side session (bound to an HttpOnly cookie); never log it
  return Response.redirect(url, 302);

  // GET /auth/callback?relyt_code=… (server)
  const v = session.relytVerifier; delete session.relytVerifier;   // single use
  const { sessionToken } = await exchangeHandoffCode({ authUrl, code, codeVerifier: v });
  ```
  The auth host rate-limits failed exchanges per source IP (10 per 60 s). In proxy mode all users share your server's egress IP, so one user's failures eat into everyone's budget.

### Callback page rules

These are a security boundary: PKCE cannot stop a flow that the attacker started themselves; the defence is the integrity of the callback page.

1. Call `completeSocialSignIn` **before loading any third-party script** (analytics, ads, chat widgets and the like all go after it).
2. The callback page **must not do an HTTP redirect** before the code has been read, and must not contain an open redirect (a fragment is carried along or lost on redirect).
3. Register the **exact** callback URLs in the console (`callbackURL` / `errorCallbackURL` / `newUserCallbackURL` are matched verbatim, no wildcards), and add the app's **exact origin** (e.g. `https://app.example.com`) to `trustedOrigins`, without wildcards. If the origin is not registered, the CORS preflight of the exchange request fails in the browser and the SDK can only report `network` (it cannot read the 403, so it will not be `invalid_origin`); when troubleshooting, check `trustedOrigins` first. `invalid_origin` only appears for non-browser callers that send their own `Origin` header.
4. In query mode the code appears in the access logs of the server hosting the callback page; use it only when the exchange must be proxied by your server. Add `<meta name="referrer" content="no-referrer">` to the callback page so the code is not sent in the Referer to other resources on the page.
5. **Every page that can receive the redirect back** (`callbackURL`, `newUserCallbackURL`, `errorCallbackURL`) must call `completeSocialSignIn`; otherwise the code or the error stays in the address bar and the pending record is never consumed.
6. The page that starts the sign-in and the callback page must have **exactly the same origin** (`www.example.com` and `example.com` differ): the verifier lives in sessionStorage, which is isolated per origin, so after an origin change it cannot be read and the result is `no_pending_sign_in`.

## Errors

Every failure is a `RelytAuthError` with a stable `code`, a `retryable` flag and a fixed English `message`. Messages never include tokens, response bodies or URL query strings.

| `code` | Meaning | `retryable` by default | Extra fields |
|---|---|---|---|
| `unauthenticated` | not signed in (401 / 403 from the auth host, or the session-token provider failed) | no | `status` |
| `unavailable` | auth service unavailable (503) | yes (no when `Retry-After` is missing or after a failed exchange) | `status` |
| `network` | network error or timeout | yes (no for the social exchange) | |
| `bad_response` | unexpected response from the auth host | no | `status` |
| `invalid_token` | signature, algorithm, issuer, audience or time check failed | no | |
| `invalid_claims` | payload shape is invalid | no | |
| `jwks_unavailable` | signing keys could not be fetched | yes | |
| `config` | invalid option | no | `option` (option name only, never the value) |
| `invalid_handoff_code` | invalid or expired sign-in code (400) | no | `status` |
| `invalid_origin` | origin not trusted by the auth host (403, non-browser callers only) | no | `status` |
| `rate_limited` | too many requests (429) | no | `status`, `retryAfterS` |
| `no_pending_sign_in` | no pending sign-in in this browser session | no | |
| `missing_code` | sign-in code missing from the callback URL | no | |
| `oauth_error` | the social provider reported an error | no | `oauthError` (filtered to `^[a-z0-9_]{1,64}$`, otherwise `"unknown"`) |

`@relyt/auth/next` additionally exports `RelytAuthUnavailableError` (a `RelytAuthError` with code `jwks_unavailable`), thrown by `getClaims` so route handlers can answer 503.

## Security notes

- Tokens, session tokens, handoff codes, PKCE verifiers and cookie values never appear in errors, events or logs. The SDK itself never calls `console`.
- The issuer always comes from configuration; it is never derived from the token or the request.
- Verification fails closed: any error the SDK does not recognise becomes `invalid_token`.
- Report security issues privately through [GitHub security advisories](https://github.com/relytcloud/relyt-auth-js/security/advisories/new) rather than public issues.

## Development

This repository uses **pnpm** (version pinned in `packageManager`; enable it with `corepack enable`).

```sh
pnpm install
pnpm run typecheck
pnpm test          # builds dist/ first, then runs vitest (Node 22 or 24)
pnpm run build
npm pack --dry-run # inspect the published file list
```

## License

[MIT](./LICENSE)
