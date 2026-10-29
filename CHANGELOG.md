# Changelog

All notable changes to this package are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the package uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-29

Initial release.

### Added

- `createVerifier` / `verifyToken`: server-side JWT verification (EdDSA only, remote JWKS with a per-process cache,
  issuer = audience pinned from configuration, lifetime post-check, payload shape check).
- `createAuthClient`: browser / Node token cache with single-flight refresh, generation-guarded `clear()`,
  `Retry-After`-driven retries on 503 and per-request timeouts; cookie and bearer modes.
- `@relyt/auth/next`: `createAuthMiddleware`, `getClaims`, `setTokenCookie`, `clearTokenCookie`,
  `RelytAuthUnavailableError`, `safeNext`, `DEFAULT_COOKIE_NAME`.
- Cross-site social sign-in: `startSocialSignIn`, `completeSocialSignIn`, `createSocialStart`,
  `exchangeHandoffCode` (PKCE S256, single-use handoff codes).
- `RelytAuthError` with stable error codes.

[0.1.0]: https://github.com/relytcloud/relyt-auth-js/releases/tag/v0.1.0
