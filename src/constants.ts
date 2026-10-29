// Duration constants that must match the Relyt auth service (copied; see test/package.test.ts).
/** Upper bound of a token's issued lifetime in seconds: default `maxTokenAgeS` for verification and the client's `exp − iat` upper bound. */
export const TOKEN_TTL_S = 900;
/** Upper bound of the clock tolerance in seconds: how long the auth service keeps a retired key in its JWKS after rotation, beyond the token TTL. */
export const MAX_CLOCK_TOLERANCE_S = 60;
