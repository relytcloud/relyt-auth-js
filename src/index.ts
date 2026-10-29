// @relyt/auth main entry (Web APIs only: works in browsers, Node and the Next.js edge runtime).
export { RelytAuthError, type RelytAuthErrorCode, type AuthEvent } from "./errors.js";
export { CLAIM_KEYS, REGISTERED_CLAIM_KEYS, type RelytClaims } from "./claims.js";
export { createVerifier, verifyToken, type VerifierOptions } from "./verify.js";
export { createAuthClient, type AuthClient, type AuthClientOptions } from "./client.js";
export {
  startSocialSignIn,
  createSocialStart,
  completeSocialSignIn,
  exchangeHandoffCode,
  SOCIAL_PKCE_STORAGE_KEY,
  type StartSocialSignInOptions,
  type SocialStart,
  type CompleteSocialSignInOptions,
  type ExchangeHandoffCodeOptions,
  type SocialResponseMode,
} from "./social.js";
