<?php

declare(strict_types=1);

namespace GhostAuth\Contracts;

/**
 * SsoProviderInterface
 *
 * Contract for OIDC (OpenID Connect) / Enterprise SSO integrations.
 * Implementations connect to identity providers like Okta, Azure AD,
 * Auth0, PingIdentity, or any standards-compliant OIDC IdP.
 *
 * @package GhostAuth\Contracts
 */
interface SsoProviderInterface extends AuthenticationProviderInterface
{
    /**
     * Fetch and cache the OIDC Discovery Document from the provider's
     * well-known endpoint (/.well-known/openid-configuration).
     * Called once at boot; results should be cached for the TTL the IdP specifies.
     *
     * @return array<string, mixed>  Parsed discovery document.
     *
     * @throws \GhostAuth\Exceptions\OidcException  On fetch or parse failure.
     */
    public function discoverConfiguration(): array;

    /**
     * Generate the OIDC Authorization URL with a CSPRNG `nonce` and `state`
     * for CSRF and replay protection.
     *
     * @param  array<string, string> $additionalParams  Extra query params (e.g. login_hint).
     * @return string  Full authorization URL to redirect the end-user to.
     */
    public function getAuthorizationUrl(array $additionalParams = []): string;

    /**
     * Validate and decode an OIDC ID Token.
     * MUST verify: signature (against JWKS), `iss`, `aud`, `exp`, `iat`, `nonce`.
     *
     * @param  string $idToken  The raw OIDC ID Token JWT.
     * @return array<string, mixed>  Decoded and verified claims.
     *
     * @throws \GhostAuth\Exceptions\OidcException  On any validation failure.
     */
    public function validateIdToken(string $idToken): array;
}
