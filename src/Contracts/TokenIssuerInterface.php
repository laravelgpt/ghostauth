<?php

declare(strict_types=1);

namespace GhostAuth\Contracts;

/**
 * TokenIssuerInterface
 *
 * Abstracts token issuance so Providers are decoupled from the
 * underlying mechanism (JWT vs. opaque session token vs. database token).
 *
 * To switch from JWT to session-based auth, swap the TokenIssuer
 * implementation — zero Provider code changes required.
 *
 * @package GhostAuth\Contracts
 */
interface TokenIssuerInterface
{
    /**
     * Issue a new token for the given authenticated user.
     *
     * @param  AuthenticatableInterface $user         The authenticated user.
     * @param  array<string, mixed>     $extraClaims  Additional payload to embed.
     * @return string                                 The raw token string (JWT, session ID, etc.)
     *
     * @throws \GhostAuth\Exceptions\TokenException  On signing/issuance failure.
     */
    public function issue(AuthenticatableInterface $user, array $extraClaims = []): string;

    /**
     * Validate and decode a previously issued token.
     * Returns the decoded payload on success.
     *
     * @param  string $token  The raw token string.
     * @return array<string, mixed>  Decoded claims/payload.
     *
     * @throws \GhostAuth\Exceptions\TokenException  On invalid, expired, or tampered token.
     */
    public function verify(string $token): array;

    /**
     * Revoke/invalidate a token.
     * For stateless JWT, this typically adds the token to a denylist cache.
     * For session tokens, it deletes the session record.
     *
     * @param  string $token  The raw token to revoke.
     * @return bool           True if successfully revoked.
     */
    public function revoke(string $token): bool;
}
