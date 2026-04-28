<?php

declare(strict_types=1);

namespace GhostAuth\Tokens;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\SignatureInvalidException;
use GhostAuth\Contracts\AuthenticatableInterface;
use GhostAuth\Contracts\TokenIssuerInterface;
use GhostAuth\Exceptions\TokenException;
use Psr\SimpleCache\CacheInterface;

/**
 * JwtIssuer
 *
 * Stateless token issuance and verification using RS256 (RSA + SHA-256) by default,
 * with optional HS256 (HMAC) for environments where RSA key management is not available.
 *
 * Security posture:
 *  - RS256 (asymmetric): Private key signs; public key verifies.
 *    Allows resource servers to verify tokens without the signing secret.
 *  - HS256 (symmetric): Single shared secret. Simpler but all parties share the secret.
 *
 * JWT revocation:
 *  Stateless JWTs cannot be invalidated server-side by default.
 *  We solve this with a denylist cache (PSR-16): on revoke(), the token's `jti`
 *  (JWT ID — a CSPRNG UUID) is written to cache with TTL = token remaining lifetime.
 *  verify() checks the denylist before returning the payload.
 *
 * @package GhostAuth\Tokens
 */
final class JwtIssuer implements TokenIssuerInterface
{
    /**
     * Supported signing algorithms.
     */
    public const ALGO_RS256 = 'RS256';
    public const ALGO_HS256 = 'HS256';

    /**
     * Cache key prefix for the JWT denylist.
     */
    private const DENYLIST_PREFIX = 'ghostauth:jwt:deny:';

    /**
     * @param string              $algorithm        Signing algorithm: RS256 or HS256.
     * @param string              $privateKeyOrSecret  PEM private key (RS256) or HMAC secret (HS256).
     * @param string|null         $publicKey           PEM public key (RS256 only; null for HS256).
     * @param string              $issuer              JWT `iss` claim — identifies your application.
     * @param string              $audience            JWT `aud` claim — the intended recipient/API.
     * @param int                 $ttlSeconds          Token lifetime in seconds (default: 1 hour).
     * @param CacheInterface|null $denylistCache       PSR-16 cache for revoked token JTIs.
     *                                                 If null, revoke() is a no-op (tokens live until expiry).
     */
    public function __construct(
        private readonly string $algorithm,
        private readonly string $privateKeyOrSecret,
        private readonly ?string $publicKey,
        private readonly string $issuer,
        private readonly string $audience,
        private readonly int $ttlSeconds = 3600,
        private readonly ?CacheInterface $denylistCache = null,
    ) {
        if (! in_array($algorithm, [self::ALGO_RS256, self::ALGO_HS256], true)) {
            throw new TokenException("Unsupported algorithm: {$algorithm}. Use RS256 or HS256.");
        }

        if ($algorithm === self::ALGO_RS256 && $publicKey === null) {
            throw new TokenException('RS256 requires a public key for verification.');
        }
    }

    // -------------------------------------------------------------------------
    // TokenIssuerInterface implementation
    // -------------------------------------------------------------------------

    /**
     * Issue a signed JWT for the given authenticated user.
     *
     * Payload structure (registered claims per RFC 7519):
     *   iss  — Issuer (your app)
     *   sub  — Subject (user's unique identifier)
     *   aud  — Audience (your API / resource server)
     *   iat  — Issued At (Unix timestamp)
     *   exp  — Expiration Time (iat + ttlSeconds)
     *   jti  — JWT ID (CSPRNG UUID for revocation tracking)
     *
     * Plus any custom claims from AuthenticatableInterface::getJwtClaims()
     * and the $extraClaims parameter.
     *
     * @throws TokenException  On signing failure.
     */
    public function issue(AuthenticatableInterface $user, array $extraClaims = []): string
    {
        $now = time();

        // Generate a cryptographically random JWT ID for denylist tracking.
        // bin2hex(random_bytes(16)) produces 32 hex chars — 128 bits of entropy.
        $jti = bin2hex(random_bytes(16));

        $payload = array_merge(
            // Custom user claims first (lower priority — standard claims win)
            $user->getJwtClaims(),
            $extraClaims,
            // Standard claims last — these are authoritative and must not be overridden
            [
                'iss' => $this->issuer,
                'sub' => (string) $user->getAuthIdentifier(),
                'aud' => $this->audience,
                'iat' => $now,
                'exp' => $now + $this->ttlSeconds,
                'jti' => $jti,
            ],
        );

        // Include email if available (common convenience claim)
        if ($user->getEmail() !== null) {
            $payload['email'] = $user->getEmail();
        }

        try {
            return JWT::encode(
                payload: $payload,
                key: $this->privateKeyOrSecret,
                alg: $this->algorithm,
            );
        } catch (\Throwable $e) {
            throw new TokenException(
                message: 'JWT signing failed: ' . $e->getMessage(),
                code: 0,
                previous: $e,
            );
        }
    }

    /**
     * Verify a JWT and return its decoded payload.
     *
     * Verifies:
     *  - Signature (against public key or shared secret)
     *  - Expiration (`exp`)
     *  - Not-before (`nbf`, if present)
     *  - Denylist (`jti` not revoked)
     *
     * @throws TokenException  On invalid, expired, or revoked token.
     */
    public function verify(string $token): array
    {
        try {
            $decoded = JWT::decode(
                jwt: $token,
                keyOrKeyArray: $this->buildVerificationKey(),
            );
        } catch (ExpiredException $e) {
            throw new TokenException('Token has expired.', 401, $e);
        } catch (BeforeValidException $e) {
            throw new TokenException('Token is not yet valid.', 401, $e);
        } catch (SignatureInvalidException $e) {
            throw new TokenException('Token signature is invalid.', 401, $e);
        } catch (\Throwable $e) {
            throw new TokenException('Token verification failed: ' . $e->getMessage(), 401, $e);
        }

        // Cast stdClass to array for a consistent return type
        $payload = (array) $decoded;

        // Check denylist — token may have been explicitly revoked (e.g. logout)
        if ($this->denylistCache !== null && isset($payload['jti'])) {
            $denyKey = self::DENYLIST_PREFIX . $payload['jti'];
            if ($this->denylistCache->has($denyKey)) {
                throw new TokenException('Token has been revoked.', 401);
            }
        }

        return $payload;
    }

    /**
     * Revoke a token by adding its `jti` to the denylist cache.
     * The cache entry TTL is set to the token's remaining lifetime so the
     * denylist entry expires automatically — no manual cleanup required.
     *
     * Returns false (gracefully) if no cache is configured or the token
     * has no `jti` claim — log the condition but do not throw.
     */
    public function revoke(string $token): bool
    {
        if ($this->denylistCache === null) {
            // No denylist configured — revocation is not supported.
            // This is not an error; the token will expire naturally.
            return false;
        }

        try {
            // Decode WITHOUT verifying expiry for revocation — we need the jti even
            // if the token just expired (e.g. a logout call made milliseconds late).
            $payload = (array) JWT::decode(
                jwt: $token,
                keyOrKeyArray: $this->buildVerificationKey(),
            );
        } catch (\Throwable) {
            // If we can't even decode it, there's nothing to revoke.
            return false;
        }

        if (! isset($payload['jti'], $payload['exp'])) {
            return false;
        }

        $remainingTtl = max(1, (int) $payload['exp'] - time());
        $denyKey = self::DENYLIST_PREFIX . $payload['jti'];

        return $this->denylistCache->set($denyKey, true, $remainingTtl);
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Build the verification key in the format firebase/php-jwt expects.
     *
     * @return Key|string
     */
    private function buildVerificationKey(): Key|string
    {
        if ($this->algorithm === self::ALGO_RS256) {
            // RS256: verify with the public key
            return new Key($this->publicKey, self::ALGO_RS256);
        }

        // HS256: verify with the shared secret
        return new Key($this->privateKeyOrSecret, self::ALGO_HS256);
    }
}
