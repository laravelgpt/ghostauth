<?php

declare(strict_types=1);

namespace GhostAuth\Providers;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use GhostAuth\Auth\AuthResult;
use GhostAuth\Contracts\AuthResultInterface;
use GhostAuth\Contracts\SsoProviderInterface;
use GhostAuth\Contracts\TokenIssuerInterface;
use GhostAuth\Contracts\UserProviderInterface;
use GhostAuth\Exceptions\GhostAuthException;
use GhostAuth\Exceptions\OidcException;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Psr\SimpleCache\CacheInterface;

/**
 * OidcProvider
 *
 * OIDC (OpenID Connect) / Enterprise SSO provider.
 * Compatible with Okta, Auth0, Azure AD (Entra ID), Google Workspace,
 * and any standards-compliant OIDC IdP.
 *
 * Security validations per OIDC Core 1.0 §3.1.3.7:
 *   ✓ Signature verification (via JWKS from discovery document)
 *   ✓ `iss` (issuer) claim validation
 *   ✓ `aud` (audience) must contain our client_id
 *   ✓ `exp` (expiration) must be in the future
 *   ✓ `iat` (issued at) checked for clock skew
 *   ✓ `nonce` validation (anti-replay)
 *   ✓ State parameter CSRF protection
 *
 * NOTE: Full JWKS rotation and at_hash validation are noted as TODO
 * for the post-MVP v1.1 milestone.
 *
 * Expected credentials for authenticate():
 *   ['id_token' => '...', 'state' => '...', 'nonce' => '...']
 *
 * @package GhostAuth\Providers
 */
final class OidcProvider implements SsoProviderInterface
{
    private const CACHE_DISCOVERY_PREFIX = 'ghostauth:oidc:discovery:';
    private const CACHE_STATE_PREFIX     = 'ghostauth:oidc:state:';
    private const CACHE_NONCE_PREFIX     = 'ghostauth:oidc:nonce:';
    private const DISCOVERY_TTL          = 3600;  // 1 hour cache for discovery doc
    private const STATE_TTL              = 600;   // 10 min for state/nonce

    /** @var array<string, mixed>|null  Cached discovery document */
    private ?array $discoveryDoc = null;

    /**
     * @param string              $issuerUrl       Base URL of the OIDC provider (used to build discovery URL).
     * @param string              $clientId        Your application's OIDC client_id.
     * @param string              $clientSecret    Your application's OIDC client_secret.
     * @param string              $redirectUri     Callback URL registered with the IdP.
     * @param UserProviderInterface $userProvider  Application's user adapter.
     * @param TokenIssuerInterface  $tokenIssuer   GhostAuth token issuer.
     * @param CacheInterface        $cache         PSR-16 cache for discovery doc, state, nonce.
     * @param int                   $clockSkewSec  Allowed clock skew in seconds (default: 60).
     * @param bool                  $enabled       Whether this provider is active.
     * @param LoggerInterface       $logger        PSR-3 logger.
     */
    public function __construct(
        private readonly string $issuerUrl,
        private readonly string $clientId,
        private readonly string $clientSecret,
        private readonly string $redirectUri,
        private readonly UserProviderInterface $userProvider,
        private readonly TokenIssuerInterface $tokenIssuer,
        private readonly CacheInterface $cache,
        private readonly int $clockSkewSec = 60,
        private readonly bool $enabled = true,
        private readonly LoggerInterface $logger = new NullLogger(),
    ) {}

    // -------------------------------------------------------------------------
    // AuthenticationProviderInterface
    // -------------------------------------------------------------------------

    /**
     * Validate an OIDC ID Token and authenticate the user.
     *
     * @param  array<string, mixed> $credentials  Must contain 'id_token', 'state', 'nonce'.
     * @return AuthResultInterface
     * @throws GhostAuthException  On configuration/infrastructure error.
     */
    public function authenticate(array $credentials): AuthResultInterface
    {
        $this->guardEnabled();

        foreach (['id_token', 'state', 'nonce'] as $key) {
            if (empty($credentials[$key])) {
                throw new GhostAuthException(
                    "OidcProvider: missing required credential '{$key}'."
                );
            }
        }

        // Validate state (CSRF)
        $stateKey = self::CACHE_STATE_PREFIX . $credentials['state'];
        if (! $this->cache->has($stateKey)) {
            return AuthResult::failure('OIDC_STATE_MISMATCH', 'Invalid or expired state parameter.');
        }
        $this->cache->delete($stateKey);

        // Validate the ID Token
        try {
            $claims = $this->validateIdToken((string) $credentials['id_token']);
        } catch (OidcException $e) {
            return AuthResult::failure('OIDC_TOKEN_INVALID', $e->getMessage());
        }

        // Validate nonce (anti-replay)
        $nonceKey = self::CACHE_NONCE_PREFIX . $credentials['nonce'];
        if (! $this->cache->has($nonceKey)) {
            return AuthResult::failure('OIDC_NONCE_INVALID', 'Invalid or replayed nonce.');
        }
        $this->cache->delete($nonceKey);

        if (! isset($claims['nonce']) || ! hash_equals((string) $credentials['nonce'], (string) $claims['nonce'])) {
            return AuthResult::failure('OIDC_NONCE_MISMATCH', 'Nonce claim does not match.');
        }

        // Find or provision user
        $email = $claims['email'] ?? null;
        $user  = $email ? $this->userProvider->findByEmail($email) : null;

        if ($user === null) {
            $user = $this->userProvider->create([
                'email'    => $email,
                'name'     => $claims['name'] ?? null,
                'sub'      => $claims['sub'],
                'provider' => $this->getProviderName(),
            ]);
        }

        $token = $this->tokenIssuer->issue($user, [
            'oidc_sub' => $claims['sub'],
        ]);

        $this->logger->info('OidcProvider: SSO authentication successful', [
            'sub'     => $claims['sub'],
            'user_id' => $user->getAuthIdentifier(),
        ]);

        return AuthResult::success($user, $token, ['oidc_claims' => $claims]);
    }

    public function getProviderName(): string
    {
        return 'oidc';
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    // -------------------------------------------------------------------------
    // SsoProviderInterface
    // -------------------------------------------------------------------------

    /**
     * Fetch and cache the OIDC Discovery Document.
     *
     * @return array<string, mixed>
     * @throws OidcException
     */
    public function discoverConfiguration(): array
    {
        if ($this->discoveryDoc !== null) {
            return $this->discoveryDoc;
        }

        $cacheKey = self::CACHE_DISCOVERY_PREFIX . md5($this->issuerUrl);
        $cached   = $this->cache->get($cacheKey);

        if ($cached !== null) {
            $this->discoveryDoc = $cached;
            return $this->discoveryDoc;
        }

        $wellKnown = rtrim($this->issuerUrl, '/') . '/.well-known/openid-configuration';

        $ch = curl_init($wellKnown);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 10,
            CURLOPT_HTTPHEADER     => ['Accept: application/json'],
        ]);
        $body     = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($body === false || $httpCode !== 200) {
            throw new OidcException(
                "Failed to fetch OIDC discovery document from {$wellKnown} (HTTP {$httpCode})."
            );
        }

        $doc = json_decode((string) $body, true);

        if (! is_array($doc)) {
            throw new OidcException('OIDC discovery document is not valid JSON.');
        }

        $this->cache->set($cacheKey, $doc, self::DISCOVERY_TTL);
        $this->discoveryDoc = $doc;

        return $this->discoveryDoc;
    }

    /**
     * Build the OIDC authorization URL with fresh state and nonce values.
     *
     * @param  array<string, string> $additionalParams
     * @return string
     * @throws OidcException
     */
    public function getAuthorizationUrl(array $additionalParams = []): string
    {
        $doc   = $this->discoverConfiguration();
        $state = bin2hex(random_bytes(16));
        $nonce = bin2hex(random_bytes(16));

        // Persist state and nonce in cache for later validation
        $this->cache->set(self::CACHE_STATE_PREFIX . $state, true, self::STATE_TTL);
        $this->cache->set(self::CACHE_NONCE_PREFIX . $nonce, true, self::STATE_TTL);

        $params = array_merge($additionalParams, [
            'response_type' => 'code',
            'client_id'     => $this->clientId,
            'redirect_uri'  => $this->redirectUri,
            'scope'         => 'openid email profile',
            'state'         => $state,
            'nonce'         => $nonce,
        ]);

        return ($doc['authorization_endpoint'] ?? '') . '?' . http_build_query($params);
    }

    /**
     * Validate and decode an OIDC ID Token.
     *
     * @param  string $idToken
     * @return array<string, mixed>
     * @throws OidcException
     */
    public function validateIdToken(string $idToken): array
    {
        $doc = $this->discoverConfiguration();

        // Fetch JWKS — TODO: cache JWKS with JWK rotation support in v1.1
        $jwksUri = $doc['jwks_uri'] ?? null;
        if (! $jwksUri) {
            throw new OidcException('OIDC discovery document missing jwks_uri.');
        }

        $jwks = $this->fetchJwks((string) $jwksUri);

        // Build a Key collection for firebase/php-jwt
        $keySet = [];
        foreach ($jwks['keys'] ?? [] as $jwk) {
            if (! isset($jwk['kid'], $jwk['alg'])) {
                continue;
            }
            // For RSA keys — in production, convert JWK → PEM
            // firebase/php-jwt ≥ 6.3 accepts JWK arrays directly via JWK::parseKeySet()
            $keySet[$jwk['kid']] = new Key(
                $this->jwkToPem($jwk),
                $jwk['alg'],
            );
        }

        try {
            $decoded = JWT::decode($idToken, $keySet);
        } catch (\Throwable $e) {
            throw new OidcException('ID Token verification failed: ' . $e->getMessage(), 0, $e);
        }

        $claims = (array) $decoded;

        // Validate registered OIDC claims
        $expectedIssuer = rtrim($this->issuerUrl, '/');
        if (rtrim((string) ($claims['iss'] ?? ''), '/') !== $expectedIssuer) {
            throw new OidcException("ID Token issuer mismatch: expected {$expectedIssuer}.");
        }

        $aud = $claims['aud'] ?? [];
        $aud = is_array($aud) ? $aud : [$aud];
        if (! in_array($this->clientId, $aud, true)) {
            throw new OidcException('ID Token audience does not include our client_id.');
        }

        $now = time();
        if (isset($claims['exp']) && ($claims['exp'] + $this->clockSkewSec) < $now) {
            throw new OidcException('ID Token has expired.');
        }
        if (isset($claims['iat']) && $claims['iat'] > ($now + $this->clockSkewSec)) {
            throw new OidcException('ID Token issued in the future (clock skew too large?).');
        }

        return $claims;
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Fetch JWKS from the IdP's jwks_uri.
     *
     * @param  string $uri
     * @return array<string, mixed>
     * @throws OidcException
     */
    private function fetchJwks(string $uri): array
    {
        $ch = curl_init($uri);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 10,
        ]);
        $body     = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($body === false || $httpCode !== 200) {
            throw new OidcException("Failed to fetch JWKS from {$uri} (HTTP {$httpCode}).");
        }

        $data = json_decode((string) $body, true);

        if (! is_array($data)) {
            throw new OidcException('JWKS response is not valid JSON.');
        }

        return $data;
    }

    /**
     * Convert a JWK (RSA) to PEM format.
     *
     * NOTE: This is a stub. In production use `firebase/php-jwt`'s JWK::parseKeySet()
     * or a dedicated library (spomky-labs/jose, etc.) for robust JWK-to-PEM conversion
     * handling EC, RSA-PSS, and other key types.
     *
     * @param  array<string, mixed> $jwk
     * @return string  PEM-encoded public key.
     * @throws OidcException
     */
    private function jwkToPem(array $jwk): string
    {
        // TODO: Replace with firebase\JWT\JWK::parseKey($jwk) in v1.1
        // which handles RSA, EC, and oct keys natively.
        if (($jwk['kty'] ?? '') !== 'RSA') {
            throw new OidcException(
                'Only RSA keys are supported in MVP. EC support coming in v1.1.'
            );
        }

        // For MVP: delegate to firebase/php-jwt's JWK parser
        $keySet = \Firebase\JWT\JWK::parseKeySet(['keys' => [$jwk]]);
        $key    = reset($keySet);

        if ($key === false) {
            throw new OidcException('Failed to parse JWK into a usable key.');
        }

        return $key->getKeyMaterial();
    }

    private function guardEnabled(): void
    {
        if (! $this->enabled) {
            throw new GhostAuthException(
                'OidcProvider is disabled. Enable it in GhostAuth configuration.'
            );
        }
    }
}
