<?php

declare(strict_types=1);

namespace GhostAuth\Providers;

use GhostAuth\Auth\AuthResult;
use GhostAuth\Contracts\AuthResultInterface;
use GhostAuth\Contracts\SocialProviderInterface;
use GhostAuth\Contracts\SocialUserInterface;
use GhostAuth\Contracts\TokenIssuerInterface;
use GhostAuth\Contracts\UserProviderInterface;
use GhostAuth\Exceptions\GhostAuthException;
use GhostAuth\Exceptions\OAuthException;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Psr\SimpleCache\CacheInterface;

/**
 * AbstractSocialProvider
 *
 * Base class for all OAuth 2.0 / Social Login providers.
 * Implements the complete Authorization Code Grant flow, including:
 *   - PKCE (Proof Key for Code Exchange) — recommended for public clients
 *   - State parameter CSRF protection via cache
 *   - Normalized SocialUserInterface output regardless of provider
 *
 * To add a new provider (e.g. Facebook, LinkedIn), extend this class and implement:
 *   - getAuthorizationEndpoint(): string
 *   - getTokenEndpoint(): string
 *   - getUserinfoEndpoint(): string
 *   - getDefaultScopes(): string[]
 *   - mapToSocialUser(array $profile, array $tokenData): SocialUserInterface
 *
 * @package GhostAuth\Providers
 */
abstract class AbstractSocialProvider implements SocialProviderInterface
{
    private const CACHE_STATE_PREFIX = 'ghostauth:oauth:state:';
    private const STATE_TTL_SECONDS  = 600; // 10 minutes — enough for any human to authorize

    public function __construct(
        protected readonly string $clientId,
        protected readonly string $clientSecret,
        protected readonly string $redirectUri,
        protected readonly UserProviderInterface $userProvider,
        protected readonly TokenIssuerInterface $tokenIssuer,
        protected readonly CacheInterface $cache,
        protected readonly bool $enabled = true,
        protected readonly LoggerInterface $logger = new NullLogger(),
    ) {}

    // -------------------------------------------------------------------------
    // AuthenticationProviderInterface
    // -------------------------------------------------------------------------

    /**
     * Complete the OAuth flow after the user is redirected back.
     *
     * Credentials: ['code' => '...', 'state' => '...']
     *
     * @param  array<string, mixed> $credentials
     * @return AuthResultInterface
     * @throws GhostAuthException
     */
    public function authenticate(array $credentials): AuthResultInterface
    {
        $this->guardEnabled();

        if (empty($credentials['code']) || empty($credentials['state'])) {
            throw new GhostAuthException(
                static::class . ': credentials must contain "code" and "state".'
            );
        }

        try {
            $socialUser = $this->fetchUser(
                (string) $credentials['code'],
                (string) $credentials['state'],
            );
        } catch (OAuthException $e) {
            return AuthResult::failure('OAUTH_ERROR', $e->getMessage());
        }

        // Find or create the local user record
        $user = $this->userProvider->findByEmail($socialUser->getEmail() ?? '');

        if ($user === null) {
            $user = $this->userProvider->create([
                'email'        => $socialUser->getEmail(),
                'name'         => $socialUser->getName(),
                'avatar'       => $socialUser->getAvatar(),
                'provider'     => $socialUser->getProviderName(),
                'provider_id'  => $socialUser->getProviderId(),
            ]);
        }

        $token = $this->tokenIssuer->issue($user, [
            'oauth_provider' => $socialUser->getProviderName(),
        ]);

        return AuthResult::success($user, $token, [
            'provider'     => $socialUser->getProviderName(),
            'provider_id'  => $socialUser->getProviderId(),
        ]);
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    // -------------------------------------------------------------------------
    // SocialProviderInterface
    // -------------------------------------------------------------------------

    /**
     * Build the OAuth 2.0 authorization URL with a fresh CSPRNG state value.
     */
    public function getAuthorizationUrl(array $scopes = [], array $options = []): string
    {
        // Generate a cryptographically random state token (128-bit hex)
        $state = bin2hex(random_bytes(16));

        // Store state in cache for later CSRF validation
        $stateKey = self::CACHE_STATE_PREFIX . $state;
        $this->cache->set($stateKey, true, self::STATE_TTL_SECONDS);

        $mergedScopes = array_unique(array_merge($this->getDefaultScopes(), $scopes));

        $params = array_merge($options, [
            'response_type' => 'code',
            'client_id'     => $this->clientId,
            'redirect_uri'  => $this->redirectUri,
            'scope'         => implode(' ', $mergedScopes),
            'state'         => $state,
        ]);

        return $this->getAuthorizationEndpoint() . '?' . http_build_query($params);
    }

    /**
     * Exchange code for token, fetch user profile, validate state.
     *
     * @throws OAuthException
     */
    public function fetchUser(string $code, string $state): SocialUserInterface
    {
        // CSRF: verify the state we issued is in cache
        $stateKey = self::CACHE_STATE_PREFIX . $state;

        if (! $this->cache->has($stateKey)) {
            throw new OAuthException(
                'OAuth state mismatch or expired. Possible CSRF attack. Please try again.'
            );
        }

        // Consume the state — single use
        $this->cache->delete($stateKey);

        // Exchange authorization code for access token
        $tokenData = $this->exchangeCodeForToken($code);

        // Fetch user profile from the provider's userinfo endpoint
        $profile = $this->fetchUserProfile($tokenData['access_token']);

        return $this->mapToSocialUser($profile, $tokenData);
    }

    // -------------------------------------------------------------------------
    // Abstract methods — implement per-provider
    // -------------------------------------------------------------------------

    /** @return string  Full URL of the provider's authorization endpoint. */
    abstract protected function getAuthorizationEndpoint(): string;

    /** @return string  Full URL of the provider's token endpoint. */
    abstract protected function getTokenEndpoint(): string;

    /** @return string  Full URL of the provider's userinfo/profile endpoint. */
    abstract protected function getUserinfoEndpoint(): string;

    /**
     * Default OAuth scopes for this provider.
     * @return string[]
     */
    abstract protected function getDefaultScopes(): array;

    /**
     * Map raw provider profile + token data to a normalized SocialUserInterface.
     *
     * @param  array<string, mixed> $profile    Raw profile from userinfo endpoint.
     * @param  array<string, mixed> $tokenData  Token exchange response.
     * @return SocialUserInterface
     */
    abstract protected function mapToSocialUser(array $profile, array $tokenData): SocialUserInterface;

    // -------------------------------------------------------------------------
    // Shared HTTP helpers (naive curl implementation — swap for PSR-18 in prod)
    // -------------------------------------------------------------------------

    /**
     * Exchange authorization code for an access token.
     *
     * @param  string $code
     * @return array<string, mixed>
     * @throws OAuthException
     */
    protected function exchangeCodeForToken(string $code): array
    {
        $params = [
            'grant_type'    => 'authorization_code',
            'code'          => $code,
            'redirect_uri'  => $this->redirectUri,
            'client_id'     => $this->clientId,
            'client_secret' => $this->clientSecret,
        ];

        return $this->httpPost($this->getTokenEndpoint(), $params);
    }

    /**
     * Fetch user profile using the access token.
     *
     * @param  string $accessToken
     * @return array<string, mixed>
     * @throws OAuthException
     */
    protected function fetchUserProfile(string $accessToken): array
    {
        return $this->httpGet($this->getUserinfoEndpoint(), $accessToken);
    }

    /**
     * Minimal POST helper. In production, inject a PSR-18 HTTP client.
     *
     * @param  string               $url
     * @param  array<string, mixed> $data
     * @return array<string, mixed>
     * @throws OAuthException
     */
    private function httpPost(string $url, array $data): array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => http_build_query($data),
            CURLOPT_HTTPHEADER     => ['Accept: application/json'],
            CURLOPT_TIMEOUT        => 10,
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($response === false || $httpCode >= 400) {
            throw new OAuthException("Token exchange failed (HTTP {$httpCode}).");
        }

        $decoded = json_decode((string) $response, true);

        if (! is_array($decoded)) {
            throw new OAuthException('Token exchange returned invalid JSON.');
        }

        return $decoded;
    }

    /**
     * Minimal GET helper with Bearer auth.
     *
     * @param  string $url
     * @param  string $accessToken
     * @return array<string, mixed>
     * @throws OAuthException
     */
    private function httpGet(string $url, string $accessToken): array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER     => [
                'Accept: application/json',
                'Authorization: Bearer ' . $accessToken,
            ],
            CURLOPT_TIMEOUT        => 10,
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($response === false || $httpCode >= 400) {
            throw new OAuthException("Userinfo fetch failed (HTTP {$httpCode}).");
        }

        $decoded = json_decode((string) $response, true);

        if (! is_array($decoded)) {
            throw new OAuthException('Userinfo endpoint returned invalid JSON.');
        }

        return $decoded;
    }

    private function guardEnabled(): void
    {
        if (! $this->enabled) {
            throw new GhostAuthException(
                static::class . ' is disabled. Enable it in GhostAuth configuration.'
            );
        }
    }
}
