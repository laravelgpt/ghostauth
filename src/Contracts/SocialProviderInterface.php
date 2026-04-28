<?php

declare(strict_types=1);

namespace GhostAuth\Contracts;

/**
 * SocialProviderInterface
 *
 * Extends the base authentication contract for OAuth 2.0 / Social Login providers.
 * Concrete implementations (GoogleProvider, GitHubProvider, etc.) extend the
 * abstract AbstractSocialProvider class which implements the shared OAuth flow,
 * then override only the provider-specific endpoints and scopes.
 *
 * @package GhostAuth\Contracts
 */
interface SocialProviderInterface extends AuthenticationProviderInterface
{
    /**
     * Generate the OAuth 2.0 Authorization URL to redirect the user to.
     * Embeds a CSPRNG-generated `state` parameter for CSRF protection.
     *
     * @param  array<string, string> $scopes   Additional scopes beyond the defaults.
     * @param  array<string, string> $options  Extra query params (e.g. ['prompt' => 'consent']).
     * @return string  The full authorization URL.
     */
    public function getAuthorizationUrl(array $scopes = [], array $options = []): string;

    /**
     * Exchange the authorization `code` returned by the provider for an access token,
     * then fetch the user's profile from the provider's userinfo endpoint.
     *
     * @param  string $code   The authorization code from the callback query string.
     * @param  string $state  The `state` value from the callback, for CSRF validation.
     * @return SocialUserInterface  Normalized profile data from the provider.
     *
     * @throws \GhostAuth\Exceptions\OAuthException  On invalid code, state mismatch, or network error.
     */
    public function fetchUser(string $code, string $state): SocialUserInterface;
}
