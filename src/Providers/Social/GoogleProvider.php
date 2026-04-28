<?php

declare(strict_types=1);

namespace GhostAuth\Providers\Social;

use GhostAuth\Contracts\SocialUserInterface;
use GhostAuth\Models\SocialUser;
use GhostAuth\Providers\AbstractSocialProvider;

/**
 * GoogleProvider
 *
 * OAuth 2.0 / OpenID Connect provider for Google Sign-In.
 * Extend AbstractSocialProvider — only provider-specific URLs,
 * scopes, and profile mapping are defined here.
 *
 * @package GhostAuth\Providers\Social
 */
final class GoogleProvider extends AbstractSocialProvider
{
    public function getProviderName(): string
    {
        return 'google';
    }

    protected function getAuthorizationEndpoint(): string
    {
        return 'https://accounts.google.com/o/oauth2/v2/auth';
    }

    protected function getTokenEndpoint(): string
    {
        return 'https://oauth2.googleapis.com/token';
    }

    protected function getUserinfoEndpoint(): string
    {
        return 'https://www.googleapis.com/oauth2/v3/userinfo';
    }

    protected function getDefaultScopes(): array
    {
        return ['openid', 'email', 'profile'];
    }

    /**
     * Map Google's userinfo response to SocialUserInterface.
     *
     * Google userinfo keys: sub, email, name, picture, email_verified
     *
     * @param  array<string, mixed> $profile
     * @param  array<string, mixed> $tokenData
     * @return SocialUserInterface
     */
    protected function mapToSocialUser(array $profile, array $tokenData): SocialUserInterface
    {
        return new SocialUser(
            providerId:    (string) ($profile['sub'] ?? ''),
            providerName:  $this->getProviderName(),
            name:          $profile['name'] ?? null,
            email:         $profile['email'] ?? null,
            avatar:        $profile['picture'] ?? null,
            accessToken:   $tokenData['access_token'] ?? '',
            refreshToken:  $tokenData['refresh_token'] ?? null,
            raw:           $profile,
        );
    }
}
