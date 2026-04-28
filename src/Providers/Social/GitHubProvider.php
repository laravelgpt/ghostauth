<?php

declare(strict_types=1);

namespace GhostAuth\Providers\Social;

use GhostAuth\Contracts\SocialUserInterface;
use GhostAuth\Models\SocialUser;
use GhostAuth\Providers\AbstractSocialProvider;

/**
 * GitHubProvider
 *
 * OAuth 2.0 provider for GitHub Login.
 * GitHub does not expose email in the userinfo response when it's private;
 * a real implementation should also call /user/emails to retrieve the verified
 * primary email. The skeleton is simplified for MVP clarity.
 *
 * @package GhostAuth\Providers\Social
 */
final class GitHubProvider extends AbstractSocialProvider
{
    public function getProviderName(): string
    {
        return 'github';
    }

    protected function getAuthorizationEndpoint(): string
    {
        return 'https://github.com/login/oauth/authorize';
    }

    protected function getTokenEndpoint(): string
    {
        return 'https://github.com/login/oauth/access_token';
    }

    protected function getUserinfoEndpoint(): string
    {
        return 'https://api.github.com/user';
    }

    protected function getDefaultScopes(): array
    {
        return ['read:user', 'user:email'];
    }

    /**
     * Map GitHub's /user response to SocialUserInterface.
     *
     * GitHub user keys: id, login, name, email, avatar_url
     *
     * @param  array<string, mixed> $profile
     * @param  array<string, mixed> $tokenData
     * @return SocialUserInterface
     */
    protected function mapToSocialUser(array $profile, array $tokenData): SocialUserInterface
    {
        return new SocialUser(
            providerId:    (string) ($profile['id'] ?? ''),
            providerName:  $this->getProviderName(),
            name:          $profile['name'] ?? $profile['login'] ?? null,
            email:         $profile['email'] ?? null,
            avatar:        $profile['avatar_url'] ?? null,
            accessToken:   $tokenData['access_token'] ?? '',
            refreshToken:  null, // GitHub does not issue refresh tokens
            raw:           $profile,
        );
    }
}
