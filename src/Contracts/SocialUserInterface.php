<?php

declare(strict_types=1);

namespace GhostAuth\Contracts;

/**
 * SocialUserInterface
 *
 * Normalized user profile data returned by any Social/OAuth provider.
 * Regardless of whether the user came from Google, GitHub, or Facebook,
 * the consuming application always gets the same shape.
 *
 * @package GhostAuth\Contracts
 */
interface SocialUserInterface
{
    /** @return string  The provider-scoped unique user ID (e.g. Google's `sub`). */
    public function getProviderId(): string;

    /** @return string  The OAuth provider name ('google', 'github', etc.). */
    public function getProviderName(): string;

    /** @return string|null  The user's display name (may be null for some providers). */
    public function getName(): ?string;

    /** @return string|null  The user's primary email address. */
    public function getEmail(): ?string;

    /** @return string|null  The user's avatar/profile picture URL. */
    public function getAvatar(): ?string;

    /** @return string  The OAuth access token (for calling provider APIs). */
    public function getAccessToken(): string;

    /** @return string|null  The OAuth refresh token, when provided. */
    public function getRefreshToken(): ?string;

    /** @return array<string, mixed>  The raw profile payload from the provider. */
    public function getRaw(): array;
}
