<?php

declare(strict_types=1);

namespace GhostAuth\Models;

use GhostAuth\Contracts\SocialUserInterface;

/**
 * SocialUser
 *
 * Immutable value object that normalizes the profile data returned by any
 * OAuth 2.0 / Social provider into a consistent shape (SocialUserInterface).
 *
 * @package GhostAuth\Models
 */
final readonly class SocialUser implements SocialUserInterface
{
    public function __construct(
        private string $providerId,
        private string $providerName,
        private ?string $name,
        private ?string $email,
        private ?string $avatar,
        private string $accessToken,
        private ?string $refreshToken,
        private array $raw,
    ) {}

    public function getProviderId(): string    { return $this->providerId; }
    public function getProviderName(): string  { return $this->providerName; }
    public function getName(): ?string         { return $this->name; }
    public function getEmail(): ?string        { return $this->email; }
    public function getAvatar(): ?string       { return $this->avatar; }
    public function getAccessToken(): string   { return $this->accessToken; }
    public function getRefreshToken(): ?string { return $this->refreshToken; }
    public function getRaw(): array            { return $this->raw; }
}
