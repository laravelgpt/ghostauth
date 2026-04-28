<?php

declare(strict_types=1);

namespace GhostAuth\Contracts;

/**
 * AuthenticatableInterface
 *
 * Represents a user entity that can be authenticated by GhostAuth.
 * The consuming application's User model (Eloquent, Doctrine, plain POPO, etc.)
 * must implement this interface — it is the only shape GhostAuth
 * will ever interact with for user data.
 *
 * @package GhostAuth\Contracts
 */
interface AuthenticatableInterface
{
    /**
     * Return the unique identifier for the user.
     * This value is embedded into JWT payloads as the `sub` claim.
     *
     * @return int|string
     */
    public function getAuthIdentifier(): int|string;

    /**
     * Return the column/attribute name used as the unique identifier.
     * Typically 'id', 'uuid', or 'user_id'.
     *
     * @return string
     */
    public function getAuthIdentifierName(): string;

    /**
     * Return the user's hashed password (Argon2id hash).
     * For passwordless users (OTP-only, Social-only), return null.
     *
     * @return string|null
     */
    public function getAuthPassword(): ?string;

    /**
     * Return the user's email address.
     * Used by email-based strategies and for JWT `email` claim.
     *
     * @return string|null
     */
    public function getEmail(): ?string;

    /**
     * Return the user's E.164-formatted phone number.
     * Used by phone OTP strategy.
     *
     * @return string|null
     */
    public function getPhone(): ?string;

    /**
     * Return arbitrary claims to include in the JWT payload beyond the defaults.
     * For example: ['role' => 'admin', 'plan' => 'enterprise']
     * Return an empty array if no additional claims are needed.
     *
     * @return array<string, mixed>
     */
    public function getJwtClaims(): array;
}
