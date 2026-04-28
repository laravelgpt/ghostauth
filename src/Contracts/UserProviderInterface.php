<?php

declare(strict_types=1);

namespace GhostAuth\Contracts;

/**
 * UserProviderInterface
 *
 * Bridges GhostAuth with the consuming application's user persistence layer.
 * GhostAuth intentionally has NO opinion about databases or ORMs.
 * The application implements this interface against its own User model/repository,
 * then passes the implementation to each Provider at construction time.
 *
 * Design principle: GhostAuth owns the authentication logic; the app owns the data.
 *
 * @package GhostAuth\Contracts
 */
interface UserProviderInterface
{
    /**
     * Retrieve a user record by their email address.
     * Returns null when no matching user exists (do NOT throw).
     *
     * @param  string $email  Normalized, lowercased email address.
     * @return AuthenticatableInterface|null
     */
    public function findByEmail(string $email): ?AuthenticatableInterface;

    /**
     * Retrieve a user record by their phone number.
     * Phone numbers SHOULD be stored in E.164 format (+8801XXXXXXXXX).
     * Returns null when no matching user exists.
     *
     * @param  string $phone  E.164-formatted phone number.
     * @return AuthenticatableInterface|null
     */
    public function findByPhone(string $phone): ?AuthenticatableInterface;

    /**
     * Retrieve a user record by their unique identifier.
     * The type of $id depends on the application's data layer (int, string, UUID).
     *
     * @param  int|string $id  Application-specific unique identifier.
     * @return AuthenticatableInterface|null
     */
    public function findById(int|string $id): ?AuthenticatableInterface;

    /**
     * Persist a new user to the application's data store.
     * Called during first-time social/OTP login flows ("just-in-time provisioning").
     *
     * @param  array<string, mixed> $attributes  Normalized user attributes.
     * @return AuthenticatableInterface           The newly created user record.
     *
     * @throws \GhostAuth\Exceptions\GhostAuthException  On persistence failure.
     */
    public function create(array $attributes): AuthenticatableInterface;

    /**
     * Update specific attributes on an existing user.
     * Used to record last_login_at, update OTP hash, refresh OAuth tokens, etc.
     *
     * @param  int|string           $id          The user's unique identifier.
     * @param  array<string, mixed> $attributes  Key-value pairs to update.
     * @return bool                              True on success, false on failure.
     */
    public function update(int|string $id, array $attributes): bool;
}
