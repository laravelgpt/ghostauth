<?php

declare(strict_types=1);

namespace GhostAuth\Contracts;

/**
 * AuthResultInterface
 *
 * Encapsulates the outcome of an authentication attempt.
 * Returning a result object (rather than throwing on failure) allows
 * the consuming application to handle auth failures gracefully
 * without wrapping every call in try/catch.
 *
 * @package GhostAuth\Contracts
 */
interface AuthResultInterface
{
    /**
     * Whether the authentication attempt was successful.
     *
     * @return bool
     */
    public function isSuccess(): bool;

    /**
     * The authenticated user on success; null on failure.
     *
     * @return AuthenticatableInterface|null
     */
    public function getUser(): ?AuthenticatableInterface;

    /**
     * The issued token (JWT string or session token) on success; null on failure.
     *
     * @return string|null
     */
    public function getToken(): ?string;

    /**
     * A machine-readable error code on failure (e.g. 'INVALID_CREDENTIALS',
     * 'OTP_EXPIRED', 'ACCOUNT_LOCKED'); null on success.
     *
     * @return string|null
     */
    public function getErrorCode(): ?string;

    /**
     * A human-readable error message on failure; null on success.
     *
     * @return string|null
     */
    public function getErrorMessage(): ?string;

    /**
     * Any extra metadata (e.g. OTP expiry time, redirect URL for OAuth).
     * Returns an empty array when not applicable.
     *
     * @return array<string, mixed>
     */
    public function getMeta(): array;
}
