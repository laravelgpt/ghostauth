<?php

declare(strict_types=1);

namespace GhostAuth\Contracts;

/**
 * AuthenticationProviderInterface
 *
 * Every authentication strategy (Email+Password, OTP, OAuth, OIDC, etc.)
 * MUST implement this contract. This is the heart of the Strategy Pattern:
 * GhostAuthManager speaks only to this interface, so swapping strategies
 * requires zero changes to the manager or the consuming application.
 *
 * Flow:
 *   1. authenticate(array $credentials) → AuthResultInterface
 *   2. Consumer inspects isSuccess(), getUser(), getToken(), getError()
 *
 * @package GhostAuth\Contracts
 */
interface AuthenticationProviderInterface
{
    /**
     * Attempt to authenticate using the provided credentials.
     *
     * Each strategy defines what keys $credentials must carry:
     *   - EmailPassword: ['email' => ..., 'password' => ...]
     *   - OTP:           ['email' => ..., 'otp' => ...]  OR  ['phone' => ..., 'otp' => ...]
     *   - OAuth:         ['code' => ..., 'state' => ...]
     *   - OIDC:          ['id_token' => ...]
     *
     * @param  array<string, mixed> $credentials  Strategy-specific credential map.
     * @return AuthResultInterface                Structured result — never throws on auth failure.
     *
     * @throws \GhostAuth\Exceptions\GhostAuthException  Only on infrastructure/config errors.
     */
    public function authenticate(array $credentials): AuthResultInterface;

    /**
     * Human-readable identifier for this provider.
     * Used by GhostAuthManager for logging, error messages, and provider resolution.
     *
     * Examples: 'email_password', 'email_otp', 'phone_otp', 'google_oauth', 'oidc'
     *
     * @return string
     */
    public function getProviderName(): string;

    /**
     * Whether this provider is currently enabled and correctly configured.
     * GhostAuthManager MUST call this before attempting authentication
     * to surface misconfiguration early.
     *
     * @return bool
     */
    public function isEnabled(): bool;
}
