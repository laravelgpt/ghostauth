<?php

declare(strict_types=1);

namespace GhostAuth\Mfa;

/**
 * MfaHandlerInterface
 *
 * Contract for MFA verification. Implementations handle TOTP, backup codes,
 * WebAuthn/passkeys, or any second-factor mechanism.
 *
 * @package GhostAuth\Mfa
 */
interface MfaHandlerInterface
{
    /**
     * Verify the MFA challenge and return the final result.
     *
     * @param  string               $mfaToken    Short-lived token proving primary auth succeeded.
     * @param  array<string, mixed> $credentials MFA credentials (e.g. ['totp_code' => '123456']).
     * @return array{success: bool, token: string|null, error: string|null, user_id: mixed}
     */
    public function verify(string $mfaToken, array $credentials): array;

    /**
     * Enroll a user in MFA — generate secret, return provisioning data.
     *
     * @param  mixed  $userId       The user identifier.
     * @param  string $email        The user's email (for the QR code label).
     * @param  string $issuer       Application name (for the QR code).
     * @return array{secret: string, backup_codes: string[], provisioning_uri: string}
     */
    public function enroll(mixed $userId, string $email, string $issuer): array;

    /**
     * Verify a backup code and consume it (remove from storage).
     *
     * @param  mixed  $userId   The user identifier.
     * @param  string $code     Plaintext backup code.
     * @return bool             True if valid and consumed.
     */
    public function consumeBackupCode(mixed $userId, string $code): bool;

    /** Whether this handler is configured and active. */
    public function isAvailable(): bool;
}
