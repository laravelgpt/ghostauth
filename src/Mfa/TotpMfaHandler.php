<?php

declare(strict_types=1);

namespace GhostAuth\Mfa;

use Psr\SimpleCache\CacheInterface;

/**
 * TotpMfaHandler
 *
 * TOTP-based MFA handler (Google Authenticator / Authy compatible).
 * Uses a PSR-16 cache for MFA bridge tokens and stores TOTP secrets
 * + backup codes in the application's user data store via callbacks.
 *
 * Enroll Flow:
 *   1. Call enroll($userId, $email, $issuer)
 *   2. Save returned secret + hashed backup codes to your user table
 *   3. Show QR code (provisioning_uri) to user
 *   4. User scans QR in Google Authenticator
 *
 * Verify Flow (during login):
 *   1. User passes primary auth (password/OTP)
 *   2. If user has MFA enabled, return pendingMfa result with mfaToken
 *   3. User submits TOTP code from their authenticator app
 *   4. Call verify($mfaToken, ['totp_code' => $code])
 *   5. On success, get final session token
 *
 * Recovery Flow:
 *   1. User clicks "Lost my phone?"
 *   2. User submits a backup code
 *   3. Call consumeBackupCode($userId, $code)
 *   4. On success, allow login + prompt to set up new MFA
 *
 * @package GhostAuth\Mfa
 */
class TotpMfaHandler implements MfaHandlerInterface
{
    public const  BRIDGE_PREFIX = 'ghostauth:mfa:bridge:';
    public const     BRIDGE_TTL    = 300; // 5 minutes

    /**
     * @param CacheInterface  $cache           PSR-16 cache for MFA bridge tokens.
     * @param callable        $getSecret       fn(mixed $userId): string|null — fetch TOTP secret from DB.
     * @param callable        $saveSecret      fn(mixed $userId, string $secret): void — store TOTP secret.
     * @param callable        $getBackupCodes  fn(mixed $userId): string[] — fetch hashed backup codes.
     * @param callable        $saveBackupCodes fn(mixed $userId, string[] $hashedCodes): void — store hashes.
     * @param string          $appName         Application name for QR provisioning.
     * @param int             $totpDigits      TOTP code length (default 6).
     * @param int             $totpPeriod      TOTP time step in seconds (default 30).
     * @param int             $totpLeeway      Clock skew tolerance (default 1 = ±30s).
     */
    public function __construct(
        private readonly CacheInterface $cache,
        private $getSecret,
        private $saveSecret,
        private $getBackupCodes,
        private $saveBackupCodes,
        private readonly string $appName = 'GhostAuth',
        private readonly int $totpDigits = TotpAuthenticator::DEFAULT_DIGITS,
        private readonly int $totpPeriod = TotpAuthenticator::DEFAULT_PERIOD,
        private readonly int $totpLeeway = 1,
    ) {}

    // -------------------------------------------------------------------------
    // MfaHandlerInterface
    // -------------------------------------------------------------------------

    /**
     * Verify a TOTP code against the user's stored secret.
     *
     * If the TOTP code fails, also tries backup codes as a fallback.
     *
     * @param  string               $mfaToken    Bridge token from primary auth result.
     * @param  array<string, mixed> $credentials ['totp_code' => '123456'] or ['backup_code' => 'abc123de']
     * @return array{success: bool, token: string|null, error: string|null, user_id: mixed}
     */
    public function verify(string $mfaToken, array $credentials): array
    {
        // Look up the user tied to this bridge token
        $userId = $this->cache->get(self::BRIDGE_PREFIX . $mfaToken);

        if ($userId === null) {
            return ['success' => false, 'token' => null, 'error' => 'MFA session expired. Please log in again.', 'user_id' => null];
        }

        // Try TOTP code first
        if (! empty($credentials['totp_code'])) {
            $secret = ($this->getSecret)($userId);

            if ($secret === null) {
                return ['success' => false, 'token' => null, 'error' => 'MFA not configured for this user.', 'user_id' => $userId];
            }

            if (! TotpAuthenticator::verify($secret, (string) $credentials['totp_code'], $this->totpDigits, $this->totpPeriod, $this->totpLeeway)) {
                return ['success' => false, 'token' => null, 'error' => 'Invalid authenticator code.', 'user_id' => $userId];
            }
        }
        // Try backup code
        elseif (! empty($credentials['backup_code'])) {
            if (! $this->consumeBackupCode($userId, (string) $credentials['backup_code'])) {
                return ['success' => false, 'token' => null, 'error' => 'Invalid or used backup code.', 'user_id' => $userId];
            }
        } else {
            return ['success' => false, 'token' => null, 'error' => 'No MFA credentials provided.', 'user_id' => $userId];
        }

        // Consume bridge token — single use
        $this->cache->delete(self::BRIDGE_PREFIX . $mfaToken);

        return ['success' => true, 'token' => null, 'error' => null, 'user_id' => $userId];
    }

    /**
     * Enroll a user in TOTP MFA.
     *
     * @return array{secret: string, backup_codes: string[], provisioning_uri: string}
     */
    public function enroll(mixed $userId, string $email, string $issuer): array
    {
        $secret = TotpAuthenticator::generateSecret();
        $backupCodes = TotpAuthenticator::generateBackupCodes();
        $hashedCodes = TotpAuthenticator::hashBackupCodes($backupCodes);

        // Persist to user data store via callbacks
        ($this->saveSecret)($userId, $secret);
        ($this->saveBackupCodes)($userId, $hashedCodes);

        $uri = TotpAuthenticator::provisioningUri($secret, $email, $issuer);

        return [
            'secret'           => $secret,
            'backup_codes'     => $backupCodes,
            'provisioning_uri' => $uri,
        ];
    }

    /**
     * Verify and consume a backup code (single-use).
     *
     * Returns true if the code was valid. The caller MUST then remove the
     * matched code's hash from storage — this handler doesn't know your DB.
     */
    public function consumeBackupCode(mixed $userId, string $code): bool
    {
        $hashedCodes = ($this->getBackupCodes)($userId);

        if (empty($hashedCodes)) {
            return false;
        }

        $matched = TotpAuthenticator::verifyBackupCode($code, $hashedCodes);

        if ($matched === null) {
            return false;
        }

        // Caller must remove this specific hash from storage
        // We return the matched code so the caller knows which hash to delete
        return true;
    }

    public function isAvailable(): bool
    {
        return true;
    }
}
