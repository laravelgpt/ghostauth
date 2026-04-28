<?php

declare(strict_types=1);

namespace GhostAuth\Mfa;

/**
 * TotpAuthenticator
 *
 * RFC 6238 TOTP implementation (Time-based One-Time Password).
 * Compatible with Google Authenticator, Authy, 1Password, Bitwarden.
 *
 * Algorithm:
 *   1. Base32-decode the shared secret
 *   2. Compute HMAC-SHA1(secret, counter) where counter = floor(time / period)
 *   3. Dynamic truncation: extract 4 bytes at offset = last_nibble of HMAC
 *   4. Mask to $digits decimal digits
 *   5. Zero-padded
 *
 * @package GhostAuth\Mfa
 */
class TotpAuthenticator
{
    public const  DEFAULT_DIGITS = 6;
    public const  DEFAULT_PERIOD = 30;
    public const  DEFAULT_ALGO = 'sha1';

    public const  ALGO_SHA1   = 'sha1';
    public const  ALGO_SHA256 = 'sha256';
    public const  ALGO_SHA512 = 'sha512';

    /**
     * Generate a cryptographically random TOTP secret.
     *
     * @param  int    $bytes  Raw entropy bytes (20 bytes = 160 bits → 32 base32 chars).
     * @return string         Base32-encoded secret (uppercase, no padding).
     */
    public static function generateSecret(int $bytes = 20): string
    {
        return self::base32Encode(random_bytes($bytes));
    }

    /**
     * Generate the current TOTP code for a given secret.
     *
     * @param  string $base32Secret  Base32-encoded shared secret.
     * @param  int    $digits        Number of digits in the code (default 6).
     * @param  int    $period        Time step in seconds (default 30).
     * @param  int    $timestamp     Override time (for testing).
     * @param  string $algo          Hash algorithm: sha1, sha256, sha512.
     * @return string                Zero-padded TOTP code.
     */
    public static function generate(
        string $base32Secret,
        int $digits = self::DEFAULT_DIGITS,
        int $period = self::DEFAULT_PERIOD,
        ?int $timestamp = null,
        string $algo = self::DEFAULT_ALGO,
    ): string {
        $counter = self::timeCounter($timestamp ?? time(), $period);
        return self::hotp($base32Secret, $counter, $digits, $algo);
    }

    /**
     * Verify a TOTP code against the shared secret.
     *
     * Uses a configurable leeway window to account for clock skew.
     * With leeway = 1, checks: [current-1, current, current+1] (3 time steps).
     *
     * @param  string $base32Secret  Base32-encoded shared secret.
     * @param  string $code          User-submitted TOTP code.
     * @param  int    $digits        Number of digits.
     * @param  int    $period        Time step in seconds.
     * @param  int    $leeway        Clock skew tolerance in time steps.
     * @param  int    $timestamp     Override time (for testing).
     * @param  string $algo          Hash algorithm.
     * @return bool                  True if the code matches any window.
     */
    public static function verify(
        string $base32Secret,
        string $code,
        int $digits = self::DEFAULT_DIGITS,
        int $period = self::DEFAULT_PERIOD,
        int $leeway = 1,
        ?int $timestamp = null,
        string $algo = self::DEFAULT_ALGO,
    ): bool {
        $now = $timestamp ?? time();

        // Check the current time step ± leeway
        for ($i = -$leeway; $i <= $leeway; $i++) {
            $expected = self::generate($base32Secret, $digits, $period, $now + $i * $period, $algo);
            if (hash_equals($expected, str_pad((string) $code, $digits, '0', STR_PAD_LEFT))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Generate a QR code provisioning URI for Google Authenticator.
     *
     * URI format: otpauth://totp/Issuer:Account?secret=...&issuer=...&algorithm=...&digits=...&period=...
     *
     * @param  string $base32Secret  The shared secret.
     * @param  string $accountName   User's email or username (URL-unsafe chars will be escaped).
     * @param  string $issuer        Your application name.
     * @param  int    $digits        Number of digits.
     * @param  int    $period        Time step in seconds.
     * @param  string $algo          Hash algorithm.
     * @return string                Full otpauth:// URI.
     */
    public static function provisioningUri(
        string $base32Secret,
        string $accountName,
        string $issuer,
        int $digits = self::DEFAULT_DIGITS,
        int $period = self::DEFAULT_PERIOD,
        string $algo = self::DEFAULT_ALGO,
    ): string {
        $label = rawurlencode($issuer . ':' . $accountName);

        return sprintf(
            'otpauth://totp/%s?secret=%s&issuer=%s&algorithm=%s&digits=%d&period=%d',
            $label,
            $base32Secret,
            rawurlencode($issuer),
            strtoupper($algo),
            $digits,
            $period,
        );
    }

    /**
     * Generate 8 single-use backup codes for MFA recovery.
     * Each code is 8 hex characters (32 bits of entropy per code).
     *
     * @return string[]  Array of 8 backup codes. Store hashed in DB.
     */
    public static function generateBackupCodes(int $count = 8): array
    {
        return array_map(
            fn() => bin2hex(random_bytes(4)),  // 8 hex chars
            range(1, $count),
        );
    }

    /**
     * Hash backup codes for storage using Argon2id.
     *
     * @param  string[] $codes  Plaintext backup codes.
     * @return string[]         Argon2id hashes.
     */
    public static function hashBackupCodes(array $codes): array
    {
        return array_map(
            fn($code) => password_hash($code, PASSWORD_ARGON2ID, [
                'memory_cost' => 16384,
                'time_cost'   => 2,
                'threads'     => 1,
            ]),
            $codes,
        );
    }

    /**
     * Verify a backup code against stored hashes.
     * Returns the matched code on success, null on failure.
     *
     * IMPORTANT: Remove the matched code from storage after use (single-use).
     *
     * @param  string   $code          User-submitted backup code.
     * @param  string[] $hashedCodes   Stored Argon2id hashes.
     * @return string|null             Matched plaintext code, or null.
     */
    public static function verifyBackupCode(string $code, array $hashedCodes): ?string
    {
        foreach ($hashedCodes as $hashed) {
            if (password_verify($code, $hashed)) {
                return $code;
            }
        }

        return null;
    }

    // =========================================================================
    // Private helpers
    // =========================================================================

    /**
     * Compute the HOTP value for a given counter.
     * This is the core RFC 4226 algorithm that TOTP builds on.
     */
    private static function hotp(
        string $base32Secret,
        int $counter,
        int $digits,
        string $algo,
    ): string {
        // Decode base32 secret to raw bytes
        $secret = self::base32Decode($base32Secret);

        // 8-byte big-endian counter
        $counterBytes = pack('J', $counter);

        // HMAC
        $hmac = hash_hmac($algo, $counterBytes, $secret, binary: true);

        // Dynamic truncation (RFC 4226 §5.4)
        $offset = ord($hmac[19]) & 0x0F;
        $binCode = (
            ((ord($hmac[$offset]) & 0x7F) << 24) |
            ((ord($hmac[$offset + 1]) & 0xFF) << 16) |
            ((ord($hmac[$offset + 2]) & 0xFF) << 8) |
            (ord($hmac[$offset + 3]) & 0xFF)
        );

        // Modulo to get desired number of digits
        $modulo = 10 ** $digits;
        $otp = $binCode % $modulo;

        return str_pad((string) $otp, $digits, '0', STR_PAD_LEFT);
    }

    /** Compute floor(timestamp / period). */
    private static function timeCounter(int $timestamp, int $period): int
    {
        return intdiv($timestamp, $period);
    }

    /**
     * Base32 encode (RFC 4648).
     * Output is uppercase with no padding characters.
     */
    private static function base32Encode(string $data): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $result = '';
        $buffer = 0;
        $bitsLeft = 0;

        for ($i = 0, $len = strlen($data); $i < $len; $i++) {
            $buffer = ($buffer << 8) | ord($data[$i]);
            $bitsLeft += 8;

            while ($bitsLeft >= 5) {
                $bitsLeft -= 5;
                $result .= $alphabet[($buffer >> $bitsLeft) & 0x1F];
            }
        }

        if ($bitsLeft > 0) {
            $result .= $alphabet[($buffer << (5 - $bitsLeft)) & 0x1F];
        }

        return $result;
    }

    /**
     * Base32 decode (RFC 4648).
     * Handles uppercase, lowercase, and stripped padding.
     */
    private static function base32Decode(string $data): string
    {
        $data = strtoupper(trim($data, '='));
        $map = array_flip(str_split('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'));
        $buffer = 0;
        $bitsLeft = 0;
        $result = '';

        for ($i = 0, $len = strlen($data); $i < $len; $i++) {
            if (!isset($map[$data[$i]])) {
                throw new \InvalidArgumentException("Invalid base32 character: {$data[$i]}");
            }

            $buffer = ($buffer << 5) | $map[$data[$i]];
            $bitsLeft += 5;

            if ($bitsLeft >= 8) {
                $bitsLeft -= 8;
                $result .= chr(($buffer >> $bitsLeft) & 0xFF);
            }
        }

        return $result;
    }
}
