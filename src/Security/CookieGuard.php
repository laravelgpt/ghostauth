<?php

declare(strict_types=1);

namespace GhostAuth\Security;

/**
 * CookieGuard (v1)
 *
 * Provides cookie encryption, signing, and IP change cookie destruction
 * for GhostAuth v1. Ported to v2's SessionGuard with more features.
 *
 * Features:
 *   - AES-256-CTR encryption of cookie payload
 *   - HMAC-SHA256 integrity signature
 *   - IP address binding — cookie invalidated on IP change
 *   - Secure cookie attributes (HttpOnly, Secure, SameSite=Strict)
 *
 * @package GhostAuth\Security
 */
class CookieGuard
{
    public const  COOKIE_NAME      = 'ghostauth_session';
    public const     COOKIE_LIFETIME  = 3600;
    public const  AES_MODE         = 'aes-256-ctr';
    public const  HMAC_VERSION     = 'v1';

    public function __construct(
        private string $encryptionKey,
        private bool   $strictIpBinding = true,
        private bool   $httpsOnly       = true,
    ) {
        if (strlen($encryptionKey) < 32) {
            throw new \RuntimeException('CookieGuard encryption key must be at least 32 bytes.');
        }
    }

    /**
     * Read and decrypt a session cookie, validating HMAC and IP binding.
     *
     * @param  string      $cookieValue  Raw cookie from HTTP request.
     * @param  string|null $currentIp    Current request IP (e.g. $_SERVER['REMOTE_ADDR']).
     * @return array{token: string, user_id: mixed, ip: string}
     * @throws \RuntimeException  On invalid, expired, or tampered cookie.
     */
    public function read(string $cookieValue, ?string $currentIp = null): array
    {
        $parts = explode('.', $cookieValue);

        if (count($parts) !== 4 || $parts[0] !== self::HMAC_VERSION) {
            throw new \RuntimeException('Invalid or expired session cookie.');
        }

        [$version, $providedHmac, $iv, $ciphertext] = $parts;

        // Verify HMAC
        if (! hash_equals($this->hmac($iv . '.' . $ciphertext), $providedHmac)) {
            throw new \RuntimeException('Session cookie integrity check failed.');
        }

        // Decrypt
        $ivBytes = base64_decode($iv);
        $json = openssl_decrypt(
            base64_decode($ciphertext),
            self::AES_MODE,
            $this->encryptionKey,
            OPENSSL_RAW_DATA,
            $ivBytes,
        );

        if ($json === false) {
            throw new \RuntimeException('Session cookie decryption failed.');
        }

        $payload = json_decode($json, true);

        if (! is_array($payload) || ! isset($payload['token'], $payload['user_id'], $payload['ip'])) {
            throw new \RuntimeException('Malformed session cookie.');
        }

        // IP change cookie destroyer
        if ($this->strictIpBinding && $currentIp !== null && $payload['ip'] !== $currentIp) {
            throw new \RuntimeException(
                'Session invalidated: IP address changed from '
                . $payload['ip'] . ' to ' . $currentIp
                . '. Cookie destroyed. Please log in again.'
            );
        }

        return [
            'token'   => $payload['token'],
            'user_id' => $payload['user_id'],
            'ip'      => $payload['ip'],
        ];
    }

    /**
     * Create an encrypted, signed session cookie.
     *
     * @param  string $token   JWT or session token.
     * @param  mixed  $userId  User identifier.
     * @param  string $ip      Client IP address to bind the cookie to.
     * @return string          Encrypted + signed cookie value.
     */
    public function create(string $token, mixed $userId, string $ip): string
    {
        $payload = [
            'token'   => $token,
            'user_id' => $userId,
            'ip'      => $ip,
        ];

        $json = json_encode($payload, JSON_THROW_ON_ERROR);

        // Encrypt
        $ivBytes = random_bytes(openssl_cipher_iv_length(self::AES_MODE));
        $iv      = base64_encode($ivBytes);

        $ciphertext = openssl_encrypt($json, self::AES_MODE, $this->encryptionKey, OPENSSL_RAW_DATA, $ivBytes);

        if ($ciphertext === false) {
            throw new \RuntimeException('Cookie encryption failed.');
        }

        $ctEncoded = base64_encode($ciphertext);

        // Sign
        $hmac = $this->hmac($iv . '.' . $ctEncoded);

        return implode('.', [self::HMAC_VERSION, $hmac, $iv, $ctEncoded]);
    }

    /**
     * Set the session cookie with secure attributes.
     */
    public function setCookie(string $cookieValue, int $lifetime = self::COOKIE_LIFETIME): void
    {
        if (headers_sent()) {
            return;
        }

        setcookie(self::COOKIE_NAME, $cookieValue, [
            'expires'  => time() + $lifetime,
            'path'     => '/',
            'domain'   => '',
            'secure'   => $this->httpsOnly,
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
    }

    /**
     * Destroy the cookie (logout).
     */
    public function destroy(): void
    {
        if (headers_sent()) {
            return;
        }

        setcookie(self::COOKIE_NAME, 'deleted', [
            'expires'  => time() - 3600,
            'path'     => '/',
            'domain'   => '',
            'secure'   => $this->httpsOnly,
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
    }

    private function hmac(string $data): string
    {
        return hash_hmac('sha256', self::HMAC_VERSION . '|' . $data, $this->encryptionKey);
    }
}
