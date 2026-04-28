<?php

declare(strict_types=1);

namespace GhostAuth\Security;

/**
 * DeviceFingerprint (v1 port)
 *
 * Generates a stable fingerprint from HTTP request characteristics.
 * Used for detecting session hijacking and IP change cookie destruction.
 *
 * @package GhostAuth\Security
 */
class DeviceFingerprint
{
    /**
     * @param string $remoteIp
     * @param string $userAgent
     * @param string $acceptLanguage
     * @param string $salt
     */
    public function __construct(
        private string $remoteIp,
        private string $userAgent,
        private string $acceptLanguage = '',
        private string $salt = '',
    ) {}

    public static function fromRequest(array $server, string $salt = ''): static
    {
        return new static(
            $server['REMOTE_ADDR'] ?? '0.0.0.0',
            $server['HTTP_USER_AGENT'] ?? '',
            $server['HTTP_ACCEPT_LANGUAGE'] ?? '',
            $salt,
        );
    }

    /** @return string 64-char hex SHA-256 hash */
    public function compute(): string
    {
        return hash('sha256', implode('|', [
            $this->remoteIp,
            $this->userAgent,
            $this->acceptLanguage,
            $this->salt,
        ]));
    }

    /** Constant-time comparison against stored fingerprint */
    public function matches(string $storedFingerprint): bool
    {
        return hash_equals($storedFingerprint, $this->compute());
    }

    public function getIp(): string        { return $this->remoteIp; }
    public function getUserAgent(): string { return $this->userAgent; }
    public function getLanguage(): string  { return $this->acceptLanguage; }
}
