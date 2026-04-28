<?php

declare(strict_types=1);

namespace GhostAuth\Providers;

use GhostAuth\Auth\AuthResult;
use GhostAuth\Contracts\AuthResultInterface;
use GhostAuth\Contracts\AuthenticatableInterface;
use GhostAuth\Contracts\AuthenticationProviderInterface;
use GhostAuth\Contracts\TokenIssuerInterface;
use GhostAuth\Contracts\UserProviderInterface;
use GhostAuth\Exceptions\GhostAuthException;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * EmailPasswordProvider
 *
 * Authenticates users with an email address and password.
 *
 * Security practices implemented:
 *
 * 1. Constant-time comparison via password_verify() — prevents timing attacks that
 *    could confirm whether an email address is registered.
 *
 * 2. Argon2id hashing — memory-hard algorithm resistant to GPU/ASIC brute-force.
 *    PHP's password_hash(PASSWORD_ARGON2ID) handles salt generation automatically.
 *
 * 3. Pepper support (optional) — an application-level secret appended before hashing.
 *    Even if the database is exfiltrated, hashes are useless without the pepper.
 *    Store the pepper in a secrets manager / environment variable, NOT the database.
 *
 * 4. Rehashing on login — if PHP's cost parameters have increased since the hash was
 *    created, we silently upgrade the hash on successful login.
 *
 * 5. Generic error messages — we return the same error for "user not found" and
 *    "wrong password" to prevent user enumeration.
 *
 * Expected credentials:
 *   ['email' => string, 'password' => string]
 *
 * @package GhostAuth\Providers
 */
final class EmailPasswordProvider implements AuthenticationProviderInterface
{
    /**
     * Argon2id memory cost in KiB.
     * OWASP recommends ≥ 19 MiB (19456 KiB) for 2023+.
     * Adjust based on your server's available memory per request.
     */
    private const ARGON2_MEMORY_COST = 65536; // 64 MiB

    /**
     * Argon2id time cost (iterations).
     */
    private const ARGON2_TIME_COST = 4;

    /**
     * Argon2id parallelism (threads).
     */
    private const ARGON2_THREADS = 2;

    /**
     * @param UserProviderInterface $userProvider  Application's user persistence adapter.
     * @param TokenIssuerInterface  $tokenIssuer   JWT or session token issuer.
     * @param string|null           $pepper        Optional secret pepper (from env/secrets manager).
     * @param bool                  $enabled        Whether this provider is active.
     * @param LoggerInterface       $logger         PSR-3 logger.
     */
    public function __construct(
        private readonly UserProviderInterface $userProvider,
        private readonly TokenIssuerInterface $tokenIssuer,
        private readonly ?string $pepper = null,
        private readonly bool $enabled = true,
        private readonly LoggerInterface $logger = new NullLogger(),
    ) {}

    // -------------------------------------------------------------------------
    // AuthenticationProviderInterface
    // -------------------------------------------------------------------------

    /**
     * Authenticate a user by email and password.
     *
     * @param  array<string, mixed> $credentials  Must contain 'email' and 'password' keys.
     * @return AuthResultInterface
     * @throws GhostAuthException  On misconfiguration or infrastructure failure.
     */
    public function authenticate(array $credentials): AuthResultInterface
    {
        $this->guardEnabled();
        $this->validateCredentialKeys($credentials, ['email', 'password']);

        $email    = strtolower(trim((string) $credentials['email']));
        $password = (string) $credentials['password'];

        // ------------------------------------------------------------------
        // 1. Look up the user.
        //    We intentionally do NOT short-circuit here before calling
        //    password_verify() — if we returned immediately on "user not found",
        //    a timing attack could enumerate valid email addresses.
        //    Instead we always run verification against a dummy hash.
        // ------------------------------------------------------------------
        $user = $this->userProvider->findByEmail($email);

        if ($user === null) {
            // Run a dummy verify to maintain constant time response.
            // The dummy hash is a valid Argon2id hash of a throwaway string.
            password_verify('dummy', '$argon2id$v=19$m=65536,t=4,p=2$dummysaltdummysalt$dummyhash');

            $this->logger->warning('EmailPasswordProvider: auth failed — user not found', [
                'email' => $email,
            ]);

            // Generic message intentionally — do not confirm whether email exists
            return AuthResult::failure(
                'INVALID_CREDENTIALS',
                'The email or password you entered is incorrect.',
            );
        }

        // ------------------------------------------------------------------
        // 2. Verify the password (with optional pepper).
        // ------------------------------------------------------------------
        $storedHash = $user->getAuthPassword();

        if ($storedHash === null) {
            // This user was created via social/OTP — they have no password.
            return AuthResult::failure(
                'NO_PASSWORD',
                'This account uses passwordless login. Please use your configured login method.',
            );
        }

        $inputToVerify = $this->applyPepper($password);

        if (! password_verify($inputToVerify, $storedHash)) {
            $this->logger->warning('EmailPasswordProvider: auth failed — wrong password', [
                'user_id' => $user->getAuthIdentifier(),
            ]);

            return AuthResult::failure(
                'INVALID_CREDENTIALS',
                'The email or password you entered is incorrect.',
            );
        }

        // ------------------------------------------------------------------
        // 3. Silently rehash if PHP's defaults have improved since registration.
        //    This transparently upgrades security on every login without a
        //    forced password-reset campaign.
        // ------------------------------------------------------------------
        if (password_needs_rehash($storedHash, PASSWORD_ARGON2ID, $this->argon2Options())) {
            $newHash = $this->hashPassword($password);
            $this->userProvider->update($user->getAuthIdentifier(), ['password' => $newHash]);

            $this->logger->info('EmailPasswordProvider: password rehashed for upgraded cost params', [
                'user_id' => $user->getAuthIdentifier(),
            ]);
        }

        // ------------------------------------------------------------------
        // 4. Issue a token and return a success result.
        // ------------------------------------------------------------------
        $token = $this->tokenIssuer->issue($user);

        $this->logger->info('EmailPasswordProvider: authentication successful', [
            'user_id' => $user->getAuthIdentifier(),
        ]);

        return AuthResult::success($user, $token);
    }

    public function getProviderName(): string
    {
        return 'email_password';
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    // -------------------------------------------------------------------------
    // Public utility — useful for user registration flows
    // -------------------------------------------------------------------------

    /**
     * Hash a plaintext password using Argon2id with the configured options.
     * Use this when creating or updating a user's password.
     *
     * @param  string $plaintext  The raw password from the user.
     * @return string             The Argon2id hash to persist.
     */
    public function hashPassword(string $plaintext): string
    {
        return password_hash(
            $this->applyPepper($plaintext),
            PASSWORD_ARGON2ID,
            $this->argon2Options(),
        );
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Append the pepper (if configured) to the plaintext before hashing/verifying.
     * The pepper is a static secret; it does not need to be unique per user.
     */
    private function applyPepper(string $plaintext): string
    {
        return $this->pepper !== null
            ? $plaintext . $this->pepper
            : $plaintext;
    }

    /**
     * Return the Argon2id algorithm options array.
     *
     * @return array<string, int>
     */
    private function argon2Options(): array
    {
        return [
            'memory_cost' => self::ARGON2_MEMORY_COST,
            'time_cost'   => self::ARGON2_TIME_COST,
            'threads'     => self::ARGON2_THREADS,
        ];
    }

    /**
     * Throw if the provider is disabled (misconfiguration guard).
     *
     * @throws GhostAuthException
     */
    private function guardEnabled(): void
    {
        if (! $this->enabled) {
            throw new GhostAuthException(
                'EmailPasswordProvider is disabled. Enable it in GhostAuth configuration.'
            );
        }
    }

    /**
     * Ensure required credential keys are present.
     *
     * @param  array<string, mixed> $credentials
     * @param  string[]             $required
     * @throws GhostAuthException
     */
    private function validateCredentialKeys(array $credentials, array $required): void
    {
        foreach ($required as $key) {
            if (! array_key_exists($key, $credentials) || (string) $credentials[$key] === '') {
                throw new GhostAuthException(
                    "EmailPasswordProvider: missing required credential key: '{$key}'."
                );
            }
        }
    }
}
