<?php

declare(strict_types=1);

namespace GhostAuth\Providers;

use GhostAuth\Auth\AuthResult;
use GhostAuth\Contracts\AuthResultInterface;
use GhostAuth\Contracts\AuthenticationProviderInterface;
use GhostAuth\Contracts\OtpSenderInterface;
use GhostAuth\Contracts\TokenIssuerInterface;
use GhostAuth\Contracts\UserProviderInterface;
use GhostAuth\Exceptions\GhostAuthException;
use GhostAuth\Exceptions\OtpDeliveryException;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Psr\SimpleCache\CacheInterface;

/**
 * OtpProvider
 *
 * Handles passwordless authentication via One-Time Passwords delivered
 * over Email or SMS (Phone). The flow has two distinct phases:
 *
 * ── Phase 1: SEND ──────────────────────────────────────────────────────────
 *   Credentials: ['email' => '...'] OR ['phone' => '+8801...']
 *   Action: Generates and dispatches an OTP; returns AuthResult::pending()
 *   Client response: Show "Enter your code" UI
 *
 * ── Phase 2: VERIFY ────────────────────────────────────────────────────────
 *   Credentials: ['email' => '...', 'otp' => '123456']  OR
 *                ['phone' => '+8801...', 'otp' => '123456']
 *   Action: Verifies the code; returns AuthResult::success() + token
 *
 * Security practices:
 *
 * 1. OTP storage  — We NEVER store the plaintext OTP. We store a hash_hmac()
 *    digest (HMAC-SHA256 keyed with a server secret). Even if the cache is
 *    read by an attacker, the raw OTP is not recoverable.
 *
 * 2. Time-limited  — OTPs expire after $otpTtlSeconds (default: 5 minutes).
 *    Cache TTL enforces this automatically.
 *
 * 3. Single-use   — On successful verification the cache entry is deleted
 *    immediately, preventing replay attacks.
 *
 * 4. Attempt limiting  — Failed verify attempts increment a counter.
 *    After $maxAttempts the OTP is invalidated (prevents brute-force on the
 *    small OTP keyspace). The consuming app SHOULD also apply rate limiting
 *    at the HTTP layer for defense-in-depth.
 *
 * 5. Constant-time comparison — hash_equals() compares the submitted HMAC
 *    against the stored HMAC to prevent timing attacks.
 *
 * 6. CSPRNG generation — random_int() is cryptographically secure on all
 *    platforms supported by PHP 8.3.
 *
 * @package GhostAuth\Providers
 */
final class OtpProvider implements AuthenticationProviderInterface
{
    /**
     * Supported delivery channels for OTP dispatch.
     */
    public const CHANNEL_EMAIL = 'email';
    public const CHANNEL_SMS   = 'sms';

    /**
     * Cache key prefixes to namespace OTP and attempt data.
     */
    private const CACHE_OTP_PREFIX      = 'ghostauth:otp:hash:';
    private const CACHE_ATTEMPT_PREFIX  = 'ghostauth:otp:attempts:';

    /**
     * @param UserProviderInterface $userProvider    Application's user persistence adapter.
     * @param TokenIssuerInterface  $tokenIssuer     JWT or session token issuer.
     * @param OtpSenderInterface    $otpSender       Delivery adapter (email/SMS).
     * @param CacheInterface        $cache           PSR-16 cache (Redis/Memcached/APCu recommended).
     * @param string                $hmacSecret      Server-side HMAC key — MUST be ≥ 32 bytes, stored in env.
     * @param int                   $otpLength       Number of digits in the OTP (default: 6).
     * @param int                   $otpTtlSeconds   OTP validity window in seconds (default: 300 = 5 min).
     * @param int                   $maxAttempts     Max failed verifications before invalidation (default: 5).
     * @param bool                  $enabled         Whether this provider is active.
     * @param bool                  $autoCreateUser  If true, creates the user on first successful OTP verify.
     * @param LoggerInterface       $logger          PSR-3 logger.
     */
    public function __construct(
        private readonly UserProviderInterface $userProvider,
        private readonly TokenIssuerInterface $tokenIssuer,
        private readonly OtpSenderInterface $otpSender,
        private readonly CacheInterface $cache,
        private readonly string $hmacSecret,
        private readonly int $otpLength = 6,
        private readonly int $otpTtlSeconds = 300,
        private readonly int $maxAttempts = 5,
        private readonly bool $enabled = true,
        private readonly bool $autoCreateUser = false,
        private readonly LoggerInterface $logger = new NullLogger(),
    ) {
        if (strlen($hmacSecret) < 32) {
            throw new GhostAuthException(
                'OtpProvider: hmacSecret must be at least 32 bytes. '
                . 'Generate one with: bin2hex(random_bytes(32))'
            );
        }
    }

    // -------------------------------------------------------------------------
    // AuthenticationProviderInterface
    // -------------------------------------------------------------------------

    /**
     * Route to send or verify based on whether credentials contain 'otp'.
     *
     * Phase 1 (send):   credentials = ['email' => '...'] | ['phone' => '...']
     * Phase 2 (verify): credentials = ['email' => '...', 'otp' => '...']
     *                               | ['phone' => '...', 'otp' => '...']
     *
     * @param  array<string, mixed> $credentials
     * @return AuthResultInterface
     * @throws GhostAuthException   On infrastructure / config errors.
     */
    public function authenticate(array $credentials): AuthResultInterface
    {
        $this->guardEnabled();

        [$identifier, $channel] = $this->resolveIdentifier($credentials);

        // If 'otp' is present → Phase 2 (verify)
        if (! empty($credentials['otp'])) {
            return $this->verifyOtp($identifier, $channel, (string) $credentials['otp']);
        }

        // Otherwise → Phase 1 (send)
        return $this->sendOtp($identifier, $channel);
    }

    public function getProviderName(): string
    {
        return 'otp';
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    // -------------------------------------------------------------------------
    // Phase 1: Generate and send OTP
    // -------------------------------------------------------------------------

    /**
     * Generate a CSPRNG OTP, store its HMAC, and dispatch it.
     *
     * @param  string $identifier  Email or E.164 phone number.
     * @param  string $channel     'email' or 'sms'.
     * @return AuthResultInterface  AuthResult::pending() on success.
     *
     * @throws OtpDeliveryException  If the sender fails to dispatch.
     */
    private function sendOtp(string $identifier, string $channel): AuthResultInterface
    {
        // ------------------------------------------------------------------
        // 1. Generate a cryptographically secure N-digit OTP.
        //    random_int() is CSPRNG-backed — never use rand() or mt_rand().
        // ------------------------------------------------------------------
        $otp = $this->generateOtp();

        // ------------------------------------------------------------------
        // 2. Compute HMAC-SHA256 of the plaintext OTP.
        //    We store the HMAC, NOT the plaintext — safe even if cache leaks.
        // ------------------------------------------------------------------
        $hmac    = $this->computeHmac($otp);
        $cacheKey = self::CACHE_OTP_PREFIX . hash('sha256', $identifier);

        $this->cache->set($cacheKey, $hmac, $this->otpTtlSeconds);

        // Reset attempt counter for this identifier
        $attemptKey = self::CACHE_ATTEMPT_PREFIX . hash('sha256', $identifier);
        $this->cache->delete($attemptKey);

        // ------------------------------------------------------------------
        // 3. Dispatch via OtpSenderInterface — application provides the adapter.
        // ------------------------------------------------------------------
        $this->otpSender->send($identifier, $otp, $channel);

        $this->logger->info('OtpProvider: OTP dispatched', [
            'channel'    => $channel,
            'identifier' => $this->maskIdentifier($identifier),
            'expires_in' => $this->otpTtlSeconds,
        ]);

        return AuthResult::pending([
            'channel'    => $channel,
            'expires_in' => $this->otpTtlSeconds,
        ]);
    }

    // -------------------------------------------------------------------------
    // Phase 2: Verify OTP and issue token
    // -------------------------------------------------------------------------

    /**
     * Verify the submitted OTP against the stored HMAC.
     *
     * @param  string $identifier  Email or E.164 phone number.
     * @param  string $channel     'email' or 'sms'.
     * @param  string $submitted   The OTP entered by the user.
     * @return AuthResultInterface
     */
    private function verifyOtp(string $identifier, string $channel, string $submitted): AuthResultInterface
    {
        $cacheKey   = self::CACHE_OTP_PREFIX . hash('sha256', $identifier);
        $attemptKey = self::CACHE_ATTEMPT_PREFIX . hash('sha256', $identifier);

        // ------------------------------------------------------------------
        // 1. Check attempt count — guard against brute-force of the OTP space.
        // ------------------------------------------------------------------
        $attempts = (int) ($this->cache->get($attemptKey, 0));

        if ($attempts >= $this->maxAttempts) {
            // Invalidate the OTP so a new one must be requested
            $this->cache->delete($cacheKey);
            $this->cache->delete($attemptKey);

            $this->logger->warning('OtpProvider: OTP invalidated — max attempts exceeded', [
                'identifier' => $this->maskIdentifier($identifier),
            ]);

            return AuthResult::failure(
                'OTP_MAX_ATTEMPTS',
                'Too many incorrect attempts. Please request a new code.',
            );
        }

        // ------------------------------------------------------------------
        // 2. Retrieve stored HMAC from cache.
        // ------------------------------------------------------------------
        $storedHmac = $this->cache->get($cacheKey);

        if ($storedHmac === null) {
            return AuthResult::failure(
                'OTP_NOT_FOUND',
                'No active OTP found. Please request a new code.',
            );
        }

        // ------------------------------------------------------------------
        // 3. Constant-time comparison of the submitted HMAC vs. stored HMAC.
        //    hash_equals() is immune to timing side-channels.
        // ------------------------------------------------------------------
        $submittedHmac = $this->computeHmac($submitted);

        if (! hash_equals($storedHmac, $submittedHmac)) {
            // Increment attempt counter — TTL matches OTP TTL so it auto-clears
            $this->cache->set($attemptKey, $attempts + 1, $this->otpTtlSeconds);

            $this->logger->warning('OtpProvider: OTP verification failed', [
                'identifier' => $this->maskIdentifier($identifier),
                'attempt'    => $attempts + 1,
            ]);

            return AuthResult::failure(
                'OTP_INVALID',
                'The code you entered is incorrect.',
                ['attempts_remaining' => $this->maxAttempts - $attempts - 1],
            );
        }

        // ------------------------------------------------------------------
        // 4. OTP is correct — consume it immediately (single-use).
        // ------------------------------------------------------------------
        $this->cache->delete($cacheKey);
        $this->cache->delete($attemptKey);

        // ------------------------------------------------------------------
        // 5. Retrieve or auto-provision the user.
        // ------------------------------------------------------------------
        $user = $channel === self::CHANNEL_EMAIL
            ? $this->userProvider->findByEmail($identifier)
            : $this->userProvider->findByPhone($identifier);

        if ($user === null) {
            if (! $this->autoCreateUser) {
                return AuthResult::failure(
                    'USER_NOT_FOUND',
                    'No account associated with this ' . $channel . ' address.',
                );
            }

            // Just-in-time user provisioning (social-style first login)
            $attributes = $channel === self::CHANNEL_EMAIL
                ? ['email' => $identifier]
                : ['phone' => $identifier];

            $user = $this->userProvider->create($attributes);

            $this->logger->info('OtpProvider: auto-created user on first OTP login', [
                'user_id' => $user->getAuthIdentifier(),
                'channel' => $channel,
            ]);
        }

        // ------------------------------------------------------------------
        // 6. Issue token and return success.
        // ------------------------------------------------------------------
        $token = $this->tokenIssuer->issue($user);

        $this->logger->info('OtpProvider: OTP authentication successful', [
            'user_id' => $user->getAuthIdentifier(),
            'channel' => $channel,
        ]);

        return AuthResult::success($user, $token, ['channel' => $channel]);
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Generate a zero-padded N-digit OTP using CSPRNG.
     * e.g. for $otpLength = 6: '041829'
     *
     * @return string
     */
    private function generateOtp(): string
    {
        $max = (int) str_repeat('9', $this->otpLength);
        $otp = random_int(0, $max);

        return str_pad((string) $otp, $this->otpLength, '0', STR_PAD_LEFT);
    }

    /**
     * Compute HMAC-SHA256 of the OTP using the server-side secret.
     *
     * @param  string $otp  Plaintext OTP.
     * @return string       Hex-encoded HMAC digest.
     */
    private function computeHmac(string $otp): string
    {
        return hash_hmac('sha256', $otp, $this->hmacSecret);
    }

    /**
     * Resolve the identifier (email or phone) and delivery channel from credentials.
     *
     * @param  array<string, mixed> $credentials
     * @return array{0: string, 1: string}  [identifier, channel]
     * @throws GhostAuthException  If neither email nor phone is provided.
     */
    private function resolveIdentifier(array $credentials): array
    {
        if (! empty($credentials['email'])) {
            return [strtolower(trim((string) $credentials['email'])), self::CHANNEL_EMAIL];
        }

        if (! empty($credentials['phone'])) {
            return [trim((string) $credentials['phone']), self::CHANNEL_SMS];
        }

        throw new GhostAuthException(
            "OtpProvider: credentials must contain 'email' or 'phone'."
        );
    }

    /**
     * Mask an identifier for safe logging.
     * 'jane@example.com' → 'ja**@example.com'
     * '+8801712345678'   → '+880171****5678'
     */
    private function maskIdentifier(string $identifier): string
    {
        if (str_contains($identifier, '@')) {
            [$local, $domain] = explode('@', $identifier, 2);
            $masked = substr($local, 0, 2) . str_repeat('*', max(0, strlen($local) - 2));
            return $masked . '@' . $domain;
        }

        // Phone: show first 7 and last 4 chars
        return substr($identifier, 0, 7)
            . str_repeat('*', max(0, strlen($identifier) - 11))
            . substr($identifier, -4);
    }

    /**
     * @throws GhostAuthException
     */
    private function guardEnabled(): void
    {
        if (! $this->enabled) {
            throw new GhostAuthException(
                'OtpProvider is disabled. Enable it in GhostAuth configuration.'
            );
        }
    }
}
