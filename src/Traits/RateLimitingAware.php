<?php

declare(strict_types=1);

namespace GhostAuth\Traits;

use Psr\SimpleCache\CacheInterface;

/**
 * RateLimitingAware
 *
 * A plug-and-play trait for applying sliding-window rate limiting to any
 * class that performs repeated operations (OTP dispatch, login attempts, etc.)
 *
 * Usage in a provider or middleware:
 *
 *   class MyController {
 *       use RateLimitingAware;
 *
 *       public function login(Request $request): Response {
 *           $this->initRateLimit($this->cache, 'login', 5, 60);
 *
 *           if ($this->isRateLimited($request->ip())) {
 *               return Response::tooManyRequests('Slow down!');
 *           }
 *           // ... auth logic
 *       }
 *   }
 *
 * This is intentionally lightweight — consuming applications with advanced
 * needs (Leaky Bucket, Token Bucket) should implement their own strategy.
 *
 * @package GhostAuth\Traits
 */
trait RateLimitingAware
{
    private CacheInterface $rateLimitCache;
    private string $rateLimitAction;
    private int $rateLimitMaxAttempts;
    private int $rateLimitDecaySeconds;

    /**
     * Initialize rate limiting configuration.
     *
     * @param CacheInterface $cache          PSR-16 cache for attempt counters.
     * @param string         $action         Action identifier (e.g. 'otp_send', 'login').
     * @param int            $maxAttempts    Max attempts allowed in the window.
     * @param int            $decaySeconds   Window size in seconds.
     */
    protected function initRateLimit(
        CacheInterface $cache,
        string $action,
        int $maxAttempts,
        int $decaySeconds,
    ): void {
        $this->rateLimitCache         = $cache;
        $this->rateLimitAction        = $action;
        $this->rateLimitMaxAttempts   = $maxAttempts;
        $this->rateLimitDecaySeconds  = $decaySeconds;
    }

    /**
     * Check if the given key (IP address, user ID, etc.) is currently rate-limited.
     * Increments the attempt counter regardless of outcome — call this BEFORE the action.
     *
     * @param  string $key  The throttle key (IP, user ID, email hash, etc.)
     * @return bool         True if rate-limited (should be blocked), false if allowed.
     */
    protected function isRateLimited(string $key): bool
    {
        $cacheKey = 'ghostauth:ratelimit:' . $this->rateLimitAction . ':' . hash('sha256', $key);

        $attempts = (int) ($this->rateLimitCache->get($cacheKey, 0));

        if ($attempts >= $this->rateLimitMaxAttempts) {
            return true;
        }

        // Increment. If this is the first attempt, the TTL starts the window.
        $this->rateLimitCache->set(
            $cacheKey,
            $attempts + 1,
            $this->rateLimitDecaySeconds,
        );

        return false;
    }

    /**
     * Return the number of remaining attempts for the given key.
     * Useful for including a `Retry-After`-style header in your response.
     *
     * @param  string $key  The throttle key.
     * @return int          Remaining attempts (0 if rate-limited).
     */
    protected function remainingAttempts(string $key): int
    {
        $cacheKey = 'ghostauth:ratelimit:' . $this->rateLimitAction . ':' . hash('sha256', $key);
        $attempts = (int) ($this->rateLimitCache->get($cacheKey, 0));

        return max(0, $this->rateLimitMaxAttempts - $attempts);
    }

    /**
     * Manually clear the rate limit for a given key.
     * Useful after a successful authentication (reset failed-login counter).
     *
     * @param  string $key  The throttle key.
     */
    protected function clearRateLimit(string $key): void
    {
        $cacheKey = 'ghostauth:ratelimit:' . $this->rateLimitAction . ':' . hash('sha256', $key);
        $this->rateLimitCache->delete($cacheKey);
    }
}
