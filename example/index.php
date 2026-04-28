<?php

declare(strict_types=1);

/**
 * GhostAuth — Usage Example
 * =============================================================================
 * This file demonstrates how a developer wires up and uses GhostAuth
 * in a plain PHP application (no framework required).
 *
 * Sections:
 *   1. Stub implementations of UserProviderInterface & AuthenticatableInterface
 *   2. Wiring GhostAuthManager with EmailPassword + OTP providers
 *   3. Email + Password authentication
 *   4. Email OTP — Phase 1: send the code
 *   5. Email OTP — Phase 2: verify the code
 *   6. Token verification and logout (revocation)
 * =============================================================================
 */

require_once __DIR__ . '/../vendor/autoload.php';

use GhostAuth\Auth\AuthResult;
use GhostAuth\Contracts\AuthenticatableInterface;
use GhostAuth\Contracts\OtpSenderInterface;
use GhostAuth\Contracts\UserProviderInterface;
use GhostAuth\Exceptions\OtpDeliveryException;
use GhostAuth\GhostAuthManager;
use GhostAuth\Providers\EmailPasswordProvider;
use GhostAuth\Providers\OtpProvider;
use GhostAuth\Tokens\JwtIssuer;

// =============================================================================
// 1. STUB IMPLEMENTATIONS
//    In a real app these would be backed by Eloquent, PDO, Doctrine, etc.
// =============================================================================

/**
 * A minimal User entity. Your real User model implements this interface
 * and wraps your ORM row / array / DTO.
 */
final class AppUser implements AuthenticatableInterface
{
    public function __construct(
        private readonly int $id,
        private readonly string $email,
        private ?string $passwordHash = null,
    ) {}

    public function getAuthIdentifier(): int|string { return $this->id; }
    public function getAuthIdentifierName(): string { return 'id'; }
    public function getAuthPassword(): ?string      { return $this->passwordHash; }
    public function getEmail(): ?string             { return $this->email; }
    public function getPhone(): ?string             { return null; }

    /** Extra claims to embed into the JWT payload */
    public function getJwtClaims(): array
    {
        return ['role' => 'user', 'plan' => 'free'];
    }

    /** (Helper for the demo — not part of the interface) */
    public function setPasswordHash(string $hash): void
    {
        $this->passwordHash = $hash;
    }
}

/**
 * In-memory user store. Replace with a database-backed implementation.
 */
final class InMemoryUserProvider implements UserProviderInterface
{
    /** @var AppUser[] */
    private array $users = [];
    private int $nextId  = 1;

    public function addUser(AppUser $user): void
    {
        $this->users[$user->getAuthIdentifier()] = $user;
    }

    public function findByEmail(string $email): ?AuthenticatableInterface
    {
        foreach ($this->users as $user) {
            if (strtolower($user->getEmail() ?? '') === strtolower($email)) {
                return $user;
            }
        }
        return null;
    }

    public function findByPhone(string $phone): ?AuthenticatableInterface
    {
        return null; // Not used in this demo
    }

    public function findById(int|string $id): ?AuthenticatableInterface
    {
        return $this->users[$id] ?? null;
    }

    public function create(array $attributes): AuthenticatableInterface
    {
        $user = new AppUser(
            id: $this->nextId++,
            email: $attributes['email'],
        );
        $this->users[$user->getAuthIdentifier()] = $user;
        return $user;
    }

    public function update(int|string $id, array $attributes): bool
    {
        if (! isset($this->users[$id])) {
            return false;
        }
        // Handle password rehash silently
        if (isset($attributes['password'])) {
            $this->users[$id]->setPasswordHash($attributes['password']);
        }
        return true;
    }
}

/**
 * Console OTP sender — prints the OTP to stdout.
 * Production implementations would call Mailgun, SendGrid, Twilio, AWS SNS, etc.
 */
final class ConsoleOtpSender implements OtpSenderInterface
{
    public function send(string $recipient, string $otp, string $channel = 'email'): bool
    {
        echo "\n📨 [{$channel}] OTP for {$recipient}: {$otp}\n";
        return true;
    }
}

// =============================================================================
// 2. WIRE UP GHOSTAUTH
// =============================================================================

// ---------- JWT Issuer (HS256 for this demo — use RS256 in production) -------

$jwtIssuer = new JwtIssuer(
    algorithm:          JwtIssuer::ALGO_HS256,
    privateKeyOrSecret: 'super-secret-key-at-least-32-bytes!!',  // ← use env var in prod
    publicKey:          null,                                     // not required for HS256
    issuer:             'https://myapp.example.com',
    audience:           'https://api.myapp.example.com',
    ttlSeconds:         3600,
    denylistCache:      null,   // set a PSR-16 cache here to enable token revocation
);

// ---------- User Provider (in-memory for demo) --------------------------------

$userProvider = new InMemoryUserProvider();

// Pre-seed a user with a hashed password.
// We need the EmailPasswordProvider instance first to hash correctly.
$emailPasswordProvider = new EmailPasswordProvider(
    userProvider: $userProvider,
    tokenIssuer:  $jwtIssuer,
    pepper:       'my-pepper-from-env',   // ← store in secrets manager / .env
    enabled:      true,
);

$demoUser = new AppUser(1, 'alice@example.com');
$demoUser->setPasswordHash($emailPasswordProvider->hashPassword('correct-horse-battery-staple'));
$userProvider->addUser($demoUser);

// ---------- OTP Provider (requires a PSR-16 compatible cache) -----------------

// For the demo we use a trivial in-process array cache.
// In production: use Redis (e.g. symfony/cache's RedisAdapter) or Memcached.
$arrayCache = new class implements \Psr\SimpleCache\CacheInterface {
    private array $store = [];
    private array $expiry = [];

    public function get(string $key, mixed $default = null): mixed
    {
        if (isset($this->expiry[$key]) && $this->expiry[$key] < time()) {
            $this->delete($key); return $default;
        }
        return $this->store[$key] ?? $default;
    }
    public function set(string $key, mixed $value, null|int|\DateInterval $ttl = null): bool
    {
        $this->store[$key] = $value;
        if (is_int($ttl)) { $this->expiry[$key] = time() + $ttl; }
        return true;
    }
    public function delete(string $key): bool
    {
        unset($this->store[$key], $this->expiry[$key]); return true;
    }
    public function clear(): bool { $this->store = []; $this->expiry = []; return true; }
    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        foreach ($keys as $k) yield $k => $this->get($k, $default);
    }
    public function setMultiple(iterable $values, null|int|\DateInterval $ttl = null): bool
    {
        foreach ($values as $k => $v) $this->set($k, $v, $ttl); return true;
    }
    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $k) $this->delete($k); return true;
    }
    public function has(string $key): bool { return $this->get($key) !== null; }
};

$otpProvider = new OtpProvider(
    userProvider:   $userProvider,
    tokenIssuer:    $jwtIssuer,
    otpSender:      new ConsoleOtpSender(),
    cache:          $arrayCache,
    hmacSecret:     bin2hex('my-32-byte-otp-hmac-secret!!!!!'),  // must be ≥ 32 bytes
    otpLength:      6,
    otpTtlSeconds:  300,  // OTPs expire after 5 minutes
    maxAttempts:    5,
    autoCreateUser: true, // auto-provision user on first OTP login
);

// ---------- GhostAuthManager — the single entry point ------------------------

$auth = new GhostAuthManager(tokenIssuer: $jwtIssuer);

$auth
    ->registerProvider($emailPasswordProvider, setDefault: true)
    ->registerProvider($otpProvider);

// =============================================================================
// 3. EMAIL + PASSWORD AUTHENTICATION
// =============================================================================

echo "\n=== Email + Password Login ===\n";

$result = $auth->authenticate(
    credentials: [
        'email'    => 'alice@example.com',
        'password' => 'correct-horse-battery-staple',
    ],
    provider: 'email_password',  // or omit — 'email_password' is the default
);

if ($result->isSuccess()) {
    echo "✅ Logged in as user #{$result->getUser()->getAuthIdentifier()}\n";
    echo "🔑 JWT: " . substr($result->getToken(), 0, 40) . "...\n";

    $token = $result->getToken(); // save for step 6
} else {
    echo "❌ Login failed: [{$result->getErrorCode()}] {$result->getErrorMessage()}\n";
}

// Bad password demo
echo "\n--- Wrong password ---\n";
$failResult = $auth->authenticate(
    credentials: ['email' => 'alice@example.com', 'password' => 'wrong-password'],
    provider: 'email_password',
);
echo $failResult->isSuccess()
    ? "✅ Unexpected success\n"
    : "❌ Correctly rejected: [{$failResult->getErrorCode()}] {$failResult->getErrorMessage()}\n";

// =============================================================================
// 4. EMAIL OTP — PHASE 1: REQUEST THE CODE
// =============================================================================

echo "\n=== Email OTP — Phase 1: Send Code ===\n";

// alice@example.com already exists; bob@example.com will be auto-created
$otpTarget = 'bob@example.com';

$sendResult = $auth->authenticate(
    credentials: ['email' => $otpTarget],
    provider: 'otp',
);

if ($sendResult->getErrorCode() === 'OTP_SENT') {
    echo "⏳ OTP sent! Expires in {$sendResult->getMeta()['expires_in']}s\n";
}

// =============================================================================
// 5. EMAIL OTP — PHASE 2: VERIFY THE CODE
//    In a real app, the user submits this from your UI.
//    For the demo, we capture it from ConsoleOtpSender's output — see step 4 output.
// =============================================================================

echo "\n=== Email OTP — Phase 2: Verify Code ===\n";

// NOTE: Replace '123456' with the actual OTP printed above to see success.
// This demo intentionally shows the failure path since we can't read stdout.
$verifyResult = $auth->authenticate(
    credentials: [
        'email' => $otpTarget,
        'otp'   => '000000',  // ← replace with the printed OTP for success
    ],
    provider: 'otp',
);

if ($verifyResult->isSuccess()) {
    echo "✅ OTP verified! Logged in as user #{$verifyResult->getUser()->getAuthIdentifier()}\n";
    echo "🔑 JWT: " . substr($verifyResult->getToken(), 0, 40) . "...\n";
} else {
    echo "❌ OTP failed: [{$verifyResult->getErrorCode()}] {$verifyResult->getErrorMessage()}\n";
    echo "ℹ️  Tip: Replace '000000' with the OTP printed above to see success.\n";
}

// =============================================================================
// 6. TOKEN VERIFICATION + REVOCATION (LOGOUT)
// =============================================================================

echo "\n=== Token Verification ===\n";

if (isset($token)) {
    try {
        $payload = $auth->verifyToken($token);
        echo "✅ Token valid. sub={$payload['sub']}, exp={$payload['exp']}\n";
    } catch (\GhostAuth\Exceptions\TokenException $e) {
        echo "❌ Token invalid: {$e->getMessage()}\n";
    }

    // Revocation demo (no-op here since denylistCache is null — just shows the API)
    $revoked = $auth->revokeToken($token);
    echo $revoked
        ? "🔒 Token successfully revoked (added to denylist).\n"
        : "ℹ️  Revocation skipped — configure denylistCache in JwtIssuer to enable.\n";
}

echo "\n✨ GhostAuth MVP demo complete.\n\n";
