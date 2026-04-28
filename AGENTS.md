# AGENTS.md — GhostAuth v1

> Guidance for AI coding agents (Copilot, Cursor, Kilo, Claude, etc.) working on this codebase.

---

## Project Identity

- **Package:** `ghostauth/ghostauth`
- **Version:** `1.0.0`
- **PHP:** `^8.3`
- **Architecture:** Strategy Pattern, PSR-4/12/Logger
- **Purpose:** Framework-agnostic PHP authentication library

---

## Directory Map

```
src/
├── GhostAuthManager.php          ← Entry point. Register + dispatch providers here.
├── Auth/
│   └── AuthResult.php            ← Immutable result VO. Use static factories only.
├── Contracts/                    ← All interfaces. Never break these — they are the public API.
│   ├── AuthenticationProviderInterface.php
│   ├── AuthenticatableInterface.php
│   ├── AuthResultInterface.php
│   ├── UserProviderInterface.php
│   ├── TokenIssuerInterface.php
│   ├── OtpSenderInterface.php
│   ├── SocialProviderInterface.php
│   ├── SocialUserInterface.php
│   └── SsoProviderInterface.php
├── Exceptions/                   ← Throw only on infrastructure errors. Auth failures → AuthResult.
├── Models/
│   └── SocialUser.php            ← readonly DTO for normalized OAuth profile.
├── Providers/                    ← One file per auth strategy.
│   ├── EmailPasswordProvider.php
│   ├── OtpProvider.php
│   ├── AbstractSocialProvider.php
│   ├── OidcProvider.php
│   └── Social/
│       ├── GoogleProvider.php
│       └── GitHubProvider.php
├── Tokens/
│   └── JwtIssuer.php             ← RS256 / HS256 JWT. PSR-16 denylist.
└── Traits/
    └── RateLimitingAware.php     ← Sliding-window rate limiting. Plug in anywhere.
```

---

## Core Conventions

### 1. Never throw on auth failures
Auth failures (wrong password, expired OTP, etc.) MUST return `AuthResult::failure(...)`, not throw.
Only throw `GhostAuthException` (or subclass) for infrastructure/config errors (missing keys, disabled provider).

```php
// ✅ Correct
return AuthResult::failure('INVALID_CREDENTIALS', 'Email or password is incorrect.');

// ❌ Wrong
throw new GhostAuthException('Invalid password');
```

### 2. All random values via CSPRNG
```php
// ✅
$token = bin2hex(random_bytes(16));
$otp   = random_int(0, 999999);

// ❌ Never
$token = md5(uniqid());
$otp   = rand(100000, 999999);
```

### 3. No plaintext OTP storage
OTPs are stored as `hash_hmac('sha256', $otp, $secret)`. Never store or log the plaintext.

### 4. Constant-time comparisons
Use `hash_equals()` for all OTP/token comparisons. Use `password_verify()` for passwords.
Never use `===` or `==` for secrets.

### 5. Generic error messages for credentials
Never distinguish "user not found" from "wrong password" in error messages. Both return `INVALID_CREDENTIALS`.

### 6. Adding a new Social Provider
Extend `AbstractSocialProvider` and implement:
- `getAuthorizationEndpoint(): string`
- `getTokenEndpoint(): string`
- `getUserinfoEndpoint(): string`
- `getDefaultScopes(): array`
- `mapToSocialUser(array $profile, array $tokenData): SocialUserInterface`

Then register with `GhostAuthManager::registerProvider()`. Zero other changes needed.

### 7. PSR compliance
- Cache: always `Psr\SimpleCache\CacheInterface` (PSR-16)
- Logger: always `Psr\Log\LoggerInterface` (PSR-3)
- Default logger: `new NullLogger()` — never `null`

---

## What NOT to Do

- ❌ Do not add framework-specific code (no Laravel facades, no Symfony DI annotations)
- ❌ Do not add database drivers or ORM code — the app provides `UserProviderInterface`
- ❌ Do not store secrets in code — always accept via constructor/config from env
- ❌ Do not use `echo`, `var_dump`, or `print_r` in library code — use the PSR-3 logger
- ❌ Do not modify `Contracts/` interfaces without a major version bump
- ❌ Do not use `rand()`, `mt_rand()`, `uniqid()`, `microtime()` for security tokens

---

## Testing Guidance

- Each provider should be unit-testable with mocked `UserProviderInterface` and `TokenIssuerInterface`
- `AuthResult` is a value object — test all three factory paths (`success`, `failure`, `pending`)
- `JwtIssuer`: test sign/verify round-trip, expired token rejection, revoked jti rejection
- `OtpProvider`: test send→verify happy path, wrong OTP, max attempts exceeded, expired OTP
- `RateLimitingAware`: test window reset, limit enforcement, remaining count

---

## Security Checklist (before any PR)

- [ ] No plaintext secrets logged or stored
- [ ] No `rand()` / `uniqid()` for cryptographic use
- [ ] `hash_equals()` used for all secret comparisons
- [ ] Auth failures return `AuthResult::failure()`, not thrown exceptions
- [ ] New providers implement `isEnabled()` guard
- [ ] New cache keys use a `ghostauth:` prefix namespace
