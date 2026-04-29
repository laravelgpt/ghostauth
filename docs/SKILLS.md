# SKILLS.md — GhostAuth v1

> Quick-reference skill cards for common development tasks on this package.

---

## 🔐 Skill: Add a New Authentication Provider

**When:** You need a new auth method (magic link, SAML, WebAuthn, passkey, etc.)

**Steps:**

1. Create `src/Providers/YourProvider.php`
2. Implement `AuthenticationProviderInterface`

```php
final class MagicLinkProvider implements AuthenticationProviderInterface
{
    public function authenticate(array $credentials): AuthResultInterface
    {
        // credentials: ['email'] for send, ['email', 'token'] for verify
    }

    public function getProviderName(): string { return 'magic_link'; }
    public function isEnabled(): bool         { return $this->enabled; }
}
```

3. Register with the manager:

```php
$auth->registerProvider(new MagicLinkProvider(...));
```

4. Call it:

```php
$auth->authenticate(['email' => 'alice@example.com'], 'magic_link');
```

---

## 🌐 Skill: Add a New Social / OAuth Provider

**When:** You need Facebook, LinkedIn, Apple, Twitter/X, etc.

**Steps:**

1. Extend `AbstractSocialProvider`
2. Implement 5 methods:

```php
final class FacebookProvider extends AbstractSocialProvider
{
    public function getProviderName(): string      { return 'facebook'; }
    protected function getAuthorizationEndpoint(): string { return 'https://www.facebook.com/v18.0/dialog/oauth'; }
    protected function getTokenEndpoint(): string         { return 'https://graph.facebook.com/v18.0/oauth/access_token'; }
    protected function getUserinfoEndpoint(): string      { return 'https://graph.facebook.com/me?fields=id,name,email,picture'; }
    protected function getDefaultScopes(): array          { return ['email', 'public_profile']; }

    protected function mapToSocialUser(array $profile, array $tokenData): SocialUserInterface
    {
        return new SocialUser(
            providerId:   (string) $profile['id'],
            providerName: 'facebook',
            name:         $profile['name']            ?? null,
            email:        $profile['email']           ?? null,
            avatar:       $profile['picture']['data']['url'] ?? null,
            accessToken:  $tokenData['access_token'],
            refreshToken: null,
            raw:          $profile,
        );
    }
}
```

---

## 🔑 Skill: Switch from HS256 to RS256 JWT

**When:** You want resource servers to verify tokens without the signing secret.

**Steps:**

1. Generate RSA key pair:

```bash
openssl genrsa -out private.pem 4096
openssl rsa -in private.pem -pubout -out public.pem
```

2. Update `JwtIssuer` constructor:

```php
$jwtIssuer = new JwtIssuer(
    algorithm:          JwtIssuer::ALGO_RS256,
    privateKeyOrSecret: file_get_contents('/secrets/private.pem'),
    publicKey:          file_get_contents('/secrets/public.pem'),
    issuer:             'https://myapp.com',
    audience:           'https://api.myapp.com',
);
```

3. Share `public.pem` with resource servers — they can verify tokens without the private key.

---

## 🛡️ Skill: Enable Rate Limiting on a Provider

**When:** You want to throttle OTP sends or failed logins at the application layer.

**Steps:**

1. Use the `RateLimitingAware` trait in your controller/middleware:

```php
class AuthController
{
    use RateLimitingAware;

    public function login(Request $request): Response
    {
        $this->initRateLimit($this->cache, 'login', maxAttempts: 5, decaySeconds: 60);

        if ($this->isRateLimited($request->ip())) {
            return response()->json(['error' => 'Too many attempts'], 429)
                ->header('Retry-After', '60');
        }

        $result = $this->auth->authenticate($request->only('email', 'password'));

        if ($result->isSuccess()) {
            $this->clearRateLimit($request->ip()); // reset on success
        }

        return response()->json($result);
    }
}
```

---

## 🔄 Skill: Implement UserProviderInterface with Eloquent

**When:** You're integrating GhostAuth into a Laravel application.

```php
use GhostAuth\Contracts\UserProviderInterface;
use GhostAuth\Contracts\AuthenticatableInterface;

class EloquentUserProvider implements UserProviderInterface
{
    public function findByEmail(string $email): ?AuthenticatableInterface
    {
        return User::whereEmail(strtolower($email))->first();
    }

    public function findByPhone(string $phone): ?AuthenticatableInterface
    {
        return User::wherePhone($phone)->first();
    }

    public function findById(int|string $id): ?AuthenticatableInterface
    {
        return User::find($id);
    }

    public function create(array $attributes): AuthenticatableInterface
    {
        return User::create($attributes);
    }

    public function update(int|string $id, array $attributes): bool
    {
        return (bool) User::whereId($id)->update($attributes);
    }
}
```

Your `User` model also implements `AuthenticatableInterface`:

```php
class User extends Model implements AuthenticatableInterface
{
    public function getAuthIdentifier(): int|string { return $this->id; }
    public function getAuthIdentifierName(): string { return 'id'; }
    public function getAuthPassword(): ?string      { return $this->password; }
    public function getEmail(): ?string             { return $this->email; }
    public function getPhone(): ?string             { return $this->phone; }
    public function getJwtClaims(): array           { return ['role' => $this->role]; }
}
```

---

## 📦 Skill: Implement OtpSenderInterface with Mailgun

**When:** You need to deliver OTP codes via email in production.

```php
use GhostAuth\Contracts\OtpSenderInterface;
use Mailgun\Mailgun;

class MailgunOtpSender implements OtpSenderInterface
{
    public function __construct(
        private readonly Mailgun $mailgun,
        private readonly string  $domain,
        private readonly string  $from,
    ) {}

    public function send(string $recipient, string $otp, string $channel = 'email'): bool
    {
        if ($channel !== 'email') {
            throw new \InvalidArgumentException("MailgunOtpSender only supports email channel.");
        }

        $this->mailgun->messages()->send($this->domain, [
            'from'    => $this->from,
            'to'      => $recipient,
            'subject' => 'Your verification code',
            'text'    => "Your code is: {$otp}\n\nExpires in 5 minutes. Do not share it.",
        ]);

        return true;
    }
}
```

---

## 🗃️ Skill: Enable JWT Token Revocation (Logout)

**When:** You want `revokeToken()` to actually invalidate JWTs before they expire.

**Steps:**

1. Pass a PSR-16 cache to `JwtIssuer`:

```php
// Using symfony/cache Redis adapter
$cache = new \Symfony\Component\Cache\Psr16Cache(
    new \Symfony\Component\Cache\Adapter\RedisAdapter($redis)
);

$jwtIssuer = new JwtIssuer(
    // ...
    denylistCache: $cache,
);
```

2. On logout, call:

```php
$auth->revokeToken($token); // adds jti → cache for remaining TTL
```

3. Every subsequent `verifyToken()` call checks the denylist automatically.

---

## 🧪 Skill: Write a Unit Test for a Provider

```php
use PHPUnit\Framework\TestCase;
use GhostAuth\Providers\EmailPasswordProvider;

class EmailPasswordProviderTest extends TestCase
{
    public function test_successful_login(): void
    {
        $userProvider  = $this->createMock(UserProviderInterface::class);
        $tokenIssuer   = $this->createMock(TokenIssuerInterface::class);
        $provider      = new EmailPasswordProvider($userProvider, $tokenIssuer);

        $hash = $provider->hashPassword('secret');
        $user = $this->createMock(AuthenticatableInterface::class);
        $user->method('getAuthPassword')->willReturn($hash);
        $user->method('getAuthIdentifier')->willReturn(1);

        $userProvider->method('findByEmail')->willReturn($user);
        $tokenIssuer->method('issue')->willReturn('jwt.token.here');

        $result = $provider->authenticate(['email' => 'test@test.com', 'password' => 'secret']);

        $this->assertTrue($result->isSuccess());
        $this->assertSame('jwt.token.here', $result->getToken());
    }

    public function test_wrong_password_returns_failure(): void
    {
        // ... similar setup with wrong password
        $result = $provider->authenticate(['email' => 'test@test.com', 'password' => 'wrong']);
        $this->assertFalse($result->isSuccess());
        $this->assertSame('INVALID_CREDENTIALS', $result->getErrorCode());
    }
}
```
