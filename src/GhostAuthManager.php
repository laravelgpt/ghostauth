<?php

declare(strict_types=1);

namespace GhostAuth;

use GhostAuth\Contracts\AuthResultInterface;
use GhostAuth\Contracts\AuthenticationProviderInterface;
use GhostAuth\Contracts\TokenIssuerInterface;
use GhostAuth\Exceptions\GhostAuthException;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * GhostAuthManager
 *
 * The single entry point for all authentication operations in GhostAuth.
 * Acts as a Strategy registry and dispatcher — it holds a map of named
 * providers and routes authenticate() calls to the correct one.
 *
 * Design goals:
 *   - Framework-agnostic: no dependency on Laravel, Symfony, Slim, etc.
 *   - Easily wired via any DI container or constructed manually.
 *   - Extensible: add any custom provider by calling registerProvider().
 *
 * Typical usage:
 * ┌─────────────────────────────────────────────────────────┐
 * │  $manager = new GhostAuthManager(logger: $logger);      │
 * │  $manager->registerProvider($emailPasswordProvider);    │
 * │  $manager->registerProvider($otpProvider);              │
 * │                                                         │
 * │  $result = $manager->authenticate(                      │
 * │      provider: 'email_password',                        │
 * │      credentials: ['email' => ..., 'password' => ...]   │
 * │  );                                                     │
 * └─────────────────────────────────────────────────────────┘
 *
 * @package GhostAuth
 */
final class GhostAuthManager
{
    /**
     * Registered authentication strategy providers.
     * Keys are provider names (from AuthenticationProviderInterface::getProviderName()).
     *
     * @var array<string, AuthenticationProviderInterface>
     */
    private array $providers = [];

    /**
     * Optional default provider name — used when authenticate() is called
     * without specifying a provider.
     */
    private ?string $defaultProvider = null;

    /**
     * @param LoggerInterface       $logger           PSR-3 logger.
     * @param TokenIssuerInterface|null $tokenIssuer  Optional shared token issuer for convenience.
     */
    public function __construct(
        private readonly LoggerInterface $logger = new NullLogger(),
        private readonly ?TokenIssuerInterface $tokenIssuer = null,
    ) {}

    // -------------------------------------------------------------------------
    // Provider registry
    // -------------------------------------------------------------------------

    /**
     * Register an authentication provider with the manager.
     * Providers are keyed by their getProviderName() value.
     *
     * @param  AuthenticationProviderInterface $provider    The provider to register.
     * @param  bool                            $setDefault  If true, also set as the default provider.
     * @return static  Fluent — allows chaining: $manager->register($a)->register($b)
     */
    public function registerProvider(
        AuthenticationProviderInterface $provider,
        bool $setDefault = false,
    ): static {
        $name = $provider->getProviderName();

        $this->providers[$name] = $provider;

        if ($setDefault) {
            $this->defaultProvider = $name;
        }

        $this->logger->debug("GhostAuthManager: registered provider '{$name}'", [
            'enabled' => $provider->isEnabled(),
        ]);

        return $this;
    }

    /**
     * Retrieve a registered provider by name.
     *
     * @param  string $name  The provider name (e.g. 'email_password', 'otp').
     * @return AuthenticationProviderInterface
     * @throws GhostAuthException  If no provider is registered under that name.
     */
    public function getProvider(string $name): AuthenticationProviderInterface
    {
        if (! isset($this->providers[$name])) {
            throw new GhostAuthException(
                "GhostAuthManager: no provider registered with name '{$name}'. "
                . "Registered providers: [" . implode(', ', array_keys($this->providers)) . ']'
            );
        }

        return $this->providers[$name];
    }

    /**
     * Return all registered providers.
     *
     * @return array<string, AuthenticationProviderInterface>
     */
    public function getProviders(): array
    {
        return $this->providers;
    }

    /**
     * Set the default provider name used when authenticate() is called without one.
     *
     * @throws GhostAuthException  If the named provider is not yet registered.
     */
    public function setDefaultProvider(string $name): static
    {
        if (! isset($this->providers[$name])) {
            throw new GhostAuthException(
                "GhostAuthManager: cannot set default — provider '{$name}' is not registered."
            );
        }

        $this->defaultProvider = $name;

        return $this;
    }

    // -------------------------------------------------------------------------
    // Core authentication dispatch
    // -------------------------------------------------------------------------

    /**
     * Authenticate using the named provider.
     *
     * If $provider is null, the default provider is used.
     * If no default is configured, throws GhostAuthException.
     *
     * @param  array<string, mixed> $credentials  Provider-specific credential map.
     * @param  string|null          $provider     Provider name, or null to use default.
     * @return AuthResultInterface                Structured result — inspect isSuccess().
     *
     * @throws GhostAuthException  On misconfiguration or infrastructure errors.
     */
    public function authenticate(array $credentials, ?string $provider = null): AuthResultInterface
    {
        $providerName = $provider ?? $this->defaultProvider;

        if ($providerName === null) {
            throw new GhostAuthException(
                'GhostAuthManager: no provider specified and no default provider is configured.'
            );
        }

        $providerInstance = $this->getProvider($providerName);

        if (! $providerInstance->isEnabled()) {
            throw new GhostAuthException(
                "GhostAuthManager: provider '{$providerName}' is registered but currently disabled."
            );
        }

        $this->logger->info("GhostAuthManager: dispatching authenticate → '{$providerName}'");

        $result = $providerInstance->authenticate($credentials);

        if ($result->isSuccess()) {
            $this->logger->info("GhostAuthManager: authentication succeeded via '{$providerName}'", [
                'user_id' => $result->getUser()?->getAuthIdentifier(),
            ]);
        } else {
            $this->logger->warning("GhostAuthManager: authentication failed via '{$providerName}'", [
                'error_code' => $result->getErrorCode(),
            ]);
        }

        return $result;
    }

    // -------------------------------------------------------------------------
    // Token management (convenience delegation to TokenIssuerInterface)
    // -------------------------------------------------------------------------

    /**
     * Verify a previously issued token using the configured TokenIssuer.
     *
     * @param  string $token  Raw token string.
     * @return array<string, mixed>  Decoded payload.
     *
     * @throws GhostAuthException  If no TokenIssuer is configured.
     * @throws \GhostAuth\Exceptions\TokenException  On invalid/expired token.
     */
    public function verifyToken(string $token): array
    {
        $this->guardTokenIssuer();

        return $this->tokenIssuer->verify($token);
    }

    /**
     * Revoke a previously issued token.
     *
     * @param  string $token  Raw token string.
     * @return bool           True if successfully revoked.
     *
     * @throws GhostAuthException  If no TokenIssuer is configured.
     */
    public function revokeToken(string $token): bool
    {
        $this->guardTokenIssuer();

        $revoked = $this->tokenIssuer->revoke($token);

        $this->logger->info('GhostAuthManager: token revocation', [
            'success' => $revoked,
        ]);

        return $revoked;
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * @throws GhostAuthException
     */
    private function guardTokenIssuer(): void
    {
        if ($this->tokenIssuer === null) {
            throw new GhostAuthException(
                'GhostAuthManager: no TokenIssuer configured. '
                . 'Pass a TokenIssuerInterface to the constructor.'
            );
        }
    }
}
