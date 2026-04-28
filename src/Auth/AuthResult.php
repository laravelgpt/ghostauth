<?php

declare(strict_types=1);

namespace GhostAuth\Auth;

use GhostAuth\Contracts\AuthResultInterface;
use GhostAuth\Contracts\AuthenticatableInterface;

/**
 * AuthResult
 *
 * Concrete, immutable value object implementing AuthResultInterface.
 * Use the static factory methods for clean construction:
 *
 *   AuthResult::success($user, $token)
 *   AuthResult::failure('INVALID_CREDENTIALS', 'Email or password is incorrect.')
 *   AuthResult::pending(['expires_in' => 300])  // OTP sent, awaiting verification
 *
 * @package GhostAuth\Auth
 */
final class AuthResult implements AuthResultInterface
{
    /**
     * @param bool                         $success
     * @param AuthenticatableInterface|null $user
     * @param string|null                  $token
     * @param string|null                  $errorCode
     * @param string|null                  $errorMessage
     * @param array<string, mixed>         $meta
     */
    private function __construct(
        private readonly bool $success,
        private readonly ?AuthenticatableInterface $user,
        private readonly ?string $token,
        private readonly ?string $errorCode,
        private readonly ?string $errorMessage,
        private readonly array $meta,
    ) {}

    // -------------------------------------------------------------------------
    // Static factory methods
    // -------------------------------------------------------------------------

    /**
     * Create a successful authentication result.
     *
     * @param  AuthenticatableInterface $user   The authenticated user.
     * @param  string                   $token  Issued token (JWT or session ID).
     * @param  array<string, mixed>     $meta   Optional extra metadata.
     */
    public static function success(
        AuthenticatableInterface $user,
        string $token,
        array $meta = [],
    ): self {
        return new self(
            success: true,
            user: $user,
            token: $token,
            errorCode: null,
            errorMessage: null,
            meta: $meta,
        );
    }

    /**
     * Create a failed authentication result.
     *
     * @param  string               $errorCode     Machine-readable code (e.g. 'OTP_EXPIRED').
     * @param  string               $errorMessage  Human-readable description.
     * @param  array<string, mixed> $meta          Optional extra metadata.
     */
    public static function failure(
        string $errorCode,
        string $errorMessage,
        array $meta = [],
    ): self {
        return new self(
            success: false,
            user: null,
            token: null,
            errorCode: $errorCode,
            errorMessage: $errorMessage,
            meta: $meta,
        );
    }

    /**
     * Create a "pending" result — used when an OTP has been sent and
     * the client must submit a second request with the code.
     * Not a failure, but not a fully authenticated session either.
     *
     * @param  array<string, mixed> $meta  Metadata (e.g. ['channel' => 'email', 'expires_in' => 300])
     */
    public static function pending(array $meta = []): self
    {
        return new self(
            success: false,
            user: null,
            token: null,
            errorCode: 'OTP_SENT',
            errorMessage: 'OTP dispatched. Awaiting verification.',
            meta: $meta,
        );
    }

    // -------------------------------------------------------------------------
    // AuthResultInterface implementation
    // -------------------------------------------------------------------------

    public function isSuccess(): bool
    {
        return $this->success;
    }

    public function getUser(): ?AuthenticatableInterface
    {
        return $this->user;
    }

    public function getToken(): ?string
    {
        return $this->token;
    }

    public function getErrorCode(): ?string
    {
        return $this->errorCode;
    }

    public function getErrorMessage(): ?string
    {
        return $this->errorMessage;
    }

    public function getMeta(): array
    {
        return $this->meta;
    }
}
