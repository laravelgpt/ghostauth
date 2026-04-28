<?php

declare(strict_types=1);

namespace GhostAuth\Exceptions;

/**
 * GhostAuthException
 *
 * Base exception for all GhostAuth errors.
 * Infrastructure/config errors throw this (or a subclass).
 * Normal authentication failures are returned as AuthResult objects — not thrown.
 *
 * @package GhostAuth\Exceptions
 */
class GhostAuthException extends \RuntimeException {}
