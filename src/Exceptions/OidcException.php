<?php

declare(strict_types=1);

namespace GhostAuth\Exceptions;

/** Thrown on OIDC/SSO discovery, token validation, or nonce mismatch failures. */
class OidcException extends GhostAuthException {}
