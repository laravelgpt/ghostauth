<?php

declare(strict_types=1);

namespace GhostAuth\Exceptions;

/** Thrown when an OTP cannot be dispatched to its transport (email/SMS). */
class OtpDeliveryException extends GhostAuthException {}
