<?php

declare(strict_types=1);

namespace GhostAuth\Contracts;

/**
 * OtpSenderInterface
 *
 * Abstracts OTP delivery so the OtpProvider is decoupled from the
 * transport mechanism (email, SMS, WhatsApp, push, etc.).
 *
 * The consuming application provides its own implementation backed
 * by its mailer/SMS gateway of choice (Mailgun, Twilio, SNS, etc.).
 *
 * @package GhostAuth\Contracts
 */
interface OtpSenderInterface
{
    /**
     * Dispatch the OTP to the given recipient.
     *
     * @param  string $recipient  Email address OR E.164 phone number.
     * @param  string $otp        The plaintext OTP (6-digit numeric string recommended).
     * @param  string $channel    Delivery channel: 'email' | 'sms' | 'whatsapp'
     * @return bool               True if dispatch was accepted (not necessarily delivered).
     *
     * @throws \GhostAuth\Exceptions\OtpDeliveryException  On fatal dispatch failure.
     */
    public function send(string $recipient, string $otp, string $channel = 'email'): bool;
}
