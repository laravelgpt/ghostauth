<?php

declare(strict_types=1);

namespace GhostAuth\Mfa;

/**
 * WebAuthnAuthenticator (v1)
 *
 * Passkey / WebAuthn implementation for passwordless MFA.
 * Supports:
 *   - Registration (credential creation)
 *   - Authentication (assertion verification)
 *   - ECDSA P-256 (ES256) signature verification
 *   - EdDSA (Ed25519) signature verification
 *   - Resident credentials (discoverable / passkey flow)
 *
 * NOTE: This is a simplified implementation. For production use,
 * prefer `web-auth/webauthn-lib` for full attestation, extensions,
 * and platform authenticator support.
 *
 * @package GhostAuth\Mfa
 */
class WebAuthnAuthenticator
{
    public const  CHALLENGE_BYTES = 32;
    public const  CHALLENGE_TTL   = 300; // 5 minutes

    // =========================================================================
    // Registration (Credential Creation)
    // =========================================================================

    /**
     * Generate a registration challenge for a new credential.
     *
     * @param  mixed  $userId       The user's unique identifier.
     * @param  string $username     The user's username/email.
     * @param  string $displayName  The user's display name.
     * @return array{
     *     challenge: string,        // Base64URL challenge for the browser
     *     user_id: string,          // Base64URL user ID
     *     user_name: string,        // Username for display
     *     user_display_name: string,// Display name
     *     rp_id: string,            // Relying party ID (domain)
     *     rp_name: string,          // Relying party name
     *     timeout: int,             // Suggested timeout in ms
     *     algorithms: array,        // Supported public key algorithms
     *     raw_challenge: string,    // Raw bytes (keep server-side for verification)
     * }
     */
    public static function createRegistrationChallenge(
        mixed $userId,
        string $username,
        string $displayName,
        string $rpId,
        string $rpName,
    ): array {
        $challenge = random_bytes(self::CHALLENGE_BYTES);

        return [
            'challenge'       => self::base64UrlEncode($challenge),
            'user_id'         => self::base64UrlEncode((string) $userId),
            'user_name'       => $username,
            'user_display_name' => $displayName,
            'rp_id'           => $rpId,
            'rp_name'         => $rpName,
            'timeout'         => 60000,
            'algorithms'      => [
                ['type' => 'public-key', 'alg' => -7],   // ES256
                ['type' => 'public-key', 'alg' => -8],   // EdDSA
            ],
            'raw_challenge'   => $challenge,
        ];
    }

    /**
     * Verify and store a new credential from browser registration response.
     *
     * @param  array<string, mixed> $clientDataJson  Decoded clientDataJSON from navigator.credentials.create().
     * @param  array<string, mixed> $attestationObj  Decoded AttestationObject (CBOR).
     * @param  string               $rawChallenge    The raw challenge bytes from createRegistrationChallenge().
     * @param  string               $origin          Expected origin (e.g. 'https://myapp.com').
     * @param  string               $rpId            Expected relying party ID.
     * @return array{
     *     credential_id: string,   // Base64URL credential ID
     *     public_key: string,      // PEM-encoded public key
     *     alg: int,                // COSE algorithm ID
     *     counter: int,            // Initial signature counter
     * }
     *
     * @throws \RuntimeException  On verification failure.
     */
    public static function verifyRegistration(
        array $clientDataJson,
        array $attestationObj,
        string $rawChallenge,
        string $origin,
        string $rpId,
    ): array {
        // ── 1. Validate clientDataJSON ───────────────────────────────────────
        if (($clientDataJson['type'] ?? '') !== 'webauthn.create') {
            throw new \RuntimeException('Invalid clientDataJSON type.');
        }

        if (! isset($clientDataJson['challenge'])) {
            throw new \RuntimeException('Missing challenge in clientDataJSON.');
        }

        $providedChallenge = self::base64UrlDecode($clientDataJson['challenge']);

        if ($providedChallenge !== $rawChallenge) {
            throw new \RuntimeException('Challenge mismatch in registration.');
        }

        if (($clientDataJson['origin'] ?? '') !== $origin) {
            throw new \RuntimeException('Origin mismatch in registration.');
        }

        // ── 2. Extract authData from attestation object ──────────────────────
        $authData = $attestationObj['authData'] ?? '';

        if (strlen($authData) < 37) {
            throw new \RuntimeException('Invalid authData length.');
        }

        // ── 3. Verify RP ID hash ────────────────────────────────────────────
        $rpIdHash = substr($authData, 0, 32);
        $expectedRpHash = hash('sha256', $rpId, binary: true);

        if ($rpIdHash !== $expectedRpHash) {
            throw new \RuntimeException('RP ID hash mismatch.');
        }

        // ── 4. Check flags ──────────────────────────────────────────────────
        $flags = ord($authData[32]);
        $userPresent = ($flags & 0x01) !== 0;
        $userVerified = ($flags & 0x04) !== 0;
        $hasAttestedCred = ($flags & 0x40) !== 0;

        if (! $userPresent) {
            throw new \RuntimeException('User was not present during registration.');
        }

        if (! $hasAttestedCred) {
            throw new \RuntimeException('No attested credential data found.');
        }

        // ── 5. Parse attested credential data ───────────────────────────────
        $offset = 37;

        // AAGUID (16 bytes)
        $aaguid = substr($authData, $offset, 16);
        $offset += 16;

        // Credential ID length (2 bytes, big-endian)
        $credIdLen = (ord($authData[$offset]) << 8) | ord($authData[$offset + 1]);
        $offset += 2;

        // Credential ID
        $credentialId = substr($authData, $offset, $credIdLen);
        $offset += $credIdLen;

        // ── 6. Parse COSE key (credential public key) ───────────────────────
        $coseKeyData = substr($authData, $offset);
        $coseKey = self::decodeCbor($coseKeyData);

        $alg = $coseKey[3] ?? null;
        $kty = $coseKey[1] ?? null;

        // ── 7. Extract and convert to PEM public key ────────────────────────
        $publicKey = self::coseToPem($coseKey, $alg);

        return [
            'credential_id' => self::base64UrlEncode($credentialId),
            'public_key'    => $publicKey,
            'alg'           => $alg,
            'counter'       => 0,
        ];
    }

    // =========================================================================
    // Authentication (Assertion Verification)
    // =========================================================================

    /**
     * Generate an authentication challenge.
     *
     * @param  string $rpId  Relying party ID (domain).
     * @return array{challenge: string, rp_id: string, timeout: int, raw_challenge: string}
     */
    public static function createAuthenticationChallenge(string $rpId): array
    {
        $challenge = random_bytes(self::CHALLENGE_BYTES);

        return [
            'challenge'     => self::base64UrlEncode($challenge),
            'rp_id'         => $rpId,
            'timeout'       => 60000,
            'raw_challenge' => $challenge,
        ];
    }

    /**
     * Verify an authentication assertion from navigator.credentials.get().
     *
     * @param  array<string, mixed> $clientDataJson   Decoded clientDataJSON.
     * @param  array<string, mixed> $authenticatorData Decoded authenticatorData.
     * @param  string               $signature         Raw signature bytes (base64url decoded).
     * @param  string               $rawChallenge      Raw challenge from createAuthenticationChallenge().
     * @param  string               $publicKeyPem      PEM public key stored during registration.
     * @param  int                  $alg               COSE algorithm ID (-7 for ES256, -8 for EdDSA).
     * @param  string               $origin            Expected origin.
     * @param  string               $rpId              Expected relying party ID.
     * @return array{
     *     verified: bool,
     *     counter: int,
     *     user_present: bool,
     *     user_verified: bool,
     * }
     *
     * @throws \RuntimeException  On verification failure.
     */
    public static function verifyAuthentication(
        array $clientDataJson,
        array $authenticatorData,
        string $signature,
        string $rawChallenge,
        string $publicKeyPem,
        int $alg,
        string $origin,
        string $rpId,
    ): array {
        // ── 1. Validate clientDataJSON ───────────────────────────────────────
        if (($clientDataJson['type'] ?? '') !== 'webauthn.get') {
            throw new \RuntimeException('Invalid clientDataJSON type for authentication.');
        }

        $providedChallenge = self::base64UrlDecode($clientDataJson['challenge'] ?? '');

        if ($providedChallenge !== $rawChallenge) {
            throw new \RuntimeException('Challenge mismatch in authentication.');
        }

        if (($clientDataJson['origin'] ?? '') !== $origin) {
            throw new \RuntimeException('Origin mismatch in authentication.');
        }

        // ── 2. Verify RP ID hash in authenticator data ──────────────────────
        $authDataBytes = $authenticatorData['raw'] ?? '';

        if (strlen($authDataBytes) < 37) {
            throw new \RuntimeException('Invalid authenticatorData length.');
        }

        $rpIdHash = substr($authDataBytes, 0, 32);
        $expectedRpHash = hash('sha256', $rpId, binary: true);

        if ($rpIdHash !== $expectedRpHash) {
            throw new \RuntimeException('RP ID hash mismatch during authentication.');
        }

        // ── 3. Check flags ──────────────────────────────────────────────────
        $flags = ord($authDataBytes[32]);
        $userPresent = ($flags & 0x01) !== 0;
        $userVerified = ($flags & 0x04) !== 0;

        if (! $userPresent) {
            throw new \RuntimeException('User not present during authentication.');
        }

        // ── 4. Extract signature counter ────────────────────────────────────
        $counterBytes = substr($authDataBytes, 33, 4);
        $counter = unpack('N', $counterBytes)[1];

        // ── 5. Build the signed message ─────────────────────────────────────
        // The browser signed: authenticatorData || SHA256(clientDataJSON)
        $clientDataHash = hash('sha256', $clientDataJson['raw'] ?? '', binary: true);
        $signedData = $authDataBytes . $clientDataHash;

        // ── 6. Verify signature ─────────────────────────────────────────────
        $verified = self::verifySignature($signedData, $signature, $publicKeyPem, $alg);

        if (! $verified) {
            throw new \RuntimeException('Signature verification failed.');
        }

        return [
            'verified'      => true,
            'counter'       => $counter,
            'user_present'  => $userPresent,
            'user_verified' => $userVerified,
        ];
    }

    // =========================================================================
    // Signature verification
    // =========================================================================

    /**
     * Verify a WebAuthn signature against a public key.
     * Supports ES256 (ECDSA P-256) and EdDSA (Ed25519).
     */
    private static function verifySignature(
        string $data,
        string $signature,
        string $publicKeyPem,
        int $alg,
    ): bool {
        return match ($alg) {
            -7 => self::verifyEs256($data, $signature, $publicKeyPem),    // ECDSA P-256
            -8 => self::verifyEdDSA($data, $signature, $publicKeyPem),     // Ed25519
            default => throw new \RuntimeException("Unsupported algorithm: $alg"),
        };
    }

    /**
     * Verify ES256 (ECDSA with SHA-256) signature.
     * WebAuthn returns raw r||s format; openssl expects ASN.1 DER.
     */
    private static function verifyEs256(string $data, string $signature, string $publicKeyPem): bool
    {
        // Convert raw r||s (64 bytes) to ASN.1 DER format
        if (strlen($signature) !== 64) {
            return false;
        }

        $r = ltrim(substr($signature, 0, 32), "\x00");
        $s = ltrim(substr($signature, 32, 32), "\x00");

        // Ensure positive integers (add 0x00 if high bit set)
        if (ord($r[0] ?? '') & 0x80) $r = "\x00" . $r;
        if (ord($s[0] ?? '') & 0x80) $s = "\x00" . $s;

        $asnR = "\x02" . chr(strlen($r)) . $r;
        $asnS = "\x02" . chr(strlen($s)) . $s;
        $derSignature = "\x30" . chr(strlen($asnR) + strlen($asnS)) . $asnR . $asnS;

        return (bool) openssl_verify(
            $data,
            $derSignature,
            $publicKeyPem,
            OPENSSL_ALGO_SHA256,
        );
    }

    /**
     * Verify EdDSA (Ed25519) signature.
     * Requires PHP 8.2+ with libsodium.
     */
    private static function verifyEdDSA(string $data, string $signature, string $publicKeyPem): bool
    {
        if (strlen($signature) !== 64) {
            return false;
        }

        // Extract raw Ed25519 public key from PEM
        $lines = array_filter(explode("\n", $publicKeyPem));
        $b64 = '';
        $inKey = false;

        foreach ($lines as $line) {
            if (str_contains($line, 'BEGIN')) { $inKey = true; continue; }
            if (str_contains($line, 'END')) break;
            if ($inKey) $b64 .= trim($line);
        }

        $rawKey = base64_decode($b64);

        // Ed25519 public key is the last 32 bytes of the DER structure
        // (or 32 bytes raw if already in raw format)
        if (strlen($rawKey) === 32) {
            $pubKey = $rawKey;
        } elseif (strlen($rawKey) === 44) {
            // DER-wrapped: skip 12-byte prefix
            $pubKey = substr($rawKey, 12);
        } else {
            return false;
        }

        return sodium_crypto_sign_verify_detached($signature, $data, $pubKey);
    }

    // =========================================================================
    // COSE Key conversion
    // =========================================================================

    /**
     * Convert a COSE key to PEM-encoded public key.
     * Supports EC2 (P-256) and OKP (Ed25519).
     */
    private static function coseToPem(array $coseKey, ?int $alg): string
    {
        $kty = $coseKey[1] ?? null; // Key type

        return match ($kty) {
            2  => self::ec2ToPem($coseKey, $alg),    // EC2 (ECDSA)
            1  => self::okpToPem($coseKey, $alg),    // OKP (EdDSA)
            default => throw new \RuntimeException("Unsupported COSE key type: $kty"),
        };
    }

    /**
     * Convert EC2 (ECDSA) COSE key to PEM.
     * COSE key -2: x coordinate (32 bytes), -3: y coordinate (32 bytes)
     */
    private static function ec2ToPem(array $coseKey, ?int $alg): string
    {
        $x = $coseKey[-2] ?? '';
        $y = $coseKey[-3] ?? '';

        if (is_string($x) && strlen($x) < 32) $x = str_pad($x, 32, "\x00", STR_PAD_LEFT);
        if (is_string($y) && strlen($y) < 32) $y = str_pad($y, 32, "\x00", STR_PAD_LEFT);

        // Uncompressed EC point: 0x04 || x || y
        $uncompressedPoint = "\x04" . $x . $y;

        // Build DER SubjectPublicKeyInfo for P-256
        $oidP256 = hex2bin('06082a8648ce3d030107'); // OID for prime256v1
        $innerLen = strlen($oidP256) + 2;
        $algorithmIdentifier = "\x30" . chr($innerLen) . $oidP256;

        $pointLen = strlen($uncompressedPoint);
        $bitString = "\x03" . chr($pointLen + 1) . "\x00" . $uncompressedPoint;

        $spkiInner = $algorithmIdentifier . $bitString;
        $spki = "\x30" . chr(strlen($spkiInner)) . $spkiInner;

        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($spki), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
    }

    /**
     * Convert OKP (Ed25519) COSE key to PEM.
     * COSE key -1: curve ID (6 = Ed25519), -2: x coordinate (32 bytes)
     */
    private static function okpToPem(array $coseKey, ?int $alg): string
    {
        $x = $coseKey[-2] ?? '';

        if (is_string($x) && strlen($x) < 32) {
            $x = str_pad($x, 32, "\x00", STR_PAD_LEFT);
        }

        // OID for Ed25519: 1.3.101.112
        $oidEd25519 = hex2bin('06032b6570');
        $algoId = "\x30\x05" . $oidEd25519;

        $pointLen = strlen($x) + 1;
        $bitString = "\x03" . chr($pointLen) . "\x00" . $x;

        $spkiInner = $algoId . $bitString;
        $spki = "\x30" . chr(strlen($spkiInner)) . $spkiInner;

        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($spki), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
    }

    // =========================================================================
    // Simplified CBOR decoder (subset for WebAuthn credential data)
    // =========================================================================

    /**
     * Minimal CBOR decoder — handles the subset needed for WebAuthn authData.
     * Supports: unsigned ints, byte strings, text strings, arrays, maps.
     *
     * @param  string $data  Raw CBOR bytes.
     * @return mixed         Decoded value.
     */
    private static function decodeCbor(string $data): mixed
    {
        $result = [];
        self::decodeCborValue($data, 0, $result);
        return $result[0];
    }

    private static function decodeCborValue(string $data, int $offset, array &$result): int
    {
        if ($offset >= strlen($data)) {
            $result[0] = null;
            return $offset;
        }

        $byte = ord($data[$offset]);
        $major = ($byte >> 5) & 0x07;
        $additional = $byte & 0x1F;
        $pos = $offset + 1;

        // Determine value / additional bytes
        if ($additional < 24) {
            $value = $additional;
        } elseif ($additional === 24) {
            $value = ord($data[$pos]);
            $pos++;
        } elseif ($additional === 25) {
            $value = unpack('n', substr($data, $pos, 2))[1];
            $pos += 2;
        } elseif ($additional === 26) {
            $value = unpack('N', substr($data, $pos, 4))[1];
            $pos += 4;
        } elseif ($additional === 27) {
            $bytes = substr($data, $pos, 8);
            $value = unpack('J', $bytes)[1];
            $pos += 8;
        } elseif ($additional === 31) {
            throw new \RuntimeException('Indefinite length CBOR not supported');
        }

        return match ($major) {
            0 => $result[0] = $value,                       // unsigned int
            1 => $result[0] = -1 - $value,                   // negative int
            2 => self::decodeBytes($data, $pos, $value, $result),  // byte string
            3 => self::decodeText($data, $pos, $value, $result),   // text string
            4 => self::decodeArray($data, $pos, $value, $result),  // array
            5 => self::decodeMap($data, $pos, $value, $result),    // map
            6 => $result[0] = self::decodeTag($data, $pos, $value, $result), // tag
            7 => self::decodeSimple($data, $pos, $value, $result),     // simple/float
            default => throw new \RuntimeException("Unknown CBOR major type: $major"),
        } === null ? $pos : $pos;
    }

    private static function decodeBytes(string $data, int $pos, int $len, array &$result): int
    {
        $result[0] = substr($data, $pos, $len);
        return $pos + $len;
    }

    private static function decodeText(string $data, int $pos, int $len, array &$result): int
    {
        $result[0] = substr($data, $pos, $len);
        return $pos + $len;
    }

    private static function decodeArray(string $data, int $pos, int $len, array &$result): int
    {
        $arr = [];
        for ($i = 0; $i < $len; $i++) {
            $val = [];
            $pos = self::decodeCborValue($data, $pos, $val);
            $arr[] = $val[0];
        }
        $result[0] = $arr;
        return $pos;
    }

    private static function decodeMap(string $data, int $pos, int $len, array &$result): int
    {
        $map = [];
        for ($i = 0; $i < $len; $i++) {
            $key = [];
            $pos = self::decodeCborValue($data, $pos, $key);
            $val = [];
            $pos = self::decodeCborValue($data, $pos, $val);
            $map[$key[0]] = $val[0];
        }
        $result[0] = $map;
        return $pos;
    }

    private static function decodeTag(string $data, int $pos, int $tag, array &$result): int
    {
        // Tag 24 = embedded CBOR
        if ($tag === 24) {
            $val = [];
            $pos = self::decodeCborValue($data, $pos, $val);
            $result[0] = $val[0];
            return $pos;
        }

        // Tag 64 = base64url, tag 65 = base64 (not used in WebAuthn)
        $val = [];
        $pos = self::decodeCborValue($data, $pos, $val);
        $result[0] = $val[0];
        return $pos;
    }

    private static function decodeSimple(string $data, int $pos, int $value, array &$result): int
    {
        $result[0] = match ($value) {
            20 => false,
            21 => true,
            22 => null,
            23 => null, // undefined
            default => null,
        };
        return $pos;
    }

    // =========================================================================
    // Base64URL helpers
    // =========================================================================

    public static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public static function base64UrlDecode(string $data): string
    {
        return base64_decode(strtr($data, '-_', '+/'));
    }
}
