<?php

/**
 * Value object representing encrypted data.
 *
 * Copyright 2009-2026 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @category  Horde
 * @copyright 2009-2026 Horde LLC
 * @license   http://www.horde.org/licenses/lgpl21 LGPL 2.1
 * @package   Secret
 */

declare(strict_types=1);

namespace Horde\Secret;

use InvalidArgumentException;

/**
 * Immutable value object containing encrypted data with format header.
 *
 * Format: ['H']['S'][version:1byte][payload:*]
 * Where payload is cipher-specific (nonce + ciphertext + tag)
 *
 * @category  Horde
 * @copyright 2009-2026 Horde LLC
 * @license   http://www.horde.org/licenses/lgpl21 LGPL 2.1
 * @package   Secret
 */
final readonly class EncryptedData
{
    /**
     * Magic header identifying Horde Secret format
     */
    private const MAGIC = 'HS';

    /**
     * Complete encrypted data with header.
     *
     * @var string Format: ['H']['S'][version][payload]
     */
    private string $data;

    /**
     * Constructor.
     *
     * @param int    $version Cipher version identifier
     * @param string $payload Raw cipher output (nonce + ciphertext + tag)
     */
    public function __construct(
        private int $version,
        private string $payload
    ) {
        // Validate version is in valid range (0x01-0xFF)
        if ($version < 0x01 || $version > 0xFF) {
            throw new InvalidArgumentException(
                "Version must be between 0x01 and 0xFF, got: 0x" . dechex($version)
            );
        }

        // Build complete format: magic + version + payload
        $this->data = self::MAGIC . chr($version) . $payload;
    }

    /**
     * Create from complete encrypted string (with header).
     *
     * @param string $data Complete encrypted data
     *
     * @return self
     *
     * @throws InvalidArgumentException If format is invalid
     */
    public static function fromString(string $data): self
    {
        if (strlen($data) < 4) {
            throw new InvalidArgumentException(
                'Encrypted data too short (minimum 4 bytes: header + version + payload)'
            );
        }

        // Check magic header
        if (substr($data, 0, 2) !== self::MAGIC) {
            throw new InvalidArgumentException(
                'Invalid format: missing magic header "HS"'
            );
        }

        $version = ord($data[2]);
        $payload = substr($data, 3);

        return new self($version, $payload);
    }

    /**
     * Get the cipher version used.
     *
     * @return int Version byte (0x01-0xFF)
     */
    public function getVersion(): int
    {
        return $this->version;
    }

    /**
     * Get the payload (without header).
     *
     * @return string Raw cipher output
     */
    public function getPayload(): string
    {
        return $this->payload;
    }

    /**
     * Get complete encrypted data as string (with header).
     *
     * @return string Format: ['H']['S'][version][payload]
     */
    public function toString(): string
    {
        return $this->data;
    }

    /**
     * Get Base64-encoded representation.
     *
     * Useful for storing in databases or transmitting as text.
     *
     * @return string Base64-encoded encrypted data
     */
    public function toBase64(): string
    {
        return base64_encode($this->data);
    }

    /**
     * Get Base64URL-encoded representation (URL-safe).
     *
     * Useful for including in URLs or file names.
     *
     * @return string Base64URL-encoded encrypted data
     */
    public function toBase64Url(): string
    {
        return rtrim(strtr(base64_encode($this->data), '+/', '-_'), '=');
    }

    /**
     * Create from Base64-encoded string.
     *
     * @param string $base64 Base64-encoded encrypted data
     *
     * @return self
     *
     * @throws InvalidArgumentException If Base64 decoding fails or format invalid
     */
    public static function fromBase64(string $base64): self
    {
        $decoded = base64_decode($base64, true);
        if ($decoded === false) {
            throw new InvalidArgumentException('Invalid Base64 encoding');
        }

        return self::fromString($decoded);
    }

    /**
     * Create from Base64URL-encoded string.
     *
     * @param string $base64url Base64URL-encoded encrypted data
     *
     * @return self
     *
     * @throws InvalidArgumentException If decoding fails or format invalid
     */
    public static function fromBase64Url(string $base64url): self
    {
        // Add padding and convert to standard Base64
        $base64 = strtr($base64url, '-_', '+/');
        $padding = strlen($base64) % 4;
        if ($padding > 0) {
            $base64 .= str_repeat('=', 4 - $padding);
        }

        return self::fromBase64($base64);
    }

    /**
     * Check if data has the magic header.
     *
     * @param string $data Data to check
     *
     * @return bool True if data starts with "HS" magic header
     */
    public static function hasHeader(string $data): bool
    {
        return strlen($data) >= 2 && substr($data, 0, 2) === self::MAGIC;
    }

    /**
     * Get the data length in bytes.
     *
     * @return int Total length (header + version + payload)
     */
    public function getLength(): int
    {
        return strlen($this->data);
    }

    /**
     * String representation (returns Base64).
     *
     * @return string Base64-encoded data
     */
    public function __toString(): string
    {
        return $this->toBase64();
    }
}
