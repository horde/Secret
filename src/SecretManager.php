<?php

/**
 * Main facade for secret encryption/decryption operations.
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

use Horde\Secret\Cipher\CipherInterface;
use Horde\Secret\Cipher\SodiumCipher;
use Horde\Secret\Cipher\AesGcmCipher;
use Horde\Secret\Cipher\BlowfishCipher;
use Horde\Secret\Exception\DecryptionException;
use Horde\Secret\Exception\UnsupportedCipherException;

/**
 * Main facade for encryption/decryption with automatic cipher selection.
 *
 * Example usage:
 * ```php
 * // Automatic cipher selection (Sodium preferred)
 * $secret = SecretManager::create($key);
 * $encrypted = $secret->encrypt($plaintext);
 * $decrypted = $secret->decrypt($encrypted);
 *
 * // Explicit cipher selection
 * $secret = SecretManager::withSodium($key);
 * $secret = SecretManager::withAesGcm($key);
 * $secret = SecretManager::withBlowfish($key);  // Legacy only
 * ```
 *
 * @category  Horde
 * @copyright 2009-2026 Horde LLC
 * @license   http://www.horde.org/licenses/lgpl21 LGPL 2.1
 * @package   Secret
 */
final class SecretManager
{
    /**
     * Registry of available ciphers by version.
     *
     * @var array<int, class-string<CipherInterface>>
     */
    private const CIPHER_REGISTRY = [
        0x01 => BlowfishCipher::class,  // Legacy Blowfish
        0x02 => SodiumCipher::class,     // XSalsa20-Poly1305 (primary)
        0x03 => AesGcmCipher::class,     // AES-256-GCM (fallback)
    ];

    /**
     * Primary encryption cipher.
     *
     * @var CipherInterface
     */
    private readonly CipherInterface $encryptionCipher;

    /**
     * Legacy Blowfish cipher for decrypting old data.
     *
     * @var BlowfishCipher|null
     */
    private readonly ?BlowfishCipher $legacyCipher;

    /**
     * Encryption key.
     *
     * @var string
     */
    private readonly string $key;

    /**
     * Private constructor. Use factory methods.
     *
     * @param CipherInterface $cipher Primary cipher for encryption
     * @param string         $key    Encryption key
     */
    private function __construct(CipherInterface $cipher, string $key)
    {
        $this->encryptionCipher = $cipher;
        $this->key = $key;

        // Initialize legacy cipher for decrypting old data
        $this->legacyCipher = BlowfishCipher::isSupported()
            ? new BlowfishCipher($key)
            : null;
    }

    /**
     * Derive a 32-byte key from variable-length input.
     *
     * Uses HKDF (HMAC-based Key Derivation Function) to derive a consistent
     * 32-byte key from any length input.
     *
     * @param string $key Input key (any length)
     *
     * @return string 32-byte derived key
     */
    private static function deriveKey(string $key): string
    {
        // Use HKDF to derive a 32-byte key
        // This ensures we always have a proper 256-bit key for modern ciphers
        return hash_hkdf('sha256', $key, 32, 'horde-secret-v1');
    }

    /**
     * Create with automatic cipher selection.
     *
     * Prefers Sodium, falls back to AES-GCM if Sodium unavailable.
     *
     * @param string $key Encryption key (any length, will be derived to 32 bytes)
     *
     * @return self
     *
     * @throws UnsupportedCipherException If no cipher available
     */
    public static function create(string $key): self
    {
        // Try Sodium first (preferred)
        if (SodiumCipher::isSupported()) {
            return self::withSodium($key);
        }

        // Fallback to AES-GCM
        if (AesGcmCipher::isSupported()) {
            return self::withAesGcm($key);
        }

        throw new UnsupportedCipherException(
            'No supported cipher available. Ensure sodium or openssl extension is installed.'
        );
    }

    /**
     * Create with Sodium cipher (XSalsa20-Poly1305).
     *
     * Recommended for new deployments.
     *
     * @param string $key Encryption key (any length, will be derived to 32 bytes)
     *
     * @return self
     *
     * @throws UnsupportedCipherException If sodium extension not available
     */
    public static function withSodium(string $key): self
    {
        if (!SodiumCipher::isSupported()) {
            throw new UnsupportedCipherException(
                'Sodium cipher not supported. Install sodium extension.'
            );
        }

        $derivedKey = self::deriveKey($key);
        return new self(new SodiumCipher($derivedKey), $key);
    }

    /**
     * Create with AES-256-GCM cipher.
     *
     * Good fallback when Sodium unavailable.
     *
     * @param string $key Encryption key (any length, will be derived to 32 bytes)
     *
     * @return self
     *
     * @throws UnsupportedCipherException If AES-256-GCM not available
     */
    public static function withAesGcm(string $key): self
    {
        if (!AesGcmCipher::isSupported()) {
            throw new UnsupportedCipherException(
                'AES-GCM cipher not supported. Install openssl extension with GCM support.'
            );
        }

        $derivedKey = self::deriveKey($key);
        return new self(new AesGcmCipher($derivedKey), $key);
    }

    /**
     * Create with Blowfish cipher (legacy only).
     *
     * DEPRECATED: Only use for compatibility with old encrypted data.
     * For new data, use Sodium or AES-GCM instead.
     *
     * @param string $key Encryption key (up to 56 bytes)
     *
     * @return self
     *
     * @throws UnsupportedCipherException If Blowfish not available
     */
    public static function withBlowfish(string $key): self
    {
        if (!BlowfishCipher::isSupported()) {
            throw new UnsupportedCipherException(
                'Blowfish cipher not supported. Install horde/crypt_blowfish.'
            );
        }

        return new self(new BlowfishCipher($key), $key);
    }

    /**
     * Encrypt plaintext.
     *
     * Always uses the primary cipher (Sodium by default).
     * Result includes magic header for format identification.
     *
     * @param string $plaintext Data to encrypt
     *
     * @return EncryptedData Encrypted data with format header
     *
     * @throws Exception\EncryptionException If encryption fails
     */
    public function encrypt(string $plaintext): EncryptedData
    {
        $payload = $this->encryptionCipher->encrypt($plaintext);
        return new EncryptedData($this->encryptionCipher->getVersion(), $payload);
    }

    /**
     * Decrypt ciphertext.
     *
     * Automatically detects cipher version from header.
     * Supports decrypting old Blowfish data without header.
     *
     * @param EncryptedData|string $encrypted Encrypted data (object or string)
     *
     * @return string Decrypted plaintext
     *
     * @throws DecryptionException If decryption fails
     */
    public function decrypt(EncryptedData|string $encrypted): string
    {
        // Convert string to EncryptedData if needed
        if (is_string($encrypted)) {
            // Check for magic header
            if (EncryptedData::hasHeader($encrypted)) {
                $encrypted = EncryptedData::fromString($encrypted);
            } else {
                // Legacy format (no header) - try Blowfish
                return $this->decryptLegacy($encrypted);
            }
        }

        // Get cipher for this version
        $cipher = $this->getCipherByVersion($encrypted->getVersion());

        // Decrypt
        return $cipher->decrypt($encrypted->getPayload());
    }

    /**
     * Decrypt legacy ciphertext without header (Blowfish).
     *
     * @param string $ciphertext Raw Blowfish ciphertext
     *
     * @return string Decrypted plaintext
     *
     * @throws DecryptionException If decryption fails
     */
    private function decryptLegacy(string $ciphertext): string
    {
        // Validate ciphertext looks reasonable (not just random garbage)
        if (strlen($ciphertext) < 8) {
            throw new DecryptionException(
                'Invalid legacy ciphertext: too short'
            );
        }

        if ($this->legacyCipher === null) {
            throw new DecryptionException(
                'Cannot decrypt legacy format: Blowfish cipher not available'
            );
        }

        try {
            return $this->legacyCipher->decrypt($ciphertext);
        } catch (\Exception $e) {
            throw new DecryptionException(
                'Failed to decrypt legacy format: ' . $e->getMessage(),
                0,
                $e
            );
        }
    }

    /**
     * Get cipher instance for version.
     *
     * @param int $version Cipher version identifier
     *
     * @return CipherInterface
     *
     * @throws UnsupportedCipherException If version unknown or cipher unavailable
     */
    private function getCipherByVersion(int $version): CipherInterface
    {
        if (!isset(self::CIPHER_REGISTRY[$version])) {
            throw new UnsupportedCipherException(
                sprintf('Unknown cipher version: 0x%02X', $version)
            );
        }

        $cipherClass = self::CIPHER_REGISTRY[$version];

        if (!$cipherClass::isSupported()) {
            throw new UnsupportedCipherException(
                sprintf('Cipher for version 0x%02X not supported on this system', $version)
            );
        }

        // For Blowfish, use original key (no derivation needed)
        // For modern ciphers, derive key to 32 bytes
        $key = ($cipherClass === BlowfishCipher::class)
            ? $this->key
            : self::deriveKey($this->key);

        return new $cipherClass($key);
    }

    /**
     * Check if encrypted data needs re-encryption with current cipher.
     *
     * Returns true if:
     * - Data has no header (legacy format)
     * - Data uses different cipher version than current
     *
     * @param EncryptedData|string $encrypted Encrypted data
     *
     * @return bool True if should be re-encrypted
     */
    public function needsReEncryption(EncryptedData|string $encrypted): bool
    {
        // String without header = legacy format
        if (is_string($encrypted) && !EncryptedData::hasHeader($encrypted)) {
            return true;
        }

        // Convert to EncryptedData if needed
        if (is_string($encrypted)) {
            try {
                $encrypted = EncryptedData::fromString($encrypted);
            } catch (\InvalidArgumentException) {
                // Invalid format = needs re-encryption
                return true;
            }
        }

        // Check if version matches current cipher
        return $encrypted->getVersion() !== $this->encryptionCipher->getVersion();
    }

    /**
     * Get the name of the current encryption cipher.
     *
     * @return string Cipher name
     */
    public function getCipherName(): string
    {
        return $this->encryptionCipher->getName();
    }

    /**
     * Get the version of the current encryption cipher.
     *
     * @return int Version identifier
     */
    public function getCipherVersion(): int
    {
        return $this->encryptionCipher->getVersion();
    }
}
