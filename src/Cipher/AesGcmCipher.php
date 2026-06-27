<?php

/**
 * AES-256-GCM authenticated encryption using OpenSSL.
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

namespace Horde\Secret\Cipher;

use Horde\Secret\Exception\EncryptionException;
use Horde\Secret\Exception\DecryptionException;
use Horde\Secret\Exception\InvalidKeyException;
use Exception;

/**
 * AES-256-GCM cipher using OpenSSL.
 *
 * Fallback cipher when libsodium is not available.
 *
 * Features:
 * - AES-256 block cipher (industry standard)
 * - GCM mode with authentication (prevents tampering)
 * - 256-bit keys
 * - 96-bit nonces (standard GCM nonce size)
 * - Hardware acceleration (AES-NI)
 * - FIPS 140-2 compliant
 *
 * @category  Horde
 * @copyright 2009-2026 Horde LLC
 * @license   http://www.horde.org/licenses/lgpl21 LGPL 2.1
 * @package   Secret
 */
final class AesGcmCipher implements CipherInterface
{
    /**
     * Cipher version identifier.
     */
    private const VERSION = 0x03;

    /**
     * Cipher name.
     */
    private const NAME = 'AES-256-GCM';

    /**
     * OpenSSL cipher method.
     */
    private const METHOD = 'aes-256-gcm';

    /**
     * Nonce length in bytes (96 bits = 12 bytes for GCM).
     */
    private const NONCE_LENGTH = 12;

    /**
     * Authentication tag length in bytes (128 bits = 16 bytes).
     */
    private const TAG_LENGTH = 16;

    /**
     * Key length in bytes (256 bits = 32 bytes).
     */
    private const KEY_LENGTH = 32;

    /**
     * Encryption key.
     *
     * @var string 32-byte (256-bit) key
     */
    private readonly string $key;

    /**
     * Constructor.
     *
     * @param string $key Encryption key (must be 32 bytes for AES-256)
     *
     * @throws InvalidKeyException If key length is invalid
     */
    public function __construct(string $key)
    {
        if (strlen($key) !== self::KEY_LENGTH) {
            throw new InvalidKeyException(sprintf(
                'Key must be exactly %d bytes, got %d bytes',
                self::KEY_LENGTH,
                strlen($key)
            ));
        }

        $this->key = $key;
    }

    /**
     * {@inheritdoc}
     */
    public function getVersion(): int
    {
        return self::VERSION;
    }

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return self::NAME;
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt(string $plaintext): string
    {
        if ($plaintext === '') {
            throw new EncryptionException('Cannot encrypt empty plaintext');
        }

        try {
            // Generate random nonce (12 bytes)
            $nonce = random_bytes(self::NONCE_LENGTH);

            // Encrypt with authentication
            $tag = '';
            $ciphertext = openssl_encrypt(
                $plaintext,
                self::METHOD,
                $this->key,
                OPENSSL_RAW_DATA,
                $nonce,
                $tag,
                '',  // Additional Authenticated Data (AAD) - not used
                self::TAG_LENGTH
            );

            if ($ciphertext === false) {
                throw new EncryptionException(
                    'OpenSSL encryption failed: ' . openssl_error_string()
                );
            }

            // Return: nonce + ciphertext + tag
            return $nonce . $ciphertext . $tag;
        } catch (EncryptionException $e) {
            throw $e;
        } catch (Exception $e) {
            throw new EncryptionException(
                'Encryption failed: ' . $e->getMessage(),
                0,
                $e
            );
        }
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt(string $ciphertext): string
    {
        $minLength = self::NONCE_LENGTH + self::TAG_LENGTH;

        if (strlen($ciphertext) < $minLength) {
            throw new DecryptionException(sprintf(
                'Ciphertext too short (minimum %d bytes)',
                $minLength
            ));
        }

        try {
            // Extract nonce (first 12 bytes)
            $nonce = substr($ciphertext, 0, self::NONCE_LENGTH);

            // Extract tag (last 16 bytes)
            $tag = substr($ciphertext, -self::TAG_LENGTH);

            // Extract encrypted data (middle portion)
            $encrypted = substr(
                $ciphertext,
                self::NONCE_LENGTH,
                -self::TAG_LENGTH
            );

            // Decrypt and verify authentication
            $plaintext = openssl_decrypt(
                $encrypted,
                self::METHOD,
                $this->key,
                OPENSSL_RAW_DATA,
                $nonce,
                $tag
            );

            if ($plaintext === false) {
                throw new DecryptionException(
                    'Decryption failed: invalid ciphertext, wrong key, or tampered data'
                );
            }

            return $plaintext;
        } catch (DecryptionException $e) {
            throw $e;
        } catch (Exception $e) {
            throw new DecryptionException(
                'Decryption failed: ' . $e->getMessage(),
                0,
                $e
            );
        }
    }

    /**
     * {@inheritdoc}
     */
    public static function isSupported(): bool
    {
        return extension_loaded('openssl')
            && in_array(self::METHOD, openssl_get_cipher_methods(), true);
    }

    /**
     * {@inheritdoc}
     */
    public function getNonceLength(): int
    {
        return self::NONCE_LENGTH;
    }

    /**
     * {@inheritdoc}
     */
    public function getTagLength(): int
    {
        return self::TAG_LENGTH;
    }

    /**
     * Generate a random encryption key.
     *
     * @return string 32-byte random key
     */
    public static function generateKey(): string
    {
        return random_bytes(self::KEY_LENGTH);
    }
}
